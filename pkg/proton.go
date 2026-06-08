package pkg

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/proton/proton/file"
	protonTmpl "github.com/chainreactors/proton/template"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

var (
	ProtonScanner      *file.Scanner
	protonTemplates    []*protonTmpl.Template
	protonTemplateMap  map[string]*protonTmpl.Template // id → template
	protonTagMap       map[string][]string             // tag → []id
	protonMu           sync.RWMutex
	ExtractContextSize int // 0=disabled, >0=chars of context each side
)

// LoadProtonTemplates parses YAML template docs and builds a Scanner.
func LoadProtonTemplates(yamlDocs [][]byte) error {
	protonMu.Lock()
	defer protonMu.Unlock()

	protonTemplates = nil
	protonTemplateMap = make(map[string]*protonTmpl.Template)
	protonTagMap = make(map[string][]string)

	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}

	for _, doc := range yamlDocs {
		var tmpl protonTmpl.Template
		if err := yaml.Unmarshal(doc, &tmpl); err != nil {
			continue
		}
		if len(tmpl.RequestsFile) == 0 {
			continue
		}
		if err := tmpl.Compile(opts); err != nil {
			continue
		}
		protonTemplates = append(protonTemplates, &tmpl)
		protonTemplateMap[tmpl.Id] = &tmpl
		for _, tag := range tmpl.GetTags() {
			tag = strings.TrimSpace(tag)
			protonTagMap[tag] = append(protonTagMap[tag], tmpl.Id)
		}

	}

	rebuildScanner()
	return nil
}

// AddCustomExtractor creates a one-off regex extractor at runtime (for --extract <regex>).
func AddCustomExtractor(name, pattern string) {
	protonMu.Lock()
	defer protonMu.Unlock()

	req := &file.Request{
		Extensions: []string{"all"},
	}
	req.Operators.Extractors = append(req.Operators.Extractors, &operators.Extractor{
		Name:  name,
		Type:  "regex",
		Regex: []string{pattern},
	})
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	if err := req.Compile(opts); err != nil {
		return
	}

	tmpl := &protonTmpl.Template{
		Id:           "custom-" + name,
		RequestsFile: []*file.Request{req},
	}
	tmpl.Info.Name = name
	tmpl.Info.Severity = "info"
	tmpl.Info.Tags = "spray, custom"

	protonTemplates = append(protonTemplates, tmpl)
	protonTemplateMap[tmpl.Id] = tmpl
	rebuildScanner()
}

// EnableExtractors activates a subset of templates by name or tag.
// Called after LoadProtonTemplates to filter what runs during scanning.
// Empty names = all templates active.
func EnableExtractors(names []string) {
	protonMu.Lock()
	defer protonMu.Unlock()

	if len(names) == 0 {
		rebuildScanner()
		return
	}

	ids := make(map[string]bool)
	for _, n := range names {
		if _, ok := protonTemplateMap["spray-"+n]; ok {
			ids["spray-"+n] = true
		} else if _, ok := protonTemplateMap[n]; ok {
			ids[n] = true
		} else if tagIDs, ok := protonTagMap[n]; ok {
			for _, id := range tagIDs {
				ids[id] = true
			}
		} else {
			ids["custom-"+n] = true
		}
	}

	var rules []file.Rule
	for _, tmpl := range protonTemplates {
		if !ids[tmpl.Id] {
			continue
		}
		for _, req := range tmpl.RequestsFile {
			rules = append(rules, file.Rule{
				ID:       tmpl.Id,
				Name:     tmpl.Info.Name,
				Severity: tmpl.Info.Severity,
				Requests: []*file.Request{req},
			})
		}
	}
	ProtonScanner = file.NewScanner(rules, nil)
}

func rebuildScanner() {
	var rules []file.Rule
	for _, tmpl := range protonTemplates {
		for _, req := range tmpl.RequestsFile {
			rules = append(rules, file.Rule{
				ID:       tmpl.Id,
				Name:     tmpl.Info.Name,
				Severity: tmpl.Info.Severity,
				Requests: []*file.Request{req},
			})
		}
	}
	ProtonScanner = file.NewScanner(rules, nil)
}

type extractHit struct {
	value    string
	line     int
	offset   int
	severity string
}

func captureContext(content []byte, lineOffset int, value string, ctxSize int) string {
	searchEnd := len(content)
	if nlPos := bytes.IndexByte(content[lineOffset:], '\n'); nlPos >= 0 {
		searchEnd = lineOffset + nlPos
	}
	line := content[lineOffset:searchEnd]
	idx := bytes.Index(line, []byte(value))
	if idx == -1 {
		return ""
	}
	matchStart := lineOffset + idx
	start := matchStart - ctxSize
	if start < 0 {
		start = 0
	}
	end := matchStart + len(value) + ctxSize
	if end > len(content) {
		end = len(content)
	}
	return string(content[start:end])
}

// ProtonExtract runs proton scanner on in-memory content and returns
// parsers.Extracted results compatible with spray's output format.
func ProtonExtract(content []byte) parsers.Extracteds {
	protonMu.RLock()
	scanner := ProtonScanner
	protonMu.RUnlock()

	if scanner == nil || len(scanner.Groups) == 0 || len(content) == 0 {
		return nil
	}

	resultMap := make(map[string][]extractHit)

	for _, group := range scanner.Groups {
		findings := scanner.ScanData(content, "response", group)
		for _, f := range findings {
			for _, e := range f.Extracts {
				resultMap[f.TemplateID] = append(resultMap[f.TemplateID], extractHit{
					value: e.Value, line: e.Line, offset: e.Offset, severity: f.Severity,
				})
			}
			// f.Matches contains matcher hits (gate only), not extractor results — skip
			if f.Result != nil {
				for _, val := range f.Result.OutputExtracts {
					resultMap[f.TemplateID] = append(resultMap[f.TemplateID], extractHit{
						value: val, severity: f.Severity,
					})
				}
			}
		}
	}

	var extracteds parsers.Extracteds
	for templateID, hits := range resultMap {
		displayName := strings.TrimPrefix(templateID, "spray-")
		extracted := &parsers.Extracted{
			Name:     displayName,
			Severity: hits[0].severity,
		}
		seen := make(map[string]struct{})
		for _, h := range hits {
			if _, ok := seen[h.value]; ok {
				continue
			}
			seen[h.value] = struct{}{}
			extracted.ExtractResult = append(extracted.ExtractResult, h.value)
			if ExtractContextSize > 0 {
				extracted.Items = append(extracted.Items, parsers.ExtractItem{
					Value:  h.value,
					Line:   h.line,
					Offset: h.offset,
					Ctx:    captureContext(content, h.offset, h.value, ExtractContextSize),
				})
			}
		}
		if len(extracted.ExtractResult) > 0 {
			extracteds = append(extracteds, extracted)
		}
	}
	return extracteds
}

// LoadProtonTemplatesFromDir loads all .yaml template files from a directory.
func LoadProtonTemplatesFromDir(dir string) error {
	var docs [][]byte
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		docs = append(docs, data)
		return nil
	})
	return LoadProtonTemplates(docs)
}

// ProtonExtractorNames returns all available template IDs.
func ProtonExtractorNames() []string {
	protonMu.RLock()
	defer protonMu.RUnlock()
	names := make([]string, 0, len(protonTemplateMap))
	for id := range protonTemplateMap {
		names = append(names, id)
	}
	return names
}

// IsProtonExtractor checks if a name matches a proton template ID or tag.
func IsProtonExtractor(name string) bool {
	protonMu.RLock()
	defer protonMu.RUnlock()
	if _, ok := protonTemplateMap["spray-"+name]; ok {
		return true
	}
	if _, ok := protonTemplateMap[name]; ok {
		return true
	}
	if _, ok := protonTagMap[name]; ok {
		return true
	}
	return false
}
