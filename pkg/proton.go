package pkg

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/proton/protocols/file"
	protonTmpl "github.com/chainreactors/proton/templates"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

var (
	ProtonScanner     *file.Scanner
	protonTemplates   []*protonTmpl.Template
	protonTemplateMap map[string]*protonTmpl.Template // id → template
	protonTagMap      map[string][]string             // tag → []id
	protonMu          sync.RWMutex
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

// ProtonExtract runs proton scanner on in-memory content and returns
// parsers.Extracted results compatible with spray's output format.
func ProtonExtract(content []byte) parsers.Extracteds {
	protonMu.RLock()
	scanner := ProtonScanner
	protonMu.RUnlock()

	if scanner == nil || len(scanner.Groups) == 0 || len(content) == 0 {
		return nil
	}

	resultMap := make(map[string]map[string]struct{})

	for _, group := range scanner.Groups {
		findings := scanner.ScanData(content, "response", group)
		for _, f := range findings {
			if resultMap[f.TemplateID] == nil {
				resultMap[f.TemplateID] = make(map[string]struct{})
			}
			for _, e := range f.Extracts {
				resultMap[f.TemplateID][e.Value] = struct{}{}
			}
			for _, events := range f.Matches {
				for _, e := range events {
					resultMap[f.TemplateID][e.Value] = struct{}{}
				}
			}
			if f.Result != nil {
				for _, val := range f.Result.OutputExtracts {
					resultMap[f.TemplateID][val] = struct{}{}
				}
			}
		}
	}

	var extracteds parsers.Extracteds
	for name, vals := range resultMap {
		displayName := strings.TrimPrefix(name, "spray-")
		extracted := &parsers.Extracted{Name: displayName}
		for v := range vals {
			extracted.ExtractResult = append(extracted.ExtractResult, v)
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
