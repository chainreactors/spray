package pkg

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/chainreactors/parsers"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

type PocMode int

const (
	PocModeCheck PocMode = 1 << iota
	PocModeBrute
	PocModeAll = PocModeCheck | PocModeBrute
)

var (
	neutronMu         sync.RWMutex
	neutronTemplates  []*templates.Template
	neutronFingerMap  map[string][]*templates.Template // finger name → check templates
	neutronBruteMap   map[string][]*templates.Template // zombie/tag name → brute templates
	neutronTimeout    = 10
	NeutronEnabled    bool
	NeutronPocMode    PocMode
)

func LoadNeutronTemplates() error {
	data := LoadConfig("neutron")
	if len(data) == 0 {
		return nil
	}

	var rawTemplates []interface{}
	if err := yaml.Unmarshal(data, &rawTemplates); err != nil {
		return err
	}

	var docs [][]byte
	for _, tmpl := range rawTemplates {
		doc, err := yaml.Marshal(tmpl)
		if err != nil {
			continue
		}
		docs = append(docs, doc)
	}

	return loadNeutronDocs(docs)
}

func LoadNeutronTemplatesFromDir(dir string) error {
	var docs [][]byte
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		docs = append(docs, data)
		return nil
	})
	return loadNeutronDocs(docs)
}

func loadNeutronDocs(docs [][]byte) error {
	neutronMu.Lock()
	defer neutronMu.Unlock()

	neutronTemplates = nil
	neutronFingerMap = make(map[string][]*templates.Template)
	neutronBruteMap = make(map[string][]*templates.Template)

	opts := &protocols.ExecuterOptions{
		Options: &protocols.Options{
			Timeout: neutronTimeout,
		},
	}

	for _, doc := range docs {
		var tmpl templates.Template
		if err := yaml.Unmarshal(doc, &tmpl); err != nil {
			continue
		}

		if tmpl.GetRequests() == nil && len(tmpl.RequestsNetwork) == 0 &&
			len(tmpl.RequestsTCP) == 0 && len(tmpl.RequestsUDP) == 0 {
			continue
		}

		if err := tmpl.Compile(opts); err != nil {
			logs.Log.Debugf("neutron compile %s failed: %s", tmpl.Id, err.Error())
			continue
		}

		t := &tmpl
		neutronTemplates = append(neutronTemplates, t)

		isBrute := tmpl.Info.Zombie != "" || hasPayloads(t)

		if isBrute {
			// brute template: index by zombie field and tags
			if tmpl.Info.Zombie != "" {
				key := strings.ToLower(tmpl.Info.Zombie)
				neutronBruteMap[key] = append(neutronBruteMap[key], t)
			}
			for _, tag := range tmpl.GetTags() {
				key := strings.ToLower(strings.TrimSpace(tag))
				if key != "" {
					neutronBruteMap[key] = append(neutronBruteMap[key], t)
				}
			}
			// also index by finger field if present
			for _, finger := range tmpl.Fingers {
				key := strings.ToLower(strings.TrimSpace(finger))
				if key != "" {
					neutronBruteMap[key] = append(neutronBruteMap[key], t)
				}
			}
		} else {
			// check template: index by finger field and tags
			for _, finger := range tmpl.Fingers {
				key := strings.ToLower(strings.TrimSpace(finger))
				if key != "" {
					neutronFingerMap[key] = append(neutronFingerMap[key], t)
				}
			}
			for _, tag := range tmpl.GetTags() {
				key := strings.ToLower(strings.TrimSpace(tag))
				if key != "" {
					neutronFingerMap[key] = append(neutronFingerMap[key], t)
				}
			}
		}
	}

	logs.Log.Importantf("loaded %d neutron templates (check: %d fingers, brute: %d services)",
		len(neutronTemplates), len(neutronFingerMap), len(neutronBruteMap))
	return nil
}

func hasPayloads(t *templates.Template) bool {
	for _, req := range t.GetRequests() {
		if len(req.Payloads) > 0 {
			return true
		}
	}
	return false
}

// NeutronCheck runs vulnerability check templates matching the given fingerprints.
func NeutronCheck(baseURL string, frameworks common.Frameworks) []*PocResult {
	if !NeutronEnabled || NeutronPocMode&PocModeCheck == 0 {
		return nil
	}

	neutronMu.RLock()
	defer neutronMu.RUnlock()

	seen := make(map[string]bool)
	var results []*PocResult

	for name := range frameworks {
		key := strings.ToLower(name)
		tmplList, ok := neutronFingerMap[key]
		if !ok {
			continue
		}
		for _, tmpl := range tmplList {
			if seen[tmpl.Id] {
				continue
			}
			seen[tmpl.Id] = true

			result, err := tmpl.Execute(baseURL, nil)
			if err != nil {
				logs.Log.Debugf("neutron check %s on %s: %s", tmpl.Id, baseURL, err.Error())
				continue
			}
			if result != nil && result.Matched {
				results = append(results, &PocResult{
					TemplateID: tmpl.Id,
					Name:       tmpl.Info.Name,
					Severity:   tmpl.Info.Severity,
					Tags:       tmpl.GetTags(),
					Matched:    true,
					Extracts:   result.OutputExtracts,
				})
			}
		}
	}
	return results
}

// NeutronBrute runs brute/login templates matching the given fingerprints.
func NeutronBrute(baseURL string, frameworks common.Frameworks) []*PocResult {
	if !NeutronEnabled || NeutronPocMode&PocModeBrute == 0 {
		return nil
	}

	neutronMu.RLock()
	defer neutronMu.RUnlock()

	seen := make(map[string]bool)
	var results []*PocResult

	for name := range frameworks {
		key := strings.ToLower(name)
		tmplList, ok := neutronBruteMap[key]
		if !ok {
			continue
		}
		for _, tmpl := range tmplList {
			if seen[tmpl.Id] {
				continue
			}
			seen[tmpl.Id] = true

			result, err := tmpl.Execute(baseURL, nil)
			if err != nil {
				logs.Log.Debugf("neutron brute %s on %s: %s", tmpl.Id, baseURL, err.Error())
				continue
			}
			if result != nil && result.Matched {
				pr := &PocResult{
					TemplateID: tmpl.Id,
					Name:       tmpl.Info.Name,
					Severity:   tmpl.Info.Severity,
					Tags:       tmpl.GetTags(),
					Matched:    true,
					Extracts:   result.OutputExtracts,
				}
				if result.PayloadValues != nil {
					pr.Payload = result.PayloadValues
				}
				results = append(results, pr)
			}
		}
	}
	return results
}

// NeutronScan runs both check and brute templates based on configured mode.
func NeutronScan(baseURL string, frameworks common.Frameworks) []*PocResult {
	if !NeutronEnabled || len(frameworks) == 0 {
		return nil
	}

	var results []*PocResult
	results = append(results, NeutronCheck(baseURL, frameworks)...)
	results = append(results, NeutronBrute(baseURL, frameworks)...)
	return results
}

// PocResultToExtracteds converts POC results to parsers.Extracteds for output.
func PocResultToExtracteds(results []*PocResult) parsers.Extracteds {
	if len(results) == 0 {
		return nil
	}

	var extracteds parsers.Extracteds
	for _, r := range results {
		extracted := &parsers.Extracted{
			Name: "poc:" + r.TemplateID,
		}
		extracted.ExtractResult = append(extracted.ExtractResult,
			"["+r.Severity+"] "+r.Name)
		if len(r.Extracts) > 0 {
			extracted.ExtractResult = append(extracted.ExtractResult, r.Extracts...)
		}
		if r.Payload != nil {
			for k, v := range r.Payload {
				if s, ok := v.(string); ok {
					extracted.ExtractResult = append(extracted.ExtractResult, k+"="+s)
				}
			}
		}
		extracteds = append(extracteds, extracted)
	}
	return extracteds
}

// PocResultToVulns converts POC results to common.Vulns for structured output.
func PocResultToVulns(results []*PocResult) common.Vulns {
	if len(results) == 0 {
		return nil
	}

	vulns := make(common.Vulns)
	for _, r := range results {
		vuln := &common.Vuln{
			Name:          r.TemplateID,
			Tags:          r.Tags,
			SeverityLevel: common.GetSeverityLevel(r.Severity),
		}
		if r.Payload != nil {
			vuln.Payload = r.Payload
		}
		if len(r.Extracts) > 0 {
			vuln.Detail = map[string][]string{
				"extracts": r.Extracts,
			}
		}
		vulns.Add(vuln)
	}
	return vulns
}

type PocResult struct {
	TemplateID string
	Name       string
	Severity   string
	Tags       []string
	Matched    bool
	Extracts   []string
	Payload    map[string]interface{}
	Result     *operators.Result
}
