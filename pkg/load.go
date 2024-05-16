package pkg

import (
	"encoding/json"
	"github.com/chainreactors/fingers"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words/mask"
	"os"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
	"strings"
)

var (
	Md5Fingers     map[string]string = make(map[string]string)
	Mmh3Fingers    map[string]string = make(map[string]string)
	ExtractRegexps                   = make(parsers.Extractors)
	Extractors                       = make(parsers.Extractors)

	FingerEngine *fingers.Engine
	ActivePath   []string
)

func LoadTemplates() error {
	var err error
	// load fingers
	FingerEngine, err = fingers.NewEngine()
	if err != nil {
		return err
	}
	for _, f := range FingerEngine.FingersEngine.HTTPFingers {
		for _, rule := range f.Rules {
			if rule.SendDataStr != "" {
				ActivePath = append(ActivePath, rule.SendDataStr)
			}
			if rule.Favicon != nil {
				for _, mmh3 := range rule.Favicon.Mmh3 {
					Mmh3Fingers[mmh3] = f.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					Md5Fingers[md5] = f.Name
				}
			}
		}
	}
	for _, f := range FingerEngine.FingerPrintEngine {
		if f.Path != "/" {
			ActivePath = append(ActivePath, f.Path)
		}
		for _, ico := range f.FaviconHash {
			Md5Fingers[ico] = f.Name
		}
	}

	// load rule
	var data map[string]interface{}
	err = json.Unmarshal(LoadConfig("spray_rule"), &data)
	if err != nil {
		return err
	}
	for k, v := range data {
		Rules[k] = v.(string)
	}

	// load mask
	var keywords map[string]interface{}
	err = json.Unmarshal(LoadConfig("spray_common"), &keywords)
	if err != nil {
		return err
	}

	for k, v := range keywords {
		t := make([]string, len(v.([]interface{})))
		for i, vv := range v.([]interface{}) {
			t[i] = iutils.ToString(vv)
		}
		mask.SpecialWords[k] = t
	}

	var extracts []*parsers.Extractor
	err = json.Unmarshal(LoadConfig("extract"), &extracts)
	if err != nil {
		return err
	}

	for _, extract := range extracts {
		extract.Compile()

		ExtractRegexps[extract.Name] = []*parsers.Extractor{extract}
		for _, tag := range extract.Tags {
			if _, ok := ExtractRegexps[tag]; !ok {
				ExtractRegexps[tag] = []*parsers.Extractor{extract}
			} else {
				ExtractRegexps[tag] = append(ExtractRegexps[tag], extract)
			}
		}
	}
	return nil
}

func LoadExtractorConfig(filename string) ([]*parsers.Extractor, error) {
	var extracts []*parsers.Extractor
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(content, &extracts)
	if err != nil {
		return nil, err
	}

	for _, extract := range extracts {
		extract.Compile()
	}

	return extracts, nil
}

func Load() error {
	// load fingers
	err := LoadTemplates()
	if err != nil {
		return err
	}
	return nil
}

func LoadDefaultDict() []string {
	return strings.Split(strings.TrimSpace(string(LoadConfig("spray_default"))), "\n")
}
