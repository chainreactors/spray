package pkg

import (
	"fmt"
	"os"
	"strings"

	"github.com/chainreactors/fingers"
	fingerscommon "github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/favicon"
	fingerslib "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words/mask"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

func LoadPorts() error {
	var err error
	var ports []*utils.PortConfig
	err = yaml.Unmarshal(LoadConfig("port"), &ports)
	if err != nil {
		return err
	}
	utils.PrePort = utils.NewPortPreset(ports)
	return nil
}

func LoadFingers() error {
	var err error
	ActivePath = ActivePath[:0]
	if httpData := LoadConfig("http"); len(httpData) > 0 {
		httpFingers, err := fingerslib.LoadFingers(httpData)
		if err != nil {
			return err
		}
		socketFingers, err := fingerslib.LoadFingers(LoadConfig("socket"))
		if err != nil {
			return err
		}
		fingerImpl, err := fingerslib.NewEngine(httpFingers, socketFingers)
		if err != nil {
			return err
		}
		FingerEngine = &fingers.Engine{
			EnginesImpl:  make(map[string]fingers.EngineImpl),
			Enabled:      make(map[string]bool),
			Capabilities: make(map[string]fingerscommon.EngineCapability),
		}
		faviconEngine := favicon.NewFavicons()
		FingerEngine.EnginesImpl[fingers.FaviconEngine] = faviconEngine
		FingerEngine.Capabilities[fingers.FaviconEngine] = faviconEngine.Capability()
		FingerEngine.Register(fingerImpl)
		if err := FingerEngine.Compile(); err != nil {
			return err
		}
	} else {
		FingerEngine, err = fingers.NewEngine()
	}
	if err != nil {
		return err
	}
	for _, f := range FingerEngine.Fingers().HTTPFingers {
		if f.SendDataStr != "" {
			ActivePath = append(ActivePath, f.SendDataStr)
		}
		for _, rule := range f.Rules {
			if rule.SendDataStr != "" {
				ActivePath = append(ActivePath, rule.SendDataStr)
			}
		}
	}

	return nil
}

func LoadTemplates() error {
	var err error
	Rules = make(map[string]string)
	Dicts = make(map[string][]string)
	ExtractRegexps = make(parsers.Extractors)
	Extractors = make(parsers.Extractors)
	// load rule

	err = yaml.Unmarshal(LoadConfig("spray_rule"), &Rules)
	if err != nil {
		return err
	}

	// load default words
	var dicts map[string]string
	err = yaml.Unmarshal(LoadConfig("spray_dict"), &dicts)
	if err != nil {
		return err
	}
	for name, wordlist := range dicts {
		dict := strings.Split(strings.TrimSpace(wordlist), "\n")
		for i, d := range dict {
			dict[i] = strings.TrimSpace(d)
		}
		Dicts[strings.TrimSuffix(name, ".txt")] = dict
	}

	// load mask
	var keywords map[string]interface{}
	err = yaml.Unmarshal(LoadConfig("spray_common"), &keywords)
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
	err = yaml.Unmarshal(LoadConfig("extract"), &extracts)
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
	err := LoadPorts()
	if err != nil {
		return fmt.Errorf("load ports, %w", err)
	}
	err = LoadTemplates()
	if err != nil {
		return fmt.Errorf("load templates, %w", err)
	}

	return nil
}
