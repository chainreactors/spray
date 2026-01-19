package core

import (
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/iutils"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	DefaultFingerPath     = "fingers"
	DefaultFingerTemplate = "fingers/templates"

	FingerConfigs = map[string]string{
		fingers.FingersEngine:     "fingers_http.json.gz",
		fingers.FingerPrintEngine: "fingerprinthub_v3.json.gz",
		fingers.WappalyzerEngine:  "wappalyzer.json.gz",
		fingers.EHoleEngine:       "ehole.json.gz",
		fingers.GobyEngine:        "goby.json.gz",
	}
	baseURL = "https://raw.githubusercontent.com/chainreactors/fingers/master/resources/"
)

type FingerOptions struct {
	Finger       bool   `long:"finger" description:"Bool, enable active finger detect" config:"finger"`
	FingerUpdate bool   `long:"update" description:"Bool, update finger database" config:"update"`
	FingerPath   string `long:"finger-path" default:"fingers" description:"String, 3rd finger config path" config:"finger-path"`
	//FingersTemplatesPath string `long:"finger-template" default:"fingers/templates" description:"Bool, use finger templates path" config:"finger-template"`
	FingerEngines string `long:"finger-engine" default:"all" description:"String, custom finger engine, e.g. --finger-engine ehole,goby" config:"finger-engine"`
}

func (opt *FingerOptions) Validate() error {
	var err error
	if opt.FingerUpdate {
		if opt.FingerPath != DefaultFingerPath && !files.IsExist(opt.FingerPath) {
			err = os.MkdirAll(opt.FingerPath, 0755)
			if err != nil {
				return err
			}
		} else if !files.IsExist(DefaultFingerPath) {
			opt.FingerPath = DefaultFingerPath
			err = os.MkdirAll(DefaultFingerPath, 0755)
			if err != nil {
				return err
			}
		}
		//if opt.FingersTemplatesPath != DefaultFingerTemplate && !files.IsExist(opt.FingersTemplatesPath) {
		//	err = os.MkdirAll(opt.FingersTemplatesPath, 0755)
		//	if err != nil {
		//		return err
		//	}
		//} else if !files.IsExist(DefaultFingerTemplate) {
		//	err = os.MkdirAll(DefaultFingerTemplate, 0755)
		//	if err != nil {
		//		return err
		//	}
		//}
	}

	if opt.FingerEngines != "all" {
		for _, name := range strings.Split(opt.FingerEngines, ",") {
			if !iutils.StringsContains(fingers.AllEngines, name) {
				return fmt.Errorf("invalid finger engine: %s, please input one of %v", name, fingers.FingersEngine)
			}
		}
	}
	return nil
}

func (opt *FingerOptions) LoadLocalFingerConfig() error {
	for name, fingerPath := range FingerConfigs {
		if content, err := os.ReadFile(fingerPath); err == nil {
			if encode.Md5Hash(content) != resources.CheckSum[name] {
				logs.Log.Importantf("found %s difference, use %s replace embed", name, fingerPath)
				switch name {
				case fingers.FingersEngine:
					resources.FingersHTTPData = content
				case fingers.FingerPrintEngine:
					resources.FingerprinthubWebData = content
				case fingers.EHoleEngine:
					resources.EholeData = content
				case fingers.GobyEngine:
					resources.GobyData = content
				case fingers.WappalyzerEngine:
					resources.WappalyzerData = content
				default:
					return fmt.Errorf("unknown engine name")
				}
			} else {
				logs.Log.Infof("%s config is up to date", name)
			}
		}
	}
	return nil
}

func (opt *FingerOptions) UpdateFinger() error {
	modified := false
	for name, _ := range FingerConfigs {
		if ok, err := opt.downloadConfig(name); err != nil {
			return err
		} else {
			if ok {
				modified = ok
			}
		}
	}
	if !modified {
		logs.Log.Importantf("everything is up to date")
	}
	return nil
}

func (opt *FingerOptions) downloadConfig(name string) (bool, error) {
	fingerFile, ok := FingerConfigs[name]
	if !ok {
		return false, fmt.Errorf("unknown engine name")
	}
	url := baseURL + fingerFile
	resp, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bad status: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	filePath := filepath.Join(files.GetExcPath(), opt.FingerPath, fingerFile)
	if files.IsExist(filePath) {
		origin, err := os.ReadFile(filePath)
		if err != nil {
			return false, err
		}
		if resources.CheckSum[name] != encode.Md5Hash(origin) {
			logs.Log.Importantf("update %s config from %s save to %s", name, url, fingerFile)
			err = os.WriteFile(filePath, content, 0644)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	} else {
		out, err := os.Create(filePath)
		if err != nil {
			return false, err
		}
		defer out.Close()
		logs.Log.Importantf("download %s config from %s save to %s", name, url, fingerFile)
		err = os.WriteFile(filePath, content, 0644)
		if err != nil {
			return false, err
		}
	}
	if err != nil {
		return false, err
	}

	if origin, err := os.ReadFile(filePath); err == nil {
		if encode.Md5Hash(content) != encode.Md5Hash(origin) {
			logs.Log.Infof("download %s config from %s save to %s", name, url, fingerFile)
			err = os.WriteFile(filePath, content, 0644)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}
