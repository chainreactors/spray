package internal

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/logs"
	"io/ioutil"
	"os"
)

func Format(filename string, color bool) {
	var content []byte
	var err error
	if filename == "stdin" {
		content, err = ioutil.ReadAll(os.Stdin)
	} else {
		content, err = ioutil.ReadFile(filename)
	}

	if err != nil {
		return
	}
	var results []*Baseline
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		var result Baseline
		err := json.Unmarshal(line, &result)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		results = append(results, &result)
	}
	for _, result := range results {
		if color {
			logs.Log.Info(result.ColorString())
		} else {
			logs.Log.Info(result.String())
		}
	}
}
