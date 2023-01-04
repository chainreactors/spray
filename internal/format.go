package internal

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"io/ioutil"
)

func Format(filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	var results []*pkg.Baseline
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		var result pkg.Baseline
		err := json.Unmarshal(line, &result)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		results = append(results, &result)
	}
	for _, result := range results {
		logs.Log.Info(result.String())
	}
}
