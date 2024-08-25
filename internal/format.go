package internal

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"io"
	"net/url"
	"os"
)

func Format(opts Option) {
	var content []byte
	var err error
	if opts.Format == "stdin" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(opts.Format)
	}

	if err != nil {
		return
	}
	group := make(map[string][]*pkg.Baseline)
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte("\n")) {
		var result pkg.Baseline
		err := json.Unmarshal(line, &result)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		result.Url, err = url.Parse(result.UrlString)
		if err != nil {
			continue
		}
		group[result.Url.Host] = append(group[result.Url.Host], &result)
	}

	// 分组

	for _, results := range group {
		for _, result := range results {
			if !opts.Fuzzy && result.IsFuzzy {
				continue
			}
			if !opts.NoColor {
				logs.Log.Console(result.ColorString() + "\n")
			} else {
				logs.Log.Console(result.String() + "\n")
			}
		}
	}
}
