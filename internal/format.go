package internal

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"io"
	"net/url"
	"os"
	"strings"
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

func PrintPreset() {
	logs.Log.Console("internal rules:\n")
	for name, rule := range pkg.Rules {
		logs.Log.Consolef("\t%s\t%d rules\n", name, len(strings.Split(rule, "\n")))
	}

	logs.Log.Console("\ninternal dicts:\n")
	for name, dict := range pkg.Dicts {
		logs.Log.Consolef("\t%s\t%d items\n", name, len(dict))
	}

	logs.Log.Console("\ninternal words keyword:\n")
	for name, words := range mask.SpecialWords {
		logs.Log.Consolef("\t%s\t%d words\n", name, len(words))
	}

	logs.Log.Console("\ninternal extractor:\n")
	for name, _ := range pkg.ExtractRegexps {
		logs.Log.Consolef("\t%s\n", name)
	}

	logs.Log.Console("\ninternal fingers:\n")
	for name, engine := range pkg.FingerEngine.EnginesImpl {
		logs.Log.Consolef("\t%s\t%d fingerprints \n", name, engine.Len())
	}

	logs.Log.Consolef("\nload %d active path\n", len(pkg.ActivePath))
}
