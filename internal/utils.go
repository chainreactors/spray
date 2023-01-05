package internal

import (
	"bytes"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"io/ioutil"
	"strings"
)

func parseExtension(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[i+1:]
	}
	return ""
}

func StringsContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func IntsContains(s []int, e int) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func loadFileToSlice(filename string) ([]string, error) {
	var ss []string
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ss = strings.Split(strings.TrimSpace(string(content)), "\n")

	// 统一windows与linux的回车换行差异
	for i, word := range ss {
		ss[i] = strings.TrimSpace(word)
	}

	return ss, nil
}

func loadFileAndCombine(filename []string) (string, error) {
	var bs bytes.Buffer
	for _, f := range filename {
		if data, ok := pkg.Rules[f]; ok {
			bs.WriteString(strings.TrimSpace(data))
			bs.WriteString("\n")
		} else {
			content, err := ioutil.ReadFile(f)
			if err != nil {
				return "", err
			}
			bs.Write(bytes.TrimSpace(content))
			bs.WriteString("\n")
		}
	}
	return bs.String(), nil
}

func loadFileWithCache(filename string) ([]string, error) {
	if dict, ok := dictCache[filename]; ok {
		return dict, nil
	}
	dict, err := loadFileToSlice(filename)
	if err != nil {
		return nil, err
	}
	dictCache[filename] = dict
	return dict, nil
}

func loadDictionaries(filenames []string) ([][]string, error) {
	dicts := make([][]string, len(filenames))
	for i, name := range filenames {
		dict, err := loadFileWithCache(name)
		if err != nil {
			return nil, err
		}
		dicts[i] = dict
	}
	return dicts, nil
}

func loadWordlist(word string, dictNames []string) ([]string, error) {
	if wl, ok := wordlistCache[word+strings.Join(dictNames, ",")]; ok {
		return wl, nil
	}
	dicts, err := loadDictionaries(dictNames)
	if err != nil {
		return nil, err
	}
	wl, err := mask.Run(word, dicts, nil)
	if err != nil {
		return nil, err
	}
	wordlistCache[word] = wl
	return wl, nil
}

func loadRuleWithFiles(ruleFiles []string, filter string) ([]rule.Expression, error) {
	if rules, ok := ruleCache[strings.Join(ruleFiles, ",")]; ok {
		return rules, nil
	}
	var rules bytes.Buffer
	for _, filename := range ruleFiles {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		rules.Write(content)
		rules.WriteString("\n")
	}
	return rule.Compile(rules.String(), filter).Expressions, nil
}
