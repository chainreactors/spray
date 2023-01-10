package internal

import (
	"bytes"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"io/ioutil"
	"net/url"
	"path"
	"strings"
)

func parseExtension(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[i+1:]
	}
	return ""
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

func relaPath(base, u string) string {
	// 拼接相对目录, 不使用path.join的原因是, 如果存在"////"这样的情况, 可能真的是有意义的路由, 不能随意去掉.
	// ""	/a 	/a
	// "" 	a  	/a
	// /    ""  /
	// /a/ 	b 	/a/b
	// /a/ 	/b 	/a/b
	// /a  	b 	/b
	// /a  	/b 	/b

	if u == "" {
		return base
	}

	pathSlash := strings.HasPrefix(u, "/")
	if base == "" {
		if pathSlash {
			return u[1:]
		} else {
			return "/" + u
		}
	} else if strings.HasSuffix(base, "/") {
		if pathSlash {
			return base + u[1:]
		} else {
			return base + u
		}
	} else {
		if pathSlash {
			return Dir(base) + u[1:]
		} else {
			return Dir(base) + u
		}
	}
}

func Dir(u string) string {
	// 安全的获取目录, 不会额外处理多个"//", 并非用来获取上级目录
	// /a 	/
	// /a/ 	/a/
	// a/ 	a/
	// aaa 	/

	if strings.HasSuffix(u, "/") {
		return u
	} else if i := strings.LastIndex(u, "/"); i == -1 {
		return "/"
	} else {
		return u[:i+1]
	}
}

func FormatURL(base, u string) string {
	if strings.HasPrefix(u, "http") {
		parsed, err := url.Parse(u)
		if err != nil {
			return ""
		}
		if len(parsed.Path) <= 1 {
			return ""
		}
		return parsed.Path
	} else if strings.HasPrefix(u, "//") {
		parsed, err := url.Parse(u)
		if err != nil {
			return ""
		}
		if len(parsed.Path) <= 1 {
			// 跳过"/"与空目录
			return ""
		}
		return parsed.Path
	} else if strings.HasPrefix(u, "/") {
		// 绝对目录拼接
		// 不需要进行处理, 用来跳过下面的判断
		return u
	} else if strings.HasPrefix(u, "./") {
		// "./"相对目录拼接
		return relaPath(base, u[2:])
	} else if strings.HasPrefix(u, "../") {
		return path.Join(Dir(base), u)
	} else {
		// 相对目录拼接
		return relaPath(base, u)
	}
}

//func Join(base, u string) string {
//	// //././ ../../../a
//	base = Dir(base)
//	for strings.HasPrefix(u, "../") {
//		u = u[3:]
//		for strings.HasSuffix(base, "/") {
//			// 去掉多余的"/"
//			base = base[:len(base)-2]
//		}
//		if i := strings.LastIndex(base, "/"); i == -1 {
//			return "/"
//		} else {
//			return base[:i+1]
//		}
//	}
//	return base + u
//}
