package internal

import (
	"bytes"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"io/ioutil"
	"math/rand"
	"net/url"
	"path"
	"strconv"
	"strings"
)

var (
	// from feroxbuster
	randomUserAgent = []string{
		"Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254",
		"Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
		"Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
	}
	uacount = len(randomUserAgent)
)

func parseExtension(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[i+1:]
	}
	return ""
}

func parseStatus(preset []int, changed string) []int {
	if changed == "" {
		return preset
	}
	if strings.HasPrefix(changed, "+") {
		for _, s := range strings.Split(changed[1:], ",") {
			if t, err := strconv.Atoi(s); err != nil {
				continue
			} else {
				preset = append(preset, t)
			}
		}
	} else if strings.HasPrefix(changed, "!") {
		for _, s := range strings.Split(changed[1:], ",") {
			for i, status := range preset {
				if t, err := strconv.Atoi(s); err != nil {
					break
				} else if t == status {
					preset = append(preset[:i], preset[i+1:]...)
					break
				}
			}
		}
	} else {
		preset = []int{}
		for _, s := range strings.Split(changed, ",") {
			if t, err := strconv.Atoi(s); err != nil {
				continue
			} else {
				preset = append(preset, t)
			}
		}
	}
	return preset
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
		return parsed.Path
	} else if strings.HasPrefix(u, "//") {
		parsed, err := url.Parse(u)
		if err != nil {
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

func RandomUA() string {
	return randomUserAgent[rand.Intn(uacount)]
}
