package pkg

import (
	"bufio"
	"bytes"
	"github.com/chainreactors/files"
	"github.com/chainreactors/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

var (
	LogVerbose   = logs.Warn - 2
	LogFuzz      = logs.Warn - 1
	WhiteStatus  = []int{} // cmd input, 200
	BlackStatus  = []int{} // cmd input, 400,410
	FuzzyStatus  = []int{} // cmd input, 500,501,502,503
	WAFStatus    = []int{493, 418, 1020, 406, 429}
	UniqueStatus = []int{} // 相同unique的403表示命中了同一条acl, 相同unique的200表示default页面

	// plugins
	EnableAllFingerEngine = false
)
var (
	Rules          map[string]string   = make(map[string]string)
	Dicts          map[string][]string = make(map[string][]string)
	wordlistCache                      = make(map[string][]string)
	ruleCache                          = make(map[string][]rule.Expression)
	BadExt                             = []string{".js", ".css", ".scss", ".,", ".jpeg", ".jpg", ".png", ".gif", ".svg", ".vue", ".ts", ".swf", ".pdf", ".mp4", ".zip", ".rar"}
	BadURL                             = []string{";", "}", "\\n", "webpack://", "{", "www.w3.org", ".src", ".url", ".att", ".href", "location.href", "javascript:", "location:", ".createObject", ":location", ".path"}
	ExtractRegexps                     = make(parsers.Extractors)
	Extractors                         = make(parsers.Extractors)

	FingerEngine   *fingers.Engine
	ActivePath     []string
	ContentTypeMap = map[string]string{
		"application/javascript":   "js",
		"application/json":         "json",
		"application/xml":          "xml",
		"application/octet-stream": "bin",
		"application/atom+xml":     "atom",
		"application/msword":       "doc",
		"application/pdf":          "pdf",
		"image/gif":                "gif",
		"image/jpeg":               "jpg",
		"image/png":                "png",
		"image/svg+xml":            "svg",
		"text/css":                 "css",
		"text/plain":               "txt",
		"text/html":                "html",
		"audio/mpeg":               "mp3",
		"video/mp4":                "mp4",
		"video/ogg":                "ogg",
		"video/webm":               "webm",
		"video/x-ms-wmv":           "wmv",
		"video/avi":                "avi",
		"image/x-icon":             "ico",
	}

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

type BS []byte

func (b BS) String() string {
	return string(b)
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var src = rand.NewSource(time.Now().UnixNano())

const (
	// 6 bits to represent a letter index
	letterIdBits = 6
	// All 1-bits as many as letterIdBits
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

func RandPath() string {
	n := 16
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return *(*string)(unsafe.Pointer(&b))
}

func RandHost() string {
	n := 8
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 1; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIdBits
		remain--
	}

	b[5] = byte(0x2e)
	return *(*string)(unsafe.Pointer(&b))
}

func FilterJs(u string) bool {
	if commonFilter(u) {
		return true
	}

	return false
}

func FilterUrl(u string) bool {
	if commonFilter(u) {
		return true
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return true
	} else {
		ext := path.Ext(parsed.Path)
		for _, e := range BadExt {
			if strings.EqualFold(e, ext) {
				return true
			}
		}
	}
	return false
}

func CleanURL(u string) string {
	// 去掉frag与params, 节约url.parse性能, 防止带参数造成意外的影响
	u = strings.Trim(u, "\"")
	u = strings.Trim(u, "'")
	if strings.Contains(u, "2f") || strings.Contains(u, "2F") {
		u = strings.ReplaceAll(u, "\\u002F", "/")
		u = strings.ReplaceAll(u, "\\u002f", "/")
		u = strings.ReplaceAll(u, "%252F", "/")
		u = strings.ReplaceAll(u, "%252f", "/")
		u = strings.ReplaceAll(u, "%2f", "/")
		u = strings.ReplaceAll(u, "%2F", "/")
	}

	u = strings.TrimRight(u, "\\")
	if i := strings.Index(u, "?"); i != -1 {
		return u[:i]
	}
	if i := strings.Index(u, "#"); i != -1 {
		return u[:i]
	}
	return u
}

func commonFilter(u string) bool {
	if strings.HasPrefix(u, "http") && len(u) < 15 {
		return true
	}

	for _, bad := range BadURL {
		if strings.Contains(u, bad) {
			return true
		}
	}
	return false
}

func BakGenerator(domain string) []string {
	var possibilities []string
	for first, _ := range domain {
		for last, _ := range domain[first:] {
			p := domain[first : first+last+1]
			if !iutils.StringsContains(possibilities, p) {
				possibilities = append(possibilities, p)
			}
		}
	}
	return possibilities
}

var MbTable = []uint16{
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040}

func CRC16Hash(data []byte) uint16 {
	var crc16 uint16
	crc16 = 0xffff
	for _, v := range data {
		n := uint8(uint16(v) ^ crc16)
		crc16 >>= 8
		crc16 ^= MbTable[n]
	}
	return crc16
}

func SafePath(dir, u string) string {
	hasSlash := strings.HasPrefix(u, "/")
	if hasSlash {
		return path.Join(dir, u[1:])
	} else {
		return path.Join(dir, u)
	}
}

func RelaPath(base, u string) string {
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

func UniqueHash(bl *Baseline) uint16 {
	// 由host+状态码+重定向url+content-type+title+length舍去个位组成的hash
	// body length可能会导致一些误报, 目前没有更好的解决办法
	return CRC16Hash([]byte(bl.Host + strconv.Itoa(bl.Status) + bl.RedirectURL + bl.ContentType + bl.Title + strconv.Itoa(bl.BodyLength/10*10)))
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
		return RelaPath(base, u[2:])
	} else if strings.HasPrefix(u, "../") {
		return path.Join(Dir(base), u)
	} else {
		// 相对目录拼接
		return RelaPath(base, u)
	}
}

func BaseURL(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

func RandomUA() string {
	return randomUserAgent[rand.Intn(uacount)]
}

func CompareWithExpr(exp *vm.Program, params map[string]interface{}) bool {
	res, err := expr.Run(exp, params)
	if err != nil {
		logs.Log.Warn(err.Error())
	}

	if res == true {
		return true
	} else {
		return false
	}
}

func MatchWithGlobs(u string, globs []string) bool {
	for _, glob := range globs {
		ok, err := filepath.Match(glob, u)
		if err == nil && ok {
			return true
		}
	}
	return false
}

func ParseRawResponse(raw []byte) (*http.Response, error) {
	reader := bytes.NewReader(raw)

	// 使用http.ReadResponse解析HTTP响应
	resp, err := http.ReadResponse(bufio.NewReader(reader), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

func GetPresetWordList(key []string) []string {
	var wordlist []string

	for _, k := range key {
		if v, ok := mask.SpecialWords[k]; ok {
			wordlist = append(wordlist, v...)
		}
	}
	return wordlist
}

func ParseExtension(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[i+1:]
	}
	return ""
}

func ParseStatus(preset []int, changed string) []int {
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

func LoadFileToSlice(filename string) ([]string, error) {
	var ss []string
	if dicts, ok := Dicts[filename]; ok {
		if files.IsExist(filename) {
			logs.Log.Warnf("load and overwrite %s from preset", filename)
		}
		return dicts, nil
	}
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

func LoadRuleAndCombine(filename []string) (string, error) {
	var bs bytes.Buffer
	for _, f := range filename {
		if data, ok := Rules[f]; ok {
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
	if dict, ok := Dicts[filename]; ok {
		return dict, nil
	}
	dict, err := LoadFileToSlice(filename)
	if err != nil {
		return nil, err
	}
	Dicts[filename] = dict
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

func LoadWordlist(word string, dictNames []string) ([]string, error) {
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

func LoadRuleWithFiles(ruleFiles []string, filter string) ([]rule.Expression, error) {
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

func WrapWordsFunc(f func(string) string) func(string) []string {
	return func(s string) []string {
		return []string{f(s)}
	}
}

func SafeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, "http://", "")
	filename = strings.ReplaceAll(filename, "https://", "")
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "/", "_")
	return filename
}
