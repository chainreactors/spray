package pkg

import (
	"encoding/json"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
	"github.com/chainreactors/words/mask"
	"math/rand"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

var (
	Md5Fingers  map[string]string = make(map[string]string)
	Mmh3Fingers map[string]string = make(map[string]string)
	Rules       map[string]string = make(map[string]string)
	ActivePath  []string
	Fingers     fingers.Fingers
	JSRegexps   []*regexp.Regexp = []*regexp.Regexp{
		regexp.MustCompile(`.(https{0,1}:[^\s',’"”><;()|*\[]{2,250}?[^=*\s'’><:;|()[]{3}\[]\.js)`),
		regexp.MustCompile(`["']\s{0,6}(/{0,1}[^\s',’"”><;()|*:\[]{2,250}?[^=*\s'’|"”><^:;()\[]{3}\.\.js)`),
		regexp.MustCompile(`=\s{0,6}["']{0,1}\s{0,6}(/{0,1}[^\s^',’><;()|*\[]{2,250}?[^=,\s'’"”>|<:;*()\[]{3}\.js)`),
	}
	URLRegexps []*regexp.Regexp = []*regexp.Regexp{
		regexp.MustCompile(`=\s{0,6}(https{0,1}:[^\s',’"”><;()|*\[]{2,250})`),
		regexp.MustCompile(`["']([^\s',’"”><.@;()|*\[]{2,250}\.[a-zA-Z]\w{1,4})["']`),
		regexp.MustCompile(`["'](https?:[^\s',’"”><;()@|*\[]{2,250}?\.[^\s',’"”><;()|*\[]{2,250}?)["']`),
		regexp.MustCompile(`["']\s{0,6}([#,.]{0,2}/[^\s',’"”><;()|*\[]{2,250}?)\s{0,6}["']`),
		regexp.MustCompile(`href\s{0,6}=\s{0,6}["'‘“]{0,1}\s{0,6}([^\s',’"”><;()|*\[]{2,250})|action\s{0,6}=\s{0,6}["'‘“]{0,1}\s{0,6}([^\s'’"“><)(]{2,250})`),
	}

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
)

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

func RemoveDuplication(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}

func HasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
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

func LoadTemplates() error {
	var err error
	// load fingers
	Fingers, err = fingers.LoadFingers(LoadConfig("http"))
	if err != nil {
		return err
	}

	for _, finger := range Fingers {
		err := finger.Compile(ipcs.ParsePorts)
		if err != nil {
			return err
		}
	}

	for _, f := range Fingers {
		for _, rule := range f.Rules {
			if rule.SendDataStr != "" {
				ActivePath = append(ActivePath, rule.SendDataStr)
			}
			if rule.Favicon != nil {
				for _, mmh3 := range rule.Favicon.Mmh3 {
					Mmh3Fingers[mmh3] = f.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					Md5Fingers[md5] = f.Name
				}
			}
		}
	}

	// load rule
	var data map[string]interface{}
	err = json.Unmarshal(LoadConfig("rule"), &data)
	if err != nil {
		return err
	}
	for k, v := range data {
		Rules[k] = v.(string)
	}

	// load mask
	var keywords map[string]interface{}
	err = json.Unmarshal(LoadConfig("mask"), &keywords)
	if err != nil {
		return err
	}

	for k, v := range keywords {
		t := make([]string, len(v.([]interface{})))
		for i, vv := range v.([]interface{}) {
			t[i] = utils.ToString(vv)
		}
		mask.SpecialWords[k] = t
	}
	return nil
}

func FingerDetect(content string) Frameworks {
	var frames Frameworks
	for _, finger := range Fingers {
		frame, _, ok := fingers.FingerMatcher(finger, content, 0, nil)
		if ok {
			frames = append(frames, frame)
		}
	}
	return frames
}

var (
	BadExt = []string{".js", ".css", ".scss", ".,", ".jpeg", ".jpg", ".png", ".gif", ".svg", ".vue", ".ts", ".swf", ".pdf", ".mp4"}
	BadURL = []string{";", "}", "webpack://", "{", "www.w3.org", ".src", ".url", ".att", ".href", "location.href", "javascript:", "location:", ".createObject", ":location", ".path"}
)

func filterJs(u string) bool {
	if commonFilter(u) {
		return true
	}

	return false
}

func filterUrl(u string) bool {
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

func formatURL(u string) string {
	// 去掉frag与params, 节约url.parse性能, 防止带参数造成意外的影响
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

//func SafeJoin(base, uri string) string {
//	baseSlash := strings.HasSuffix(base, "/")
//	uriSlash := strings.HasPrefix(uri, "/")
//	if (baseSlash && !uriSlash) || (!baseSlash && uriSlash) {
//		return base + uri
//	} else if baseSlash && uriSlash {
//		return base + uri[1:]
//	} else {
//		return base + "/" + uri
//	}
//}

//func SafePath(url, path string) string {
//	urlSlash := strings.HasSuffix(url, "/")
//	pathSlash := strings.HasPrefix(path, "/")
//	if !urlSlash && !pathSlash {
//		return "/" + path
//	} else if urlSlash && pathSlash {
//		return path[1:]
//	} else {
//		return path
//	}
//}

func BakGenerator(domain string) []string {
	var possibilities []string
	for first, _ := range domain {
		for last, _ := range domain[first:] {
			p := domain[first : first+last+1]
			if !StringsContains(possibilities, p) {
				possibilities = append(possibilities, p)
			}
		}
	}
	return possibilities
}
