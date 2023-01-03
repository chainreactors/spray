package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
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
	ActivePath  []string
	Fingers     fingers.Fingers
	JSRegexps   []*regexp.Regexp = []*regexp.Regexp{
		regexp.MustCompile(".(https{0,1}:[^\\s,^',^’,^\",^”,^>,^<,^;,^(,^),^|,^*,^\\[]{2,250}?[^=,^*,^\\s,^',^’,^\",^”,^>,^<,^:,^;,^*,^|,^(,^),^\\[]{3}[.]js)"),
		regexp.MustCompile("[\",',‘,“]\\s{0,6}(/{0,1}[^\\s,^',^’,^\",^”,^|,^>,^<,^:,^;,^*,^(,^\\),^\\[]{2,250}?[^=,^*,^\\s,^',^’,^|,^\",^”,^>,^<,^:,^;,^*,^(,^),^\\[]{3}[.]js)"),
		regexp.MustCompile("=\\s{0,6}[\",',’,”]{0,1}\\s{0,6}(/{0,1}[^\\s,^',^’,^\",^”,^|,^>,^<,^;,^*,^(,^),^\\[]{2,250}?[^=,^*,^\\s,^',^’,^\",^”,^>,^|,^<,^:,^;,^*,^(,^),^\\[]{3}[.]js)"),
	}
	URLRegexps []*regexp.Regexp = []*regexp.Regexp{
		regexp.MustCompile("[\",',‘,“]\\s{0,6}(https{0,1}:[^\\s,^',^’,^\",^”,^>,^<,^),^(]{2,250}?)\\s{0,6}[\",',‘,“]"),
		regexp.MustCompile("=\\s{0,6}(https{0,1}:[^\\s,^',^’,^\",^”,^>,^<,^),^(]{2,250})"),
		regexp.MustCompile("[\",',‘,“]\\s{0,6}([#,.]{0,2}/[^\\s,^',^’,^\",^”,^>,^<,^:,^),^(]{2,250}?)\\s{0,6}[\",',‘,“]"),
		regexp.MustCompile("href\\s{0,6}=\\s{0,6}[\",',‘,“]{0,1}\\s{0,6}([^\\s,^',^’,^\",^“,^>,^<,^,^+),^(]{2,250})|action\\s{0,6}=\\s{0,6}[\",',‘,“]{0,1}\\s{0,6}([^\\s,^',^’,^\",^“,^>,^<,^,^+),^(]{2,250})"),
	}
)

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
	b[0] = byte(0x2f)
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
	Fingers, err = fingers.LoadFingers(LoadConfig("http"))
	if err != nil {
		utils.Fatal(err.Error())
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

	return nil
}

func FingerDetect(content string) Frameworks {
	var frames Frameworks
	//content := string(body)
	for _, finger := range Fingers {
		frame, _, ok := fingers.FingerMatcher(finger, content, 0, nil)
		if ok {
			frames = append(frames, frame)
		}
	}
	return frames
}

var (
	BadExt = []string{".js", ".css", ".scss", ",", ".jpeg", ".jpg", ".png", ".gif", ".ico", ".svg", ".vue", ".ts"}
	//BadURL   = []string{".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?", "github.com", "www.w3.org", "example.com", "<", ">", "{", "}", "[", "]", "|", "^", ";", "/js/", ".src", ".url", ".att", ".href", "location.href", "javascript:", "location:", ".createObject", ":location", ".path", "*#__PURE__*", "\\n"}
	BadScoop = []string{"www.w3.org", "example.com"}
)

func filterJs(u string) bool {
	for _, scoop := range BadScoop {
		if strings.Contains(u, scoop) {
			return true
		}
	}
	return false
}

func filterUrl(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return true
	} else {
		ext := path.Ext(parsed.Path)
		for _, e := range BadExt {
			if e == ext {
				return true
			}
		}
	}
	for _, scoop := range BadScoop {
		if strings.Contains(u, scoop) {
			return true
		}
	}
	return false
}
func URLJoin(base, uri string) string {
	baseSlash := strings.HasSuffix(base, "/")
	uriSlash := strings.HasPrefix(uri, "/")
	if (baseSlash && !uriSlash) || (!baseSlash && uriSlash) {
		return base + uri
	} else if baseSlash && uriSlash {
		return base + uri[1:]
	} else {
		return base + "/" + uri
	}
}
