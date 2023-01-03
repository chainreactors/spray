package pkg

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg/ihttp"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func NewBaseline(u, host string, resp *ihttp.Response) *Baseline {
	bl := &Baseline{
		UrlString: u,
		Status:    resp.StatusCode(),
		IsValid:   true,
	}
	uu, err := url.Parse(u)
	if err == nil {
		bl.Path = uu.Path
		bl.Url = uu
	}
	if resp.ClientType == ihttp.STANDARD {
		bl.Host = host
	}
	bl.Body = resp.Body()
	bl.BodyLength = len(bl.Body)
	bl.Header = resp.Header()
	bl.HeaderLength = len(bl.Header)
	bl.RedirectURL = resp.GetHeader("Location")
	bl.Raw = append(bl.Header, bl.Body...)
	return bl
}

func NewInvalidBaseline(u, host string, resp *ihttp.Response, reason string) *Baseline {
	bl := &Baseline{
		UrlString: u,
		Status:    resp.StatusCode(),
		IsValid:   false,
		Reason:    reason,
	}

	uu, err := url.Parse(u)
	if err == nil {
		bl.Path = uu.Path
		bl.Url = uu
	}

	if resp.ClientType == ihttp.STANDARD {
		bl.Host = host
	}

	bl.Body = resp.Body()
	bl.BodyLength = len(bl.Body)
	bl.Header = resp.Header()
	bl.HeaderLength = len(bl.Header)
	bl.RedirectURL = string(resp.GetHeader("Location"))

	return bl
}

type Baseline struct {
	Number       int        `json:"number"`
	Url          *url.URL   `json:"-"`
	UrlString    string     `json:"url"`
	Path         string     `json:"path"`
	Host         string     `json:"host"`
	Body         []byte     `json:"-"`
	BodyLength   int        `json:"body_length"`
	Header       []byte     `json:"-"`
	Raw          []byte     `json:"-"`
	HeaderLength int        `json:"header_length"`
	RedirectURL  string     `json:"redirect_url,omitempty"`
	FrontURL     string     `json:"front_url,omitempty"`
	Status       int        `json:"status"`
	Spended      int64      `json:"spend"` // 耗时, 毫秒
	Title        string     `json:"title"`
	Frameworks   Frameworks `json:"frameworks"`
	Extracteds   Extracteds `json:"extracts"`
	ErrString    string     `json:"error"`
	Reason       string     `json:"reason"`
	IsValid      bool       `json:"valid"`
	IsFuzzy      bool       `json:"fuzzy"`
	URLs         []string   `json:"urls"`
	RecuDepth    int        `json:"-"`
	ReqDepth     int        `json:"depth"`
	Recu         bool       `json:"-"`
	*parsers.Hashes
}

func (bl *Baseline) IsDir() bool {
	if strings.HasSuffix(bl.Path, "/") {
		return true
	}
	return false
}

// Collect 深度收集信息
func (bl *Baseline) Collect() {
	if len(bl.Body) > 0 {
		bl.Title = utils.AsciiEncode(parsers.MatchTitle(string(bl.Body)))
	}
	bl.Hashes = parsers.NewHashes(bl.Raw)
	bl.Extracteds = Extractors.Extract(string(bl.Raw))
	bl.Frameworks = FingerDetect(string(bl.Raw))
}

func (bl *Baseline) CollectURL() {
	if len(bl.Body) == 0 {
		return
	}
	for _, reg := range JSRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			var filter bool
			parsed, err := url.Parse(u[1])
			if err != nil {
				filter = true
			} else {
				for _, scoop := range BadScoop {
					if scoop == parsed.Host {
						filter = true
						break
					}
				}
			}

			if filter {
				continue
			}
			bl.URLs = append(bl.URLs, u[1])
		}
	}

	for _, reg := range URLRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			var filter bool
			parsed, err := url.Parse(u[1])
			if err != nil {
				filter = true
			} else {
				ext := path.Ext(parsed.Path)
				for _, e := range BadExt {
					if e == ext {
						filter = true
						break
					}
				}
				for _, scoop := range BadScoop {
					if scoop == parsed.Host {
						filter = true
						break
					}
				}
			}

			if filter {
				continue
			}
			bl.URLs = append(bl.URLs, u[1])
		}
	}
}

// Compare
// if totally equal return 1
// if maybe equal return 0
// not equal return -1
func (bl *Baseline) Compare(other *Baseline) int {
	if other.RedirectURL != "" && bl.RedirectURL == other.RedirectURL {
		// 如果重定向url不为空, 且与base不相同, 则说明不是同一个页面
		return 1
	}

	if bl.BodyLength == other.BodyLength {
		// 如果body length相等且md5相等, 则说明是同一个页面
		if bytes.Equal(bl.Body, other.Body) {
			// 如果length相等, md5也相等, 则判断为全同
			return 1
		} else {
			// 如果长度相等, 但是md5不相等, 可能是存在csrftoken之类的随机值
			return 0
		}
	} else if i := bl.BodyLength - other.BodyLength; (i < 16 && i > 0) || (i > -16 && i < 0) {
		// 如果body length绝对值小于16, 则可能是存在csrftoken之类的随机值, 需要模糊判断
		return 0
	} else {
		// 如果body length绝对值大于16, 则认为大概率存在较大差异
		if strings.Contains(string(other.Body), other.Path) {
			// 如果包含路径本身, 可能是路径自身的随机值影响结果
			return 0
		} else {
			// 如果不包含路径本身, 则认为是不同页面
			return -1
		}
	}
	return -1
}

var Distance uint8 = 5

func (bl *Baseline) FuzzyCompare(other *Baseline) bool {
	if parsers.SimhashCompare(other.BodySimhash, bl.BodySimhash) < Distance {
		return true
	}
	return false
}

func (bl *Baseline) Get(key string) string {
	switch key {
	case "url":
		return bl.UrlString
	case "host":
		return bl.Host
	case "title":
		return bl.Title
	case "redirect":
		return bl.RedirectURL
	case "md5":
		if bl.Hashes != nil {
			return bl.Hashes.BodyMd5
		} else {
			return ""
		}
	case "simhash":
		if bl.Hashes != nil {
			return bl.Hashes.BodySimhash
		} else {
			return ""
		}
	case "mmh3":
		if bl.Hashes != nil {
			return bl.Hashes.BodySimhash
		} else {
			return ""
		}
	case "stat", "status":
		return strconv.Itoa(bl.Status)
	case "spend":
		return strconv.Itoa(int(bl.Spended))
	case "extract":
		return bl.Extracteds.String()
	case "frame", "framework":
		return bl.Frameworks.String()
	case "full":
		return bl.String()
	default:
		return ""
	}
}

func (bl *Baseline) Additional(key string) string {
	if v := bl.Get(key); v != "" {
		return " [" + v + "]"
	} else {
		return ""
	}
}

func (bl *Baseline) Format(probes []string) string {
	var line strings.Builder
	if bl.FrontURL != "" {
		line.WriteString("\t")
		line.WriteString(bl.FrontURL)
		line.WriteString(" -> ")
	}
	line.WriteString(bl.UrlString)
	if bl.Host != "" {
		line.WriteString(" (" + bl.Host + ")")
	}

	if bl.Reason != "" {
		line.WriteString(" ,")
		line.WriteString(bl.Reason)
	}
	if bl.ErrString != "" {
		line.WriteString(" ,err: ")
		line.WriteString(bl.ErrString)
		return line.String()
	}

	for _, p := range probes {
		line.WriteString(" ")
		line.WriteString(bl.Additional(p))
	}

	return line.String()
}

func (bl *Baseline) ColorString() string {
	var line strings.Builder
	if bl.FrontURL != "" {
		line.WriteString("\t")
		line.WriteString(logs.CyanLine(bl.FrontURL))
		line.WriteString(" --> ")
	}
	line.WriteString(logs.GreenLine(bl.UrlString))
	if bl.Host != "" {
		line.WriteString(" (" + bl.Host + ")")
	}

	if bl.Reason != "" {
		line.WriteString(" [reason: ")
		line.WriteString(logs.YellowBold(bl.Reason))
		line.WriteString("]")
	}
	if bl.ErrString != "" {
		line.WriteString(" [err: ")
		line.WriteString(logs.RedBold(bl.ErrString))
		line.WriteString("]")
		return line.String()
	}

	line.WriteString(" - ")
	line.WriteString(logs.GreenBold(strconv.Itoa(bl.Status)))
	line.WriteString(" - ")
	line.WriteString(logs.YellowBold(strconv.Itoa(bl.BodyLength)))
	line.WriteString(" - ")
	line.WriteString(logs.YellowBold(strconv.Itoa(int(bl.Spended)) + "ms"))
	line.WriteString(logs.GreenLine(bl.Additional("title")))
	line.WriteString(logs.Cyan(bl.Frameworks.String()))
	line.WriteString(logs.Cyan(bl.Extracteds.String()))
	if bl.RedirectURL != "" {
		line.WriteString(" --> ")
		line.WriteString(logs.CyanLine(bl.RedirectURL))
		line.WriteString(" ")
	}
	if len(bl.URLs) > 0 {
		line.WriteString("\n")
	}
	for _, u := range bl.URLs {
		line.WriteString("\t" + u + "\n")
	}
	return line.String()
}

func (bl *Baseline) String() string {
	var line strings.Builder
	if bl.FrontURL != "" {
		line.WriteString("\t")
		line.WriteString(bl.FrontURL)
		line.WriteString(" --> ")
	}
	line.WriteString(bl.UrlString)
	if bl.Host != "" {
		line.WriteString(" (" + bl.Host + ")")
	}

	if bl.Reason != "" {
		line.WriteString(" [reason: ")
		line.WriteString(bl.Reason)
		line.WriteString("]")
	}
	if bl.ErrString != "" {
		line.WriteString(" [err: ")
		line.WriteString(bl.ErrString)
		line.WriteString("]")
		return line.String()
	}

	line.WriteString(" - ")
	line.WriteString(strconv.Itoa(bl.Status))
	line.WriteString(" - ")
	line.WriteString(strconv.Itoa(bl.BodyLength))
	line.WriteString(" - ")
	line.WriteString(strconv.Itoa(int(bl.Spended)) + "ms")
	line.WriteString(bl.Additional("title"))
	line.WriteString(bl.Frameworks.String())
	line.WriteString(bl.Extracteds.String())
	if bl.RedirectURL != "" {
		line.WriteString(" --> ")
		line.WriteString(bl.RedirectURL)
		line.WriteString(" ")
	}
	if len(bl.URLs) > 0 {
		line.WriteString("\n")
	}
	for _, u := range bl.URLs {
		line.WriteString("\t" + u + "\n")
	}
	return line.String()
}

func (bl *Baseline) Jsonify() string {
	bs, err := json.Marshal(bl)
	if err != nil {
		return ""
	}
	return string(bs)
}
