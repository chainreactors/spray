package internal

import (
	"encoding/json"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"strconv"
	"strings"
)

func NewBaseline(u, host string, resp *ihttp.Response) *baseline {
	bl := &baseline{
		//Url:       u,
		UrlString: u,
		Host:      host,
		Status:    resp.StatusCode(),
		IsValid:   true,
	}

	bl.Body = resp.Body()
	bl.BodyLength = resp.ContentLength()
	bl.Header = resp.Header()
	bl.HeaderLength = len(bl.Header)
	bl.RedirectURL = resp.GetHeader("Location")
	bl.Raw = append(bl.Header, bl.Body...)
	return bl
}

func NewInvalidBaseline(u, host string, resp *ihttp.Response) *baseline {
	bl := &baseline{
		//Url:       u,
		UrlString: u,
		Host:      host,
		Status:    resp.StatusCode(),
		IsValid:   false,
	}

	bl.RedirectURL = string(resp.GetHeader("Location"))

	return bl
}

type baseline struct {
	UrlString    string         `json:"url"`
	Host         string         `json:"host"`
	Body         []byte         `json:"-"`
	BodyLength   int            `json:"body_length"`
	Header       []byte         `json:"-"`
	Raw          []byte         `json:"-"`
	HeaderLength int            `json:"header_length"`
	RedirectURL  string         `json:"redirect_url"`
	Status       int            `json:"status"`
	IsDynamicUrl bool           `json:"is_dynamic_url"` // 判断是否存在动态的url
	Spended      int            `json:"spended"`        // 耗时, 毫秒
	Title        string         `json:"title"`
	Frameworks   pkg.Frameworks `json:"frameworks"`
	Extracteds   pkg.Extracteds `json:"extracts"`
	Err          error          `json:"-"`
	IsValid      bool           `json:"-"`
	*parsers.Hashes
}

// Collect 深度收集信息
func (bl *baseline) Collect() {
	bl.Hashes = parsers.NewHashes(bl.Raw)
	bl.Title = parsers.MatchTitle(string(bl.Body))
	// todo extract
	bl.Extracteds = pkg.Extractors.Extract(string(bl.Raw))
	// todo 指纹识别
	bl.Frameworks = pkg.FingerDetect(string(bl.Raw))
}

// Equal if this equal other return true
func (bl *baseline) Equal(other *baseline) bool {
	if other.RedirectURL != "" && bl.RedirectURL == other.RedirectURL {
		// 如果重定向url不为空, 且与bl不相同, 则说明不是同一个页面
		return true
	}

	if bl.BodyLength == other.BodyLength {
		// 如果body length相等且md5相等, 则说明是同一个页面
		if bl.BodyMd5 == parsers.Md5Hash(other.Raw) {
			return true
		} else {
			return true
		}
	}

	return false
}

func (bl *baseline) FuzzyEqual(other *baseline) bool {
	// todo 模糊匹配
	return false
}

func (bl *baseline) String() string {
	var line strings.Builder
	//line.WriteString("[+] ")
	line.WriteString(bl.UrlString)
	line.WriteString(" (" + bl.Host + ")")
	line.WriteString(" - ")
	line.WriteString(strconv.Itoa(bl.Status))
	line.WriteString(" - ")
	line.WriteString(strconv.Itoa(bl.BodyLength))
	if bl.RedirectURL != "" {
		line.WriteString(" -> ")
		line.WriteString(bl.RedirectURL)
		line.WriteString(" ")
	}
	line.WriteString(" [" + bl.Title + "]")
	if bl.Hashes != nil {
		line.WriteString(" [" + bl.Hashes.BodyMd5 + "]")
	}

	line.WriteString(bl.Frameworks.ToString())
	//line.WriteString(bl.Extracteds)
	//line.WriteString("\n")
	if bl.Err != nil {
		line.WriteString("err: ")
		line.WriteString(bl.Err.Error())
	}
	return line.String()
}

func (bl *baseline) Jsonify() string {
	bs, err := json.Marshal(bl)
	if err != nil {
		return ""
	}
	return string(bs)
}
