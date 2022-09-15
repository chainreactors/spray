package internal

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/dsl"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func NewBaseline(u *url.URL, resp *http.Response) *baseline {
	bl := &baseline{
		Url:        u,
		UrlString:  u.String(),
		BodyLength: resp.ContentLength,
		Status:     resp.StatusCode,
		IsValid:    true,
	}

	var header string
	for k, v := range resp.Header {
		// stringbuilder
		for _, i := range v {
			header += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	bl.Header = header
	bl.HeaderLength = len(header)

	redirectURL, err := resp.Location()
	if err == nil {
		bl.RedirectURL = redirectURL.String()
	}

	body := make([]byte, 20480)
	if bl.BodyLength > 0 {
		n, err := io.ReadFull(resp.Body, body)
		if err == nil {
			bl.Body = body
		} else if err == io.ErrUnexpectedEOF {
			bl.Body = body[:n]
		} else {
			logs.Log.Error("readfull failed" + err.Error())
		}
		_ = resp.Body.Close()
	}

	if len(bl.Body) > 0 {
		bl.Md5 = dsl.Md5Hash(bl.Body)
		bl.Mmh3 = dsl.Mmh3Hash32(bl.Body)
		bl.Simhash = pkg.Simhash(bl.Body)
		if strings.Contains(string(bl.Body), bl.UrlString[1:]) {
			bl.IsDynamicUrl = true
		}
		// todo callback
	}

	// todo extract

	// todo 指纹识别
	bl.Frameworks = pkg.FingerDetect(bl.Body)
	return bl
}

func NewInvalidBaseline(u *url.URL, resp *http.Response) *baseline {
	bl := &baseline{
		Url:        u,
		UrlString:  u.String(),
		BodyLength: resp.ContentLength,
		Status:     resp.StatusCode,
		IsValid:    false,
	}

	redirectURL, err := resp.Location()
	if err == nil {
		bl.RedirectURL = redirectURL.String()
	}

	return bl
}

type baseline struct {
	Url          *url.URL       `json:"-"`
	UrlString    string         `json:"url_string"`
	Body         []byte         `json:"-"`
	BodyLength   int64          `json:"body_length"`
	Header       string         `json:"-"`
	HeaderLength int            `json:"header_length"`
	RedirectURL  string         `json:"redirect_url"`
	Status       int            `json:"status"`
	Md5          string         `json:"md5"`
	Mmh3         string         `json:"mmh3"`
	Simhash      string         `json:"simhash"`
	IsDynamicUrl bool           `json:"is_dynamic_url"` // 判断是否存在动态的url
	Spended      int            `json:"spended"`        // 耗时, 毫秒
	Frameworks   pkg.Frameworks `json:"frameworks"`

	Err     error `json:"-"`
	IsValid bool  `json:"-"`
}

func (bl *baseline) Compare(other *baseline) bool {
	if bl.Md5 == other.Md5 {
		return true
	}

	if bl.RedirectURL == other.RedirectURL {
		return true
	}

	return false
}

func (bl *baseline) FuzzyCompare() bool {
	// todo 模糊匹配
	return false
}

func (bl *baseline) String() string {
	return fmt.Sprintf("%s - %d - %d [%s]", bl.UrlString, bl.Status, bl.BodyLength, bl.Frameworks.ToString())
}

func (bl *baseline) Jsonify() string {
	bs, err := json.Marshal(bl)
	if err != nil {
		return ""
	}
	return string(bs)
}
