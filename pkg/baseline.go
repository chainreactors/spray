package pkg

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/iutils"
	"net/http"
	"net/url"
	"strings"
)

func NewBaseline(u, host string, resp *ihttp.Response) *Baseline {
	var err error
	bl := &Baseline{
		SprayResult: &parsers.SprayResult{
			UrlString:  u,
			Status:     resp.StatusCode(),
			IsValid:    true,
			Frameworks: make(common.Frameworks),
		},
	}

	if t, ok := ContentTypeMap[resp.ContentType()]; ok {
		bl.ContentType = t
		bl.Title = t + " data"
	} else {
		bl.ContentType = "other"
	}

	header := resp.Header()
	bl.Header = make([]byte, len(header))
	copy(bl.Header, header)
	bl.HeaderLength = len(bl.Header)

	if i := resp.ContentLength(); ihttp.CheckBodySize(i) {
		body := resp.Body()
		bl.Body = make([]byte, len(body))
		copy(bl.Body, body)

		if i == -1 {
			bl.Chunked = true
			bl.BodyLength = len(bl.Body)
		} else {
			bl.BodyLength = int(i)
		}
	}

	bl.Raw = append(bl.Header, bl.Body...)
	bl.Response, err = ParseRawResponse(bl.Raw)
	if err != nil {
		bl.IsValid = false
		bl.Reason = ErrResponseError.Error()
		bl.ErrString = err.Error()
		return bl
	}
	if r := bl.Response.Header.Get("Location"); r != "" {
		bl.RedirectURL = r
	} else {
		bl.RedirectURL = bl.Response.Header.Get("location")
	}

	bl.Dir = bl.IsDir()
	uu, err := url.Parse(u)
	if err == nil {
		bl.Path = uu.Path
		bl.Url = uu
		if uu.Host != host {
			bl.Host = host
		}
	} else {
		bl.IsValid = false
		bl.Reason = ErrUrlError.Error()
		bl.ErrString = err.Error()
	}
	bl.Unique = UniqueHash(bl)
	return bl
}

func NewInvalidBaseline(u, host string, resp *ihttp.Response, reason string) *Baseline {
	bl := &Baseline{
		SprayResult: &parsers.SprayResult{
			UrlString: u,
			Status:    resp.StatusCode(),
			IsValid:   false,
			Reason:    reason,
		},
	}

	// 无效数据也要读取body, 否则keep-alive不生效
	resp.Body()
	bl.BodyLength = int(resp.ContentLength())
	bl.RedirectURL = string(resp.GetHeader("Location"))

	bl.Dir = bl.IsDir()
	uu, err := url.Parse(u)
	if err == nil {
		bl.Path = uu.Path
		bl.Url = uu
	} else {
		return bl
	}

	if bl.Url.Host != host {
		bl.Host = host
	}

	return bl
}

type Baseline struct {
	*parsers.SprayResult
	Url       *url.URL       `json:"-"`
	Dir       bool           `json:"-"`
	Chunked   bool           `json:"-"`
	Body      BS             `json:"-"`
	Header    BS             `json:"-"`
	Raw       BS             `json:"-"`
	Response  *http.Response `json:"-"`
	Recu      bool           `json:"-"`
	RecuDepth int            `json:"-"`
	URLs      []string       `json:"-"`
	Collected bool           `json:"-"`
	Retry     int            `json:"-"`
}

func (bl *Baseline) IsDir() bool {
	if strings.HasSuffix(bl.Path, "/") {
		return true
	}
	return false
}

// Collect 深度收集信息
func (bl *Baseline) Collect() {
	if bl.Collected { // 防止重复收集
		return
	} else {
		bl.Collected = true
	}

	if bl.ContentType == "html" || bl.ContentType == "json" || bl.ContentType == "txt" {
		// 指纹库设计的时候没考虑js,css文件的指纹, 跳过非必要的指纹收集减少误报提高性能
		//fmt.Println(bl.Source, bl.Url.String()+bl.Path, bl.RedirectURL, "call fingersengine")
		if EnableAllFingerEngine {
			bl.Frameworks = EngineDetect(bl.Raw)
		} else {
			bl.Frameworks = FingersDetect(bl.Raw)
		}
	}

	if len(bl.Body) > 0 {
		if bl.ContentType == "html" {
			bl.Title = iutils.AsciiEncode(parsers.MatchTitle(bl.Body))
		} else if bl.ContentType == "ico" {
			if frame := FingerEngine.HashContentMatch(bl.Body); frame != nil {
				bl.Frameworks.Add(frame)
			}
		}
	}

	bl.Hashes = parsers.NewHashes(bl.Raw)
	bl.Extracteds = Extractors.Extract(string(bl.Raw))
	bl.Unique = UniqueHash(bl)
}

func (bl *Baseline) CollectURL() {
	if len(bl.Body) == 0 {
		return
	}
	for _, reg := range ExtractRegexps["js"][0].CompiledRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			u[1] = CleanURL(u[1])
			if u[1] != "" && !FilterJs(u[1]) {
				bl.URLs = append(bl.URLs, u[1])
			}
		}
	}

	for _, reg := range ExtractRegexps["url"][0].CompiledRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			u[1] = CleanURL(u[1])
			if u[1] != "" && !FilterUrl(u[1]) {
				bl.URLs = append(bl.URLs, u[1])
			}
		}
	}

	bl.URLs = iutils.StringsUnique(bl.URLs)
	if len(bl.URLs) != 0 {
		bl.Extracteds = append(bl.Extracteds, &parsers.Extracted{
			Name:          "crawl",
			ExtractResult: bl.URLs,
		})
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

var Distance uint8 = 5 // 数字越小越相似, 数字为0则为完全一致.

func (bl *Baseline) FuzzyCompare(other *Baseline) bool {
	// 这里使用rawsimhash, 是为了保证一定数量的字符串, 否则超短的body会导致simhash偏差指较大
	if other.Distance = encode.SimhashCompare(other.RawSimhash, bl.RawSimhash); other.Distance < Distance {
		return true
	}
	return false
}
