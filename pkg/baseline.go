package pkg

import (
	"bytes"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"github.com/chainreactors/spray/pkg/ihttp"
	"net/url"
	"strings"
)

func NewBaseline(u, host string, resp *ihttp.Response) *Baseline {
	bl := &Baseline{
		SprayResult: &parsers.SprayResult{
			UrlString:  u,
			Status:     resp.StatusCode(),
			IsValid:    true,
			Frameworks: make(parsers.Frameworks),
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

	if i := resp.ContentLength(); i != 0 && bl.ContentType != "bin" {
		body := resp.Body()
		bl.Body = make([]byte, len(body))
		copy(bl.Body, body)

		if i == -1 {
			bl.Chunked = true
			bl.BodyLength = len(bl.Body)
		} else {
			bl.BodyLength = i
		}
	}

	bl.Raw = append(bl.Header, bl.Body...)
	if r := resp.GetHeader("Location"); r != "" {
		bl.RedirectURL = r
	} else {
		bl.RedirectURL = resp.GetHeader("location")
	}

	bl.Dir = bl.IsDir()
	uu, err := url.Parse(u)
	if err == nil {
		bl.Path = uu.Path
		bl.Url = uu
	}

	if bl.Url.Host != host {
		bl.Host = host
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
	bl.BodyLength = resp.ContentLength()
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
	Unique    uint16   `json:"-"`
	Url       *url.URL `json:"-"`
	Dir       bool     `json:"-"`
	Chunked   bool     `json:"-"`
	Body      []byte   `json:"-"`
	Header    []byte   `json:"-"`
	Raw       []byte   `json:"-"`
	Recu      bool     `json:"-"`
	RecuDepth int      `json:"-"`
	URLs      []string `json:"-"`
	Collected bool     `json:"-"`
}

func (bl *Baseline) IsDir() bool {
	if strings.HasSuffix(bl.Path, "/") {
		return true
	}
	return false
}

// Collect 深度收集信息
func (bl *Baseline) Collect() {
	bl.Frameworks = FingerDetect(string(bl.Raw))
	if len(bl.Body) > 0 {
		if bl.ContentType == "html" {
			bl.Title = iutils.AsciiEncode(parsers.MatchTitle(string(bl.Body)))
		} else if bl.ContentType == "ico" {
			if name, ok := Md5Fingers[parsers.Md5Hash(bl.Body)]; ok {
				bl.Frameworks[name] = &parsers.Framework{Name: name}
			} else if name, ok := Mmh3Fingers[parsers.Mmh3Hash32(bl.Body)]; ok {
				bl.Frameworks[name] = &parsers.Framework{Name: name}
			}
		}
	}

	bl.Hashes = parsers.NewHashes(bl.Raw)
	bl.Extracteds = Extractors.Extract(string(bl.Raw))
	bl.Unique = UniqueHash(bl)
}

func (bl *Baseline) CollectURL() {
	if bl.Collected {
		// 防止重复收集
		return
	} else {
		bl.Collected = true
	}

	if len(bl.Body) == 0 {
		return
	}
	for _, reg := range ExtractRegexps["js"][0].CompiledRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			u[1] = formatURL(u[1])
			if u[1] != "" && !filterJs(u[1]) {
				bl.URLs = append(bl.URLs, u[1])
			}
		}
	}

	for _, reg := range ExtractRegexps["url"][0].CompiledRegexps {
		urls := reg.FindAllStringSubmatch(string(bl.Body), -1)
		for _, u := range urls {
			u[1] = formatURL(u[1])
			if u[1] != "" && !filterUrl(u[1]) {
				bl.URLs = append(bl.URLs, u[1])
			}
		}
	}

	bl.URLs = RemoveDuplication(bl.URLs)
	if bl.URLs != nil {
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
	if other.Distance = parsers.SimhashCompare(other.RawSimhash, bl.RawSimhash); other.Distance < Distance {
		return true
	}
	return false
}
