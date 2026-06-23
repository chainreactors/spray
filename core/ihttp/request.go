package ihttp

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/chainreactors/spray/pkg"
	"github.com/valyala/fasthttp"
)

// RequestConfig 封装HTTP请求相关的配置参数
type RequestConfig struct {
	Method          string
	Headers         http.Header
	Host            string
	Path            string
	Body            []byte
	RawQuery        string
	RandomUserAgent bool
}

const FuzzMarker = "{{FUZZ}}"

// Build 根据配置构建Request对象.
// word 是当前迭代的字典词，用于替换所有字段中的 {{FUZZ}} 占位符.
func (rc *RequestConfig) Build(ctx context.Context, clientType int, base, path, host, word string) (*Request, error) {
	fuzz := func(s string) string {
		return strings.ReplaceAll(s, FuzzMarker, word)
	}

	// 使用配置的 Host 或传入的 host, 并替换 FUZZ
	hostToUse := host
	if rc.Host != "" {
		hostToUse = fuzz(rc.Host)
	}

	// 使用配置的 Path 或传入的 path, 并替换 FUZZ
	pathToUse := path
	if rc.Path != "" {
		pathToUse = fuzz(rc.Path)
	}

	// 构建完整的URL，使用 SafePath 避免 host + path 直接拼接
	var fullURL string
	if u, err := url.Parse(base); err == nil && u.Scheme != "" && u.Host != "" {
		// 只有当pathToUse不为空时才修改路径，否则保留原始URL的路径
		if pathToUse != "" {
			u.Path = pkg.SafePath(pkg.Dir(u.Path), pathToUse)
		}
		if rc.RawQuery != "" {
			u.RawQuery = fuzz(rc.RawQuery)
		}
		fullURL = u.String()
	} else {
		fullURL = base + pkg.SafePath("/", pathToUse)
	}

	// 替换 body 中的 FUZZ
	body := rc.Body
	if len(body) > 0 && strings.Contains(string(body), FuzzMarker) {
		body = []byte(fuzz(string(body)))
	}

	var req *Request
	var err error

	if clientType == FAST {
		fastReq := fasthttp.AcquireRequest()
		fastReq.Header.SetMethod(rc.Method)
		fastReq.SetRequestURI(fullURL)
		if hostToUse != "" {
			fastReq.SetHost(hostToUse)
		}
		if len(body) > 0 {
			fastReq.SetBody(body)
		}
		req = &Request{FastRequest: fastReq, ClientType: FAST}
	} else {
		var bodyReader *strings.Reader
		if len(body) > 0 {
			bodyReader = strings.NewReader(string(body))
		}
		var httpReq *http.Request
		if bodyReader != nil {
			httpReq, err = http.NewRequestWithContext(ctx, rc.Method, fullURL, bodyReader)
		} else {
			httpReq, err = http.NewRequestWithContext(ctx, rc.Method, fullURL, nil)
		}
		if err != nil {
			return nil, err
		}
		if hostToUse != "" {
			httpReq.Host = hostToUse
		}
		req = &Request{StandardRequest: httpReq, ClientType: STANDARD}
	}

	// 设置headers, 替换 FUZZ
	rc.setHeadersWithFuzz(req, word)

	return req, nil
}

func (rc *RequestConfig) setHeadersWithFuzz(r *Request, word string) {
	if rc.RandomUserAgent {
		r.SetHeader("User-Agent", pkg.RandomUA())
	}

	for k, vs := range rc.Headers {
		for _, v := range vs {
			val := strings.ReplaceAll(v, FuzzMarker, word)
			if r.StandardRequest != nil {
				r.StandardRequest.Header.Set(k, val)
			} else if r.FastRequest != nil {
				r.FastRequest.Header.Set(k, val)
			}
		}
	}
}

func BuildRequest(ctx context.Context, clientType int, base, path, host, method string) (*Request, error) {
	return BuildRequestWithBody(ctx, clientType, base, path, host, method, nil)
}

func BuildRequestWithBody(ctx context.Context, clientType int, base, path, host, method string, body []byte) (*Request, error) {
	if clientType == FAST {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod(method)
		req.SetRequestURI(base + path)
		if host != "" {
			req.SetHost(host)
		}
		if body != nil && len(body) > 0 {
			req.SetBody(body)
		}
		return &Request{FastRequest: req, ClientType: FAST}, nil
	} else {
		var bodyReader *strings.Reader
		if body != nil && len(body) > 0 {
			bodyReader = strings.NewReader(string(body))
		}
		var req *http.Request
		var err error
		if bodyReader != nil {
			req, err = http.NewRequestWithContext(ctx, method, base+path, bodyReader)
		} else {
			req, err = http.NewRequestWithContext(ctx, method, base+path, nil)
		}
		if host != "" {
			req.Host = host
		}
		return &Request{StandardRequest: req, ClientType: STANDARD}, err
	}
}

type Request struct {
	StandardRequest *http.Request
	FastRequest     *fasthttp.Request
	ClientType      int
}

func (r *Request) SetHeader(key, value string) {
	if r.StandardRequest != nil {
		r.StandardRequest.Header.Set(key, value)
	} else if r.FastRequest != nil {
		r.FastRequest.Header.Set(key, value)
	}
}

func (r *Request) URI() string {
	if r.FastRequest != nil {
		return r.FastRequest.URI().String()
	} else if r.StandardRequest != nil {
		return r.StandardRequest.URL.String()
	} else {
		return ""
	}
}

func (r *Request) Host() string {
	if r.FastRequest != nil {
		return string(r.FastRequest.Host())
	} else if r.StandardRequest != nil {
		return r.StandardRequest.Host
	} else {
		return ""
	}
}
