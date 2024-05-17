package ihttp

import (
	"github.com/valyala/fasthttp"
	"net/http"
)

func BuildPathRequest(clientType int, base, path, method string) (*Request, error) {
	if clientType == FAST {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod(method)
		req.SetRequestURI(base + path)
		return &Request{FastRequest: req, ClientType: FAST}, nil
	} else {
		req, err := http.NewRequest(method, base+path, nil)
		return &Request{StandardRequest: req, ClientType: STANDARD}, err
	}
}

func BuildHostRequest(clientType int, base, host string) (*Request, error) {
	if clientType == FAST {
		req := fasthttp.AcquireRequest()
		req.SetRequestURI(base)
		req.SetHost(host)
		return &Request{FastRequest: req, ClientType: FAST}, nil
	} else {
		req, err := http.NewRequest("GET", base, nil)
		req.Host = host
		return &Request{StandardRequest: req, ClientType: STANDARD}, err
	}
}

type Request struct {
	StandardRequest *http.Request
	FastRequest     *fasthttp.Request
	ClientType      int
}

func (r *Request) SetHeaders(header map[string]string) {
	if r.StandardRequest != nil {
		for k, v := range header {
			r.StandardRequest.Header.Set(k, v)
		}
	} else if r.FastRequest != nil {
		for k, v := range header {
			r.FastRequest.Header.Set(k, v)
		}
	}
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
