package ihttp

import (
	"github.com/valyala/fasthttp"
	"net/http"
)

type Request struct {
	StandardRequest *http.Request
	FastRequest     *fasthttp.Request
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
