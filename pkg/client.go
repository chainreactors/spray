package pkg

import (
	"context"
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"net/http"
	"time"
)

func NewClient(thread int, timeout int) *Client {
	//tr := &http.Transport{
	//	//Proxy: Proxy,
	//	//TLSHandshakeTimeout : delay * time.Second,
	//	TLSClientConfig: &tls.Config{
	//		Renegotiation:      tls.RenegotiateOnceAsClient,
	//		InsecureSkipVerify: true,
	//	},
	//	MaxConnsPerHost: thread,
	//	IdleConnTimeout: time.Duration(timeout) * time.Second,
	//}
	c := &Client{
		client: &fasthttp.Client{
			TLSConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
			//ReadBufferSize:      20480,
			MaxConnsPerHost:     thread,
			MaxIdleConnDuration: time.Duration(timeout) * time.Second,
			MaxConnWaitTimeout:  time.Duration(timeout) * time.Second,
			ReadTimeout:         time.Duration(timeout) * time.Second,
			WriteTimeout:        time.Duration(timeout) * time.Second,
			MaxResponseBodySize: 20480,
		},
		timeout: time.Duration(timeout) * time.Second,
	}
	//c := &Client{
	//	client: &http.Client{
	//		Transport:     tr,
	//		Timeout:       time.Second * time.Duration(timeout),
	//		CheckRedirect: checkRedirect,
	//	},
	//}

	//c.Method = method
	//c.Headers = Opt.Headers
	//c.Mod = Opt.Mod

	return c
}

type Client struct {
	client  *fasthttp.Client
	timeout time.Duration
}

func (c *Client) Do(ctx context.Context, req *fasthttp.Request) (*fasthttp.Response, error) {
	//if req.Header == nil {
	//	req.Header = c.Headers
	//}
	resp := fasthttp.AcquireResponse()
	return resp, c.client.Do(req, resp)
}

var MaxRedirects = 0
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return http.ErrUseLastResponse
	}

	return nil
}
