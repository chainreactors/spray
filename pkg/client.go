package pkg

import (
	"context"
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"net/http"
	"time"
)

var (
	DefaultMaxBodySize = 1024 * 100 // 100k
)

func NewClient(thread int, timeout int) *Client {
	c := &Client{
		client: &fasthttp.Client{
			TLSConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
			//ReadBufferSize:      20480,
			MaxConnsPerHost:     thread * 2,
			MaxIdleConnDuration: time.Duration(timeout) * time.Second,
			MaxConnWaitTimeout:  time.Duration(timeout) * time.Second,
			ReadTimeout:         time.Duration(timeout) * time.Second,
			WriteTimeout:        time.Duration(timeout) * time.Second,
			MaxResponseBodySize: DefaultMaxBodySize,
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
