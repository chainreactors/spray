package pkg

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)

func NewClient(thread int, timeout int) *Client {
	tr := &http.Transport{
		//Proxy: Proxy,
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		MaxConnsPerHost: thread,
		IdleConnTimeout: time.Duration(timeout) * time.Second,
	}
	//c := &fasthttp.Client{
	//	TLSConfig: &tls.Config{
	//		Renegotiation:      tls.RenegotiateOnceAsClient,
	//		InsecureSkipVerify: true,
	//	},
	//	MaxConnsPerHost:     thread,
	//	MaxIdleConnDuration: time.Duration(timeout) * time.Second,
	//}
	c := &Client{
		client: &http.Client{
			Transport:     tr,
			Timeout:       time.Second * time.Duration(timeout),
			CheckRedirect: checkRedirect,
		},
	}

	//c.Method = method
	//c.Headers = Opt.Headers
	//c.Mod = Opt.Mod

	return c
}

type Client struct {
	client *http.Client
}

func (c Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	//if req.Header == nil {
	//	req.Header = c.Headers
	//}

	return c.client.Do(req)
}

var MaxRedirects = 0
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return http.ErrUseLastResponse
	}

	return nil
}
