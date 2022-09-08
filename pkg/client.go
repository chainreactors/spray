package pkg

import (
	"context"
	"crypto/tls"
	"net"
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
		DialContext: (&net.Dialer{
			//Timeout:   time.Duration(delay) * time.Second,
			//KeepAlive: time.Duration(delay) * time.Second,
			//DualStack: true,
		}).DialContext,
		MaxIdleConnsPerHost: thread,
		MaxIdleConns:        thread,
		IdleConnTimeout:     time.Duration(timeout) * time.Second,
		DisableKeepAlives:   false,
	}

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
