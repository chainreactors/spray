package ihttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/valyala/fasthttp"
	"net/http"
	"time"
)

var (
	DefaultMaxBodySize = 1024 * 100 // 100k
)

const (
	FAST = iota
	STANDARD
)

func NewClient(thread int, timeout int, clientType int) *Client {
	if clientType == FAST {
		return &Client{
			fastClient: &fasthttp.Client{
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
			timeout:    time.Duration(timeout) * time.Second,
			clientType: clientType,
		}
	} else {
		return &Client{
			standardClient: &http.Client{
				Transport: &http.Transport{
					//Proxy: Proxy,
					//TLSHandshakeTimeout : delay * time.Second,
					TLSClientConfig: &tls.Config{
						Renegotiation:      tls.RenegotiateOnceAsClient,
						InsecureSkipVerify: true,
					},
					MaxConnsPerHost: thread,
					IdleConnTimeout: time.Duration(timeout) * time.Second,
				},
				Timeout:       time.Second * time.Duration(timeout),
				CheckRedirect: checkRedirect,
			},
			timeout:    time.Duration(timeout) * time.Second,
			clientType: clientType,
		}
	}
}

type Client struct {
	fastClient     *fasthttp.Client
	standardClient *http.Client
	clientType     int
	timeout        time.Duration
}

func (c *Client) TransToCheck() {
	if c.fastClient != nil {
		c.fastClient.MaxConnsPerHost = 1
	} else if c.standardClient != nil {

	}
}

func (c *Client) FastDo(ctx context.Context, req *fasthttp.Request) (*fasthttp.Response, error) {
	resp := fasthttp.AcquireResponse()
	return resp, c.fastClient.Do(req, resp)
}

func (c *Client) StandardDo(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.standardClient.Do(req)
}

func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if c.fastClient != nil {
		resp, err := c.FastDo(ctx, req.FastRequest)
		return &Response{FastResponse: resp, ClientType: FAST}, err
	} else if c.standardClient != nil {
		resp, err := c.StandardDo(ctx, req.StandardRequest)
		return &Response{StandardResponse: resp, ClientType: STANDARD}, err
	} else {
		return nil, fmt.Errorf("not found client")
	}
}

var MaxRedirects = 0
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return http.ErrUseLastResponse
	}

	return nil
}
