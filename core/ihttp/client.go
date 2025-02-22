package ihttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chainreactors/proxyclient"
	"github.com/valyala/fasthttp"
	"net"
	"net/http"
	"time"
)

var (
	DefaultMaxBodySize int64 = 1024 * 100 // 100k
)

func CheckBodySize(size int64) bool {
	if DefaultMaxBodySize == -1 {
		return true
	}
	if DefaultMaxBodySize == 0 {
		return false
	}
	return size < DefaultMaxBodySize
}

const (
	Auto = iota
	FAST
	STANDARD
)

func NewClient(config *ClientConfig) *Client {
	var client *Client

	if config.Type == FAST {
		client = &Client{
			fastClient: &fasthttp.Client{
				TLSConfig: &tls.Config{
					Renegotiation:      tls.RenegotiateOnceAsClient,
					InsecureSkipVerify: true,
				},
				Dial:                customDialFunc(config.ProxyClient, config.Timeout),
				MaxConnsPerHost:     config.Thread * 3 / 2,
				MaxIdleConnDuration: config.Timeout,
				//MaxConnWaitTimeout:  time.Duration(timeout) * time.Second,
				ReadTimeout:                   config.Timeout,
				WriteTimeout:                  config.Timeout,
				ReadBufferSize:                16384, // 16k
				MaxResponseBodySize:           int(DefaultMaxBodySize),
				NoDefaultUserAgentHeader:      true,
				DisablePathNormalizing:        true,
				DisableHeaderNamesNormalizing: true,
			},
			ClientConfig: config,
		}
	} else {
		client = &Client{
			standardClient: &http.Client{
				Transport: &http.Transport{
					DialContext: config.ProxyClient,
					TLSClientConfig: &tls.Config{
						Renegotiation:      tls.RenegotiateNever,
						InsecureSkipVerify: true,
					},
					TLSHandshakeTimeout: config.Timeout,
					MaxConnsPerHost:     config.Thread * 3 / 2,
					IdleConnTimeout:     config.Timeout,
					ReadBufferSize:      16384, // 16k
				},
				Timeout: config.Timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
			ClientConfig: config,
		}
	}
	return client
}

type ClientConfig struct {
	Type        int
	Timeout     time.Duration
	Thread      int
	ProxyClient proxyclient.Dial
}

type Client struct {
	fastClient     *fasthttp.Client
	standardClient *http.Client
	*ClientConfig
}

func (c *Client) TransToCheck() {
	if c.fastClient != nil {
		c.fastClient.MaxConnsPerHost = -1 // disable keepalive
	} else if c.standardClient != nil {
		c.standardClient.Transport.(*http.Transport).DisableKeepAlives = true // disable keepalive
	}
}

func (c *Client) FastDo(req *fasthttp.Request) (*fasthttp.Response, error) {
	resp := fasthttp.AcquireResponse()
	err := c.fastClient.DoTimeout(req, resp, c.Timeout)
	return resp, err
}

func (c *Client) StandardDo(req *http.Request) (*http.Response, error) {
	return c.standardClient.Do(req)
}

func (c *Client) Do(req *Request) (*Response, error) {
	if c.fastClient != nil {
		resp, err := c.FastDo(req.FastRequest)
		return &Response{FastResponse: resp, ClientType: FAST}, err
	} else if c.standardClient != nil {
		resp, err := c.StandardDo(req.StandardRequest)
		return &Response{StandardResponse: resp, ClientType: STANDARD}, err
	} else {
		return nil, fmt.Errorf("not found client")
	}
}

func customDialFunc(dialer proxyclient.Dial, timeout time.Duration) fasthttp.DialFunc {
	if dialer == nil {
		return func(addr string) (net.Conn, error) {
			return fasthttp.DialTimeout(addr, timeout)
		}
	}
	return func(addr string) (net.Conn, error) {
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		return dialer.DialContext(ctx, "tcp", addr)
	}
}
