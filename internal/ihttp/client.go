package ihttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"strings"
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
				Dial:                customDialFunc(config.ProxyAddr, config.Timeout),
				MaxConnsPerHost:     config.Thread * 3 / 2,
				MaxIdleConnDuration: config.Timeout,
				//MaxConnWaitTimeout:  time.Duration(timeout) * time.Second,
				//ReadTimeout:                   time.Duration(timeout) * time.Second,
				//WriteTimeout:                  time.Duration(timeout) * time.Second,
				ReadBufferSize:                16384, // 16k
				MaxResponseBodySize:           int(DefaultMaxBodySize),
				NoDefaultUserAgentHeader:      true,
				DisablePathNormalizing:        true,
				DisableHeaderNamesNormalizing: true,
			},
			Config: config,
		}
	} else {
		client = &Client{
			standardClient: &http.Client{
				Transport: &http.Transport{
					//Proxy: Proxy,
					//TLSHandshakeTimeout : delay * time.Second,
					TLSClientConfig: &tls.Config{
						Renegotiation:      tls.RenegotiateOnceAsClient,
						InsecureSkipVerify: true,
					},
					MaxConnsPerHost: config.Thread * 3 / 2,
					IdleConnTimeout: config.Timeout,
					ReadBufferSize:  16384, // 16k
				},
				Timeout: config.Timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
			Config: config,
		}
		if config.ProxyAddr != "" {
			client.standardClient.Transport.(*http.Transport).Proxy = func(_ *http.Request) (*url.URL, error) {
				return url.Parse(config.ProxyAddr)
			}
		}
	}
	return client
}

type ClientConfig struct {
	Type      int
	Timeout   time.Duration
	Thread    int
	ProxyAddr string
}

type Client struct {
	fastClient     *fasthttp.Client
	standardClient *http.Client
	Config         *ClientConfig
}

func (c *Client) TransToCheck() {
	if c.fastClient != nil {
		c.fastClient.MaxConnsPerHost = -1 // disable keepalive
	} else if c.standardClient != nil {
		c.standardClient.Transport.(*http.Transport).DisableKeepAlives = true // disable keepalive
	}
}

func (c *Client) FastDo(ctx context.Context, req *fasthttp.Request) (*fasthttp.Response, error) {
	resp := fasthttp.AcquireResponse()
	err := c.fastClient.Do(req, resp)
	return resp, err
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

func customDialFunc(proxyAddr string, timeout time.Duration) fasthttp.DialFunc {
	if proxyAddr == "" {
		return func(addr string) (net.Conn, error) {
			return fasthttp.DialTimeout(addr, timeout)
		}
	}
	u, err := url.Parse(proxyAddr)
	if err != nil {
		logs.Log.Error(err.Error())
		return nil
	}
	if strings.ToLower(u.Scheme) == "socks5" {
		return func(addr string) (net.Conn, error) {
			dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}

			// Set up a connection with a timeout
			conn, err := dialer.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}

			// Set deadlines for the connection
			deadline := time.Now().Add(timeout)
			if err := conn.SetDeadline(deadline); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}
	} else {
		return fasthttpproxy.FasthttpHTTPDialerTimeout(u.Host, timeout)
	}
}
