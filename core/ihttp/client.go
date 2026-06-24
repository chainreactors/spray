package ihttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chainreactors/proxyclient"
	req "github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"net/http"
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
	REQ
)

func NewClient(config *ClientConfig) *Client {
	var client *Client

	if config.Type == FAST {
		tlsConfig := &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		}
		client = &Client{
			fastClient: &fasthttp.Client{
				TLSConfig:           tlsConfig,
				Dial:                customDialFunc(config.ProxyClient, config.Timeout, config.IsTLS, config.ClientFingerprint),
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
	} else if config.Type == REQ {
		client = &Client{
			reqClient:    newReqClient(config),
			ClientConfig: config,
		}
	} else {
		tlsConfig := &tls.Config{
			Renegotiation:      tls.RenegotiateNever,
			InsecureSkipVerify: true,
		}
		transport := &http.Transport{
			DialContext:         config.ProxyClient,
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: config.Timeout,
			MaxConnsPerHost:     config.Thread * 3 / 2,
			IdleConnTimeout:     config.Timeout,
			ReadBufferSize:      16384, // 16k
		}
		if hasTLSFingerprint(config.ClientFingerprint) {
			transport.DialTLSContext = customTLSDialContext(config.ProxyClient, config.Timeout, config.ClientFingerprint)
			transport.ForceAttemptHTTP2 = false
		}
		client = &Client{
			standardClient: &http.Client{
				Transport: transport,
				Timeout:   config.Timeout,
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
	Type              int
	Timeout           time.Duration
	Thread            int
	ProxyClient       proxyclient.Dial
	ClientFingerprint string
	IsTLS             bool
}

type Client struct {
	fastClient     *fasthttp.Client
	standardClient *http.Client
	reqClient      *req.Client
	*ClientConfig
}

func (c *Client) TransToCheck() {
	if c.fastClient != nil {
		c.fastClient.MaxConnsPerHost = -1 // disable keepalive
	} else if c.standardClient != nil {
		c.standardClient.Transport.(*http.Transport).DisableKeepAlives = true // disable keepalive
	} else if c.reqClient != nil {
		c.reqClient.DisableKeepAlives()
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

func (c *Client) ReqDo(httpReq *http.Request) (*http.Response, error) {
	if httpReq == nil {
		return nil, fmt.Errorf("nil request")
	}

	reqReq := c.reqClient.R().
		SetContext(httpReq.Context()).
		DisableAutoReadResponse()
	reqReq.Headers = cloneReqHeaders(httpReq.Header)

	if httpReq.Host != "" && httpReq.Host != httpReq.URL.Host {
		reqReq.SetHeader("Host", httpReq.Host)
	}

	body, err := readRequestBody(httpReq)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		reqReq.SetBodyBytes(body)
	}

	resp, err := reqReq.Send(httpReq.Method, httpReq.URL.String())
	if resp == nil {
		return nil, err
	}
	return resp.Response, err
}

func (c *Client) Do(req *Request) (*Response, error) {
	if c.fastClient != nil {
		resp, err := c.FastDo(req.FastRequest)
		return &Response{FastResponse: resp, ClientType: FAST}, err
	} else if c.reqClient != nil {
		resp, err := c.ReqDo(req.StandardRequest)
		return &Response{StandardResponse: resp, ClientType: REQ}, err
	} else if c.standardClient != nil {
		resp, err := c.StandardDo(req.StandardRequest)
		return &Response{StandardResponse: resp, ClientType: STANDARD}, err
	} else {
		return nil, fmt.Errorf("not found client")
	}
}

func newReqClient(config *ClientConfig) *req.Client {
	client := req.C().
		SetTimeout(config.Timeout).
		EnableInsecureSkipVerify().
		DisableAutoReadResponse().
		SetRedirectPolicy(req.NoRedirectPolicy()).
		SetTLSHandshakeTimeout(config.Timeout)

	client.Transport.
		SetMaxConnsPerHost(config.Thread * 3 / 2).
		SetIdleConnTimeout(config.Timeout).
		SetReadBufferSize(16384)

	if config.ProxyClient != nil {
		client.SetDial(config.ProxyClient)
	}

	applyReqFingerprint(client, config.ClientFingerprint)
	return client
}

func applyReqFingerprint(client *req.Client, fingerprint string) {
	switch normalizeReqFingerprint(fingerprint) {
	case "firefox":
		client.ImpersonateFirefox()
	case "safari":
		client.ImpersonateSafari()
	case "tls-chrome":
		client.SetTLSFingerprintChrome()
	case "tls-firefox":
		client.SetTLSFingerprintFirefox()
	case "edge", "tls-edge":
		client.SetTLSFingerprintEdge()
	case "qq", "tls-qq":
		client.SetTLSFingerprintQQ()
	case "tls-safari":
		client.SetTLSFingerprintSafari()
	case "360", "tls-360":
		client.SetTLSFingerprint360()
	case "ios", "tls-ios":
		client.SetTLSFingerprintIOS()
	case "android", "tls-android":
		client.SetTLSFingerprintAndroid()
	case "tls-random", "tls-randomized", "random":
		client.SetTLSFingerprintRandomized()
	default:
		client.ImpersonateChrome()
	}
}

func normalizeReqFingerprint(fingerprint string) string {
	fingerprint = strings.TrimSpace(strings.ToLower(fingerprint))
	if fingerprint == "" {
		return "chrome"
	}
	return fingerprint
}

func cloneReqHeaders(headers http.Header) http.Header {
	if len(headers) == 0 {
		return nil
	}

	clone := make(http.Header, len(headers))
	for key, values := range headers {
		canonicalKey := http.CanonicalHeaderKey(key)
		clone[canonicalKey] = append(clone[canonicalKey], values...)
	}
	return clone
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return io.ReadAll(body)
	}

	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return body, nil
}

func hasTLSFingerprint(fingerprint string) bool {
	_, ok := tlsClientHelloID(fingerprint)
	return ok
}

func tlsClientHelloID(fingerprint string) (utls.ClientHelloID, bool) {
	switch normalizeReqFingerprint(fingerprint) {
	case "chrome", "tls-chrome":
		return utls.HelloChrome_Auto, true
	case "firefox", "tls-firefox":
		return utls.HelloFirefox_Auto, true
	case "edge", "tls-edge":
		return utls.HelloEdge_Auto, true
	case "qq", "tls-qq":
		return utls.HelloQQ_Auto, true
	case "safari", "tls-safari":
		return utls.HelloSafari_Auto, true
	case "360", "tls-360":
		return utls.Hello360_Auto, true
	case "ios", "tls-ios":
		return utls.HelloIOS_Auto, true
	case "android", "tls-android":
		return utls.HelloAndroid_11_OkHttp, true
	case "random", "tls-random", "tls-randomized":
		return utls.HelloRandomized, true
	default:
		return utls.ClientHelloID{}, false
	}
}

func customTLSDialContext(dialer proxyclient.Dial, timeout time.Duration, fingerprint string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		conn, err := dialContext(dialer, ctx, network, addr, timeout)
		if err != nil {
			return nil, err
		}
		return utlsHandshake(ctx, conn, addr, fingerprint, timeout)
	}
}

func customDialFunc(dialer proxyclient.Dial, timeout time.Duration, isTLS bool, fingerprint string) fasthttp.DialFunc {
	if dialer == nil {
		return func(addr string) (net.Conn, error) {
			conn, err := fasthttp.DialTimeout(addr, timeout)
			if err != nil {
				return nil, err
			}
			if isTLS && hasTLSFingerprint(fingerprint) {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				return utlsHandshake(ctx, conn, addr, fingerprint, timeout)
			}
			return conn, nil
		}
	}
	return func(addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		if isTLS && hasTLSFingerprint(fingerprint) {
			return utlsHandshake(ctx, conn, addr, fingerprint, timeout)
		}
		return conn, nil
	}
}

func dialContext(dialer proxyclient.Dial, ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	if dialer != nil {
		return dialer.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

func utlsHandshake(ctx context.Context, conn net.Conn, addr, fingerprint string, timeout time.Duration) (net.Conn, error) {
	clientHelloID, ok := tlsClientHelloID(fingerprint)
	if !ok {
		return conn, nil
	}

	host := tlsServerName(addr)
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, clientHelloID)
	if timeout > 0 {
		_ = uconn.SetDeadline(time.Now().Add(timeout))
		defer uconn.SetDeadline(time.Time{})
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return uconn, nil
}

func tlsServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
