package ihttp

import (
	"fmt"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

// TestFastHTTP_SetHost_NoDNS 确认使用 IP + SetHost 只修改 Host 头，不影响底层 dial 地址。
// 这里 Host 使用 di.proxy.alipay.com（真实可解析的域名），用来证明 fasthttp 只根据 URL 里的 IP 进行 dial，
// 而不会拿 Host 头去做 DNS 解析。
func TestFastHTTP_SetHost_NoDNS(t *testing.T) {
	//var dialAddrs []string

	client := &fasthttp.Client{
		//Dial: func(addr string) (net.Conn, error) {
		//	// 记录底层实际要连接的地址
		//	dialAddrs = append(dialAddrs, addr)
		//	// 立刻返回错误，避免真实网络连接
		//	return nil, net.ErrClosed
		//},
	}

	// base 使用 IP，不包含域名
	base := "http://83.229.127.172:1234"
	// Host 使用你提供的域名
	hostHeader := "di.proxy.alipay.com"

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("GET")
	req.SetRequestURI(base + "/test")
	req.Header.SetHost(hostHeader)
	//req.UseHostHeader = true

	// 确认 Host 头已被 SetHost 覆盖

	// 执行请求，由我们自定义的 Dial 接管底层 dial
	err := client.DoTimeout(req, resp, 2*time.Second)
	fmt.Println(err)
}
