//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go -need spray
package main

import (
	"github.com/chainreactors/spray/cmd"
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	//_ "net/http/pprof"
)

func init() {
	config.WithOptions(func(opt *config.Options) {
		opt.DecoderConfig.TagName = "config"
		opt.ParseDefault = true
	})
	config.AddDriver(yaml.Driver)
}

func main() {
	// 启动 pprof HTTP 服务器，用于调试 goroutine 泄露等问题
	//go func() {
	//	// 仅监听本地 6060 端口，避免对外暴露
	//	_ = http.ListenAndServe("127.0.0.1:6060", nil)
	//}()

	cmd.Spray()
}
