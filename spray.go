//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go -need spray
package main

import (
	"github.com/chainreactors/spray/cmd"
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	"net/http"
	_ "net/http/pprof"
)

func init() {
	config.WithOptions(func(opt *config.Options) {
		opt.DecoderConfig.TagName = "config"
		opt.ParseDefault = true
	})
	config.AddDriver(yaml.Driver)
}

func main() {
	// 启动 pprof HTTP 服务器
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	cmd.Spray()
}
