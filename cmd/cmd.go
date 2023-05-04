package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"github.com/chainreactors/spray/internal"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/jessevdk/go-flags"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

var ver = ""

func Spray() {
	var option internal.Option
	parser := flags.NewParser(&option, flags.Default)
	parser.Usage = `

  WIKI: https://chainreactors.github.io/wiki/spray
  
  QUICKSTART:
    simple example:
      spray -u http://example.com -d wordlist1.txt -d wordlist2.txt

    mask-base wordlist:
      spray -u http://example.com -w "/aaa/bbb{?l#4}/ccc"

    rule-base wordlist:
      spray -u http://example.com -r rule.txt -d 1.txt

    list input spray:
      spray -l url.txt -r rule.txt -d 1.txt

    resume:
      spray --resume stat.json
`

	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}

	if option.Version {
		fmt.Println(ver)
		return
	}

	if option.Format != "" {
		internal.Format(option.Format, !option.NoColor)
		os.Exit(0)
	}

	err = pkg.LoadTemplates()
	if err != nil {
		iutils.Fatal(err.Error())
	}

	if option.Extracts != nil {
		for _, e := range option.Extracts {
			if reg, ok := pkg.ExtractRegexps[e]; ok {
				pkg.Extractors[e] = reg
			} else {
				pkg.Extractors[e] = []*parsers.Extractor{
					&parsers.Extractor{
						Name:            e,
						CompiledRegexps: []*regexp.Regexp{regexp.MustCompile(e)},
					},
				}
			}
		}
	}
	// 一些全局变量初始化
	if option.Debug {
		logs.Log.Level = logs.Debug
	}

	logs.DefaultColorMap[logs.Info] = logs.PurpleBold
	logs.DefaultColorMap[logs.Important] = logs.GreenBold
	pkg.Distance = uint8(option.SimhashDistance)
	ihttp.DefaultMaxBodySize = option.MaxBodyLength * 1024
	internal.MaxCrawl = option.CrawlDepth
	if option.ReadAll {
		ihttp.DefaultMaxBodySize = 0
	}
	var runner *internal.Runner
	if option.ResumeFrom != "" {
		runner, err = option.PrepareRunner()
	} else {
		runner, err = option.PrepareRunner()
	}

	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

	ctx, canceler := context.WithTimeout(context.Background(), time.Duration(runner.Deadline)*time.Second)

	err = runner.Prepare(ctx)
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			logs.Log.Important("exit signal, save stat and exit")
			canceler()
		}()
	}()

	if runner.CheckOnly {
		runner.RunWithCheck(ctx)
	} else {
		runner.Run(ctx)
	}
}
