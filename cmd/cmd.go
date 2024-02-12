package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/internal/pool"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/iutils"
	"github.com/jessevdk/go-flags"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

var ver = "v0.9.3"

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

	// logs
	logs.AddLevel(pkg.LogVerbose, "verbose", "[=] %s {{suffix}}")
	if option.Debug {
		logs.Log.SetLevel(logs.Debug)
	} else if len(option.Verbose) > 0 {
		logs.Log.SetLevel(pkg.LogVerbose)
	}

	logs.Log.SetColorMap(map[logs.Level]func(string) string{
		logs.Info:      logs.PurpleBold,
		logs.Important: logs.GreenBold,
		pkg.LogVerbose: logs.Green,
	})

	// check $home/.config/spray/config.yaml exist, if not, create it
	if option.Config != "" {
		err := internal.LoadConfig(option.Config, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
	}

	if option.Version {
		fmt.Println(ver)
		return
	}

	if option.Format != "" {
		internal.Format(option.Format, !option.NoColor)
		return
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

	// 初始化全局变量
	pkg.Distance = uint8(option.SimhashDistance)
	ihttp.DefaultMaxBodySize = option.MaxBodyLength * 1024
	pool.MaxCrawl = option.CrawlDepth

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
	if option.ReadAll || runner.Crawl {
		ihttp.DefaultMaxBodySize = 0
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
