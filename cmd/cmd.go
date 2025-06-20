package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/iutils"
	"github.com/jessevdk/go-flags"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var ver = "dev"
var DefaultConfig = "config.yaml"

func init() {
	logs.Log.SetColorMap(map[logs.Level]func(string) string{
		logs.Info:      logs.PurpleBold,
		logs.Important: logs.GreenBold,
		pkg.LogVerbose: logs.Green,
	})
}

func Spray() {
	var option core.Option

	if files.IsExist(DefaultConfig) {
		logs.Log.Debug("config.yaml exist, loading")
		err := core.LoadConfig(DefaultConfig, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
	}

	parser := flags.NewParser(&option, flags.Default)
	parser.Usage = `

  WIKI: https://chainreactors.github.io/wiki/spray
  
  QUICKSTART:
	basic:
	  spray -u http://example.com

	basic cidr and port:
	  spray -i example -p top2,top3

    simple brute:
      spray -u http://example.com -d wordlist1.txt -d wordlist2.txt

    mask-base brute with wordlist:
      spray -u http://example.com -w "/aaa/bbb{?l#4}/ccc"

    rule-base brute with wordlist:
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
	logs.AddLevel(pkg.LogVerbose, "verbose", "[=] %s {{suffix}}\n")
	if option.Debug {
		logs.Log.SetLevel(logs.Debug)
	} else if len(option.Verbose) > 0 {
		logs.Log.SetLevel(pkg.LogVerbose)
	}
	if option.InitConfig {
		configStr := core.InitDefaultConfig(&option, 0)
		err := os.WriteFile(DefaultConfig, []byte(configStr), 0o744)
		if err != nil {
			logs.Log.Warn("cannot create config: config.yaml, " + err.Error())
			return
		}
		if files.IsExist(DefaultConfig) {
			logs.Log.Warn("override default config: ./config.yaml")
		}
		logs.Log.Info("init default config: ./config.yaml")
		return
	}

	defer time.Sleep(time.Second)
	if option.Config != "" {
		err := core.LoadConfig(option.Config, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		if files.IsExist(DefaultConfig) {
			logs.Log.Warnf("custom config %s, override default config", option.Config)
		} else {
			logs.Log.Important("load config: " + option.Config)
		}
	}

	if option.Version {
		fmt.Println(ver)
		return
	}

	if option.PrintPreset {
		err = pkg.Load()
		if err != nil {
			iutils.Fatal(err.Error())
		}

		err = pkg.LoadFingers()
		if err != nil {
			iutils.Fatal(err.Error())
		}
		core.PrintPreset()

		return
	}

	if option.Format != "" {
		core.Format(option)
		return
	}

	err = option.Prepare()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

	runner, err := option.NewRunner()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}
	if option.ReadAll || runner.CrawlPlugin {
		ihttp.DefaultMaxBodySize = -1
	}

	ctx, canceler := context.WithTimeout(context.Background(), time.Duration(runner.Deadline)*time.Second)
	go func() {
		select {
		case <-ctx.Done():
			time.Sleep(10 * time.Second)
			logs.Log.Errorf("deadline and timeout not work, hard exit!!!")
			os.Exit(0)
		}
	}()

	go func() {
		exitChan := make(chan os.Signal, 2)
		signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			sigCount := 0
			for {
				<-exitChan
				sigCount++
				if sigCount == 1 {
					logs.Log.Infof("Exit signal received, saving task and exiting...")
					canceler()
				} else if sigCount == 2 {
					logs.Log.Infof("forcing exit...")
					os.Exit(1)
				}
			}
		}()
	}()

	err = runner.Prepare(ctx)
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

}
