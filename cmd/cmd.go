package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/jessevdk/go-flags"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var ver = "v0.9.6"
var DefaultConfig = "config.yaml"

func init() {
	logs.Log.SetColorMap(map[logs.Level]func(string) string{
		logs.Info:      logs.PurpleBold,
		logs.Important: logs.GreenBold,
		pkg.LogVerbose: logs.Green,
	})
}

func Spray() {
	var option internal.Option

	if files.IsExist(DefaultConfig) {
		logs.Log.Debug("config.yaml exist, loading")
		err := internal.LoadConfig(DefaultConfig, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
	}

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
	if option.InitConfig {
		configStr := internal.InitDefaultConfig(&option, 0)
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
	if option.Config != "" {
		err := internal.LoadConfig(option.Config, &option)
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

	if option.Format != "" {
		internal.Format(option.Format, !option.NoColor)
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
	if option.ReadAll || runner.Crawl {
		ihttp.DefaultMaxBodySize = -1
	}

	ctx, canceler := context.WithTimeout(context.Background(), time.Duration(runner.Deadline)*time.Second)

	err = runner.Prepare(ctx)
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

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

	if runner.IsCheck {
		runner.RunWithCheck(ctx)
	} else {
		runner.Run(ctx)
	}
	time.Sleep(1 * time.Second)
}
