package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/iutils"
	"github.com/jessevdk/go-flags"
)

type RunOptions struct {
	Output        io.Writer
	DefaultConfig string
	Version       string
	BeforePrepare func(*Option) error
	AfterPrepare  func(*Option) error
}

func Help() string {
	var option Option
	parser := flags.NewParser(&option, flags.Default&^flags.PrintErrors)
	parser.Usage = Usage()
	var buf bytes.Buffer
	parser.WriteHelp(&buf)
	return buf.String()
}

func RunWithArgs(ctx context.Context, args []string, opts RunOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var option Option
	output := opts.Output
	if output == nil {
		output = os.Stdout
	}
	defaultConfig := opts.DefaultConfig
	if defaultConfig == "" {
		defaultConfig = "config.yaml"
	}

	if opts.Output != nil {
		oldLog := logs.Log
		logs.Log = logs.NewLogger(oldLog.Level)
		logs.Log.SetOutput(output)
		defer func() {
			logs.Log = oldLog
		}()
	}

	if files.IsExist(defaultConfig) {
		logs.Log.Debug("config.yaml exist, loading")
		err := LoadConfig(defaultConfig, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return err
		}
	}

	parser := flags.NewParser(&option, flags.Default&^flags.PrintErrors)
	parser.Usage = Usage()
	if _, err := parser.ParseArgs(args); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			fmt.Fprintln(output, err.Error())
			return nil
		}
		return err
	}

	logs.AddLevel(pkg.LogVerbose, "verbose", "[=] %s {{suffix}}\n")
	if option.Debug {
		logs.Log.SetLevel(logs.Level(10))
	} else if len(option.Verbose) > 0 {
		logs.Log.SetLevel(pkg.LogVerbose)
	}
	if option.InitConfig {
		configStr := InitDefaultConfig(&option, 0)
		err := os.WriteFile(defaultConfig, []byte(configStr), 0o744)
		if err != nil {
			logs.Log.Warn("cannot create config: config.yaml, " + err.Error())
			return err
		}
		if files.IsExist(defaultConfig) {
			logs.Log.Warn("override default config: ./config.yaml")
		}
		logs.Log.Info("init default config: ./config.yaml")
		return nil
	}

	if option.Config != "" {
		err := LoadConfig(option.Config, &option)
		if err != nil {
			logs.Log.Error(err.Error())
			return err
		}
		if files.IsExist(defaultConfig) {
			logs.Log.Warnf("custom config %s, override default config", option.Config)
		} else {
			logs.Log.Important("load config: " + option.Config)
		}
	}

	if option.Version {
		version := opts.Version
		if version == "" {
			version = "dev"
		}
		fmt.Fprintln(output, version)
		return nil
	}
	if option.PrintPreset {
		err := pkg.Load()
		if err != nil {
			iutils.Fatal(err.Error())
		}
		err = pkg.LoadFingers()
		if err != nil {
			iutils.Fatal(err.Error())
		}
		PrintPreset()
		return nil
	}
	if option.Format != "" {
		Format(option)
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if opts.BeforePrepare != nil {
		if err := opts.BeforePrepare(&option); err != nil {
			return err
		}
	}
	if err := option.Prepare(); err != nil {
		return err
	}
	if opts.AfterPrepare != nil {
		if err := opts.AfterPrepare(&option); err != nil {
			return err
		}
	}

	runner, err := option.NewRunner()
	if err != nil {
		return err
	}
	defer runner.CloseFiles()
	if option.ReadAll {
		ihttp.DefaultMaxBodySize = -1
	}

	if err := runner.Prepare(ctx); err != nil {
		return err
	}

	if runner.IsCheck {
		runner.RunWithCheck(ctx)
	} else {
		runner.RunWithBrute(ctx)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func Usage() string {
	return `

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

    mask in url (equivalent to above):
      spray -u "http://example.com/aaa/bbb{?l#4}/ccc"

    rule-base brute with wordlist:
      spray -u http://example.com -r rule.txt -d 1.txt

    list input spray:
      spray -l url.txt -r rule.txt -d 1.txt

    resume:
      spray --resume stat.json
`
}
