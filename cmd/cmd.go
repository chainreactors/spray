package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core"
	"github.com/chainreactors/spray/pkg"
	"github.com/jessevdk/go-flags"
)

var ver = "dev"
var DefaultConfig = "config.yaml"

func init() {
	logs.Log.SetColorMap(map[logs.Level]func(string) string{
		logs.InfoLevel:      logs.PurpleBold,
		logs.ImportantLevel: logs.GreenBold,
		pkg.LogVerbose:      logs.Green,
	})
}

func Spray() {
	var option core.Option

	parser := flags.NewParser(&option, flags.Default)
	parser.Usage = core.Usage()
	_, err := parser.ParseArgs(os.Args[1:])
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}

	defer time.Sleep(time.Second)
	ctx, canceler := context.WithTimeout(context.Background(), time.Duration(option.Deadline)*time.Second)
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

	if err := core.RunWithArgs(ctx, os.Args[1:], core.RunOptions{
		DefaultConfig: DefaultConfig,
		Version:       ver,
	}); err != nil {
		logs.Log.Errorf(err.Error())
		return
	}
}
