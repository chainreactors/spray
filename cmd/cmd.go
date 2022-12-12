package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal"
	"github.com/jessevdk/go-flags"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Spray() {
	var option internal.Option
	parser := flags.NewParser(&option, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
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
			fmt.Println("exit signal, save stat and exit")
			canceler()
		}()
	}()

	if runner.CheckOnly {
		runner.RunWithCheck(ctx)
	} else {
		runner.Run(ctx)
	}
}
