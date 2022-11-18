package cmd

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal"
	"github.com/jessevdk/go-flags"
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

	runner, err := option.PrepareRunner()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), time.Duration(runner.Deadline)*time.Second)

	err = runner.Prepare(ctx)
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}

	if runner.CheckOnly {
		runner.RunWithCheck(ctx)
	} else {
		runner.Run(ctx)
	}
}
