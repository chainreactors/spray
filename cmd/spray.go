package main

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal"
	"github.com/jessevdk/go-flags"
)

func main() {
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

	err = runner.Prepare()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}
	runner.Run()
}
