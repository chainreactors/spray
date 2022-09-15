package main

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal"
	"github.com/jessevdk/go-flags"
)

func main() {
	var runner internal.Runner
	parser := flags.NewParser(&runner, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if err.(*flags.Error).Type != flags.ErrHelp {
			fmt.Println(err.Error())
		}
		return
	}

	err = runner.Prepare()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}
	runner.Run()
}
