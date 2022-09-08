package main

import (
	"flag"
	"github.com/chainreactors/logs"
	"spray/internal"
)

func main() {
	var runner internal.Runner
	flag.StringVar(&runner.URL, "u", "", "url")
	flag.StringVar(&runner.URLFile, "U", "", "url filename")
	flag.StringVar(&runner.WordFile, "w", "", "wordlist filename")
	flag.StringVar(&runner.OutputFile, "f", "", "output filename")
	flag.BoolVar(&runner.Debug, "debug", false, "print debug info")
	flag.Parse()

	err := runner.Prepare()
	if err != nil {
		logs.Log.Errorf(err.Error())
		return
	}
	runner.Run()
}
