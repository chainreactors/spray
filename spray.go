//go:generate go run templates/templates_gen.go -t templates -o pkg/templates.go -need http,rule,mask,extract
package main

import "github.com/chainreactors/spray/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.Spray()
}
