//go:generate go run internal/templates_gen.go
package main

import "github.com/chainreactors/spray/cmd"

func main() {
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	cmd.Spray()
}
