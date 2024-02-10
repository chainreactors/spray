package pool

import "github.com/chainreactors/parsers"

func newUnit(path string, source parsers.SpraySource) *Unit {
	return &Unit{path: path, source: source}
}

func newUnitWithNumber(path string, source parsers.SpraySource, number int) *Unit {
	return &Unit{path: path, source: source, number: number}
}

type Unit struct {
	number   int
	path     string
	source   parsers.SpraySource
	retry    int
	frontUrl string
	depth    int // redirect depth
}
