package pool

import (
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg"
)

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

func NewBaselines() *Baselines {
	return &Baselines{
		baselines: map[int]*pkg.Baseline{},
	}
}

type Baselines struct {
	FailedBaselines []*pkg.Baseline
	random          *pkg.Baseline
	index           *pkg.Baseline
	baselines       map[int]*pkg.Baseline
}
