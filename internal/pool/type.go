package pool

import (
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg"
)

func newUnit(path string, source parsers.SpraySource) *Unit {
	return &Unit{path: path, source: source}
}

type Unit struct {
	number   int
	host     string
	path     string
	source   parsers.SpraySource
	retry    int
	frontUrl string
	depth    int
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

type SprayMod int

const (
	PathSpray SprayMod = iota + 1
	HostSpray
	ParamSpray
	CustomSpray
)

var ModMap = map[string]SprayMod{
	"path": PathSpray,
	"host": HostSpray,
}
