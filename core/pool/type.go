package pool

import (
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core/baseline"
)

func newUnit(path string, source parsers.SpraySource) *Unit {
	return &Unit{path: path, source: source}
}

type Unit struct {
	number   int
	parent   int
	host     string
	path     string
	from     parsers.SpraySource
	source   parsers.SpraySource
	retry    int
	frontUrl string
	depth    int
}

func (u *Unit) Update(bl *baseline.Baseline) {
	bl.Number = u.number
	bl.Parent = u.parent
	bl.Host = u.host
	bl.Path = u.path
	bl.Source = u.source
}

func NewBaselines() *Baselines {
	return &Baselines{
		baselines: map[int]*baseline.Baseline{},
	}
}

type Baselines struct {
	FailedBaselines []*baseline.Baseline
	random          *baseline.Baseline
	index           *baseline.Baseline
	baselines       map[int]*baseline.Baseline
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
