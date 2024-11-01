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
	parent   int
	host     string
	path     string
	from     parsers.SpraySource
	source   parsers.SpraySource
	retry    int
	frontUrl string
	depth    int
}

func (u *Unit) Update(bl *pkg.Baseline) {
	bl.Number = u.number
	bl.Parent = u.parent
	bl.Host = u.host
	bl.Path = u.path
	bl.Source = u.source
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
