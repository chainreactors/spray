package core

import (
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
)

func NewOrigin(stat *pkg.Statistor) *Origin {
	return &Origin{Statistor: stat}
}

type Origin struct {
	*pkg.Statistor
	sum int
}

func (o *Origin) InitWorder(fns []words.WordFunc) (*words.Worder, error) {
	var worder *words.Worder
	wl, err := pkg.LoadWordlist(o.Word, o.Dictionaries)
	if err != nil {
		return nil, err
	}
	worder = words.NewWorderWithList(wl)
	worder.Fns = fns
	rules, err := pkg.LoadRuleWithFiles(o.RuleFiles, o.RuleFilter)
	if err != nil {
		return nil, err
	}
	worder.Rules = rules
	if len(rules) > 0 {
		o.sum = len(rules) * len(wl)
	} else {
		o.sum = len(wl)
	}

	return worder, nil
}
