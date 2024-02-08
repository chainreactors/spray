package internal

import (
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
)

const (
	CheckSource = iota + 1
	InitRandomSource
	InitIndexSource
	RedirectSource
	CrawlSource
	ActiveSource
	WordSource
	WafSource
	RuleSource
	BakSource
	CommonFileSource
	UpgradeSource
	RetrySource
	AppendSource
)

func newUnit(path string, source int) *Unit {
	return &Unit{path: path, source: source}
}

func newUnitWithNumber(path string, source int, number int) *Unit {
	return &Unit{path: path, source: source, number: number}
}

type Unit struct {
	number   int
	path     string
	source   int
	retry    int
	frontUrl string
	depth    int // redirect depth
}

type Task struct {
	baseUrl string
	depth   int
	rule    []rule.Expression
	origin  *Origin
}

func NewOrigin(stat *pkg.Statistor) *Origin {
	return &Origin{Statistor: stat}
}

type Origin struct {
	*pkg.Statistor
	sum int
}

func (o *Origin) InitWorder(fns []func(string) []string) (*words.Worder, error) {
	var worder *words.Worder
	wl, err := loadWordlist(o.Word, o.Dictionaries)
	if err != nil {
		return nil, err
	}
	worder = words.NewWorder(wl)
	worder.Fns = fns
	rules, err := loadRuleWithFiles(o.RuleFiles, o.RuleFilter)
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
