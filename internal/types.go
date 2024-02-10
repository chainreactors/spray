package internal

import (
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
)

type Source int

const (
	CheckSource Source = iota + 1
	InitRandomSource
	InitIndexSource
	RedirectSource
	CrawlSource
	FingerSource
	WordSource
	WafSource
	RuleSource
	BakSource
	CommonFileSource
	UpgradeSource
	RetrySource
	AppendSource
)

// Name return the name of the source
func (s Source) Name() string {
	switch s {
	case CheckSource:
		return "check"
	case InitRandomSource:
		return "random"
	case InitIndexSource:
		return "index"
	case RedirectSource:
		return "redirect"
	case CrawlSource:
		return "crawl"
	case FingerSource:
		return "finger"
	case WordSource:
		return "word"
	case WafSource:
		return "waf"
	case RuleSource:
		return "rule"
	case BakSource:
		return "bak"
	case CommonFileSource:
		return "common"
	case UpgradeSource:
		return "upgrade"
	case RetrySource:
		return "retry"
	case AppendSource:
		return "append"
	default:
		return "unknown"
	}
}

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
