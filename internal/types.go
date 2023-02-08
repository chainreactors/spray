package internal

import (
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/rule"
)

type ErrorType uint

const (
	NoErr ErrorType = iota
	ErrBadStatus
	ErrSameStatus
	ErrRequestFailed
	ErrWaf
	ErrRedirect
	ErrCompareFailed
	ErrCustomCompareFailed
	ErrCustomFilter
	ErrFuzzyCompareFailed
	ErrFuzzyRedirect
	ErrFuzzyNotUnique
)

var ErrMap = map[ErrorType]string{
	NoErr:                  "",
	ErrBadStatus:           "blacklist status",
	ErrSameStatus:          "same status with random baseline",
	ErrRequestFailed:       "request failed",
	ErrWaf:                 "maybe banned by waf",
	ErrRedirect:            "duplicate redirect url",
	ErrCompareFailed:       "compare failed",
	ErrCustomCompareFailed: "custom compare failed",
	ErrCustomFilter:        "custom filtered",
	ErrFuzzyCompareFailed:  "fuzzy compare failed",
	ErrFuzzyRedirect:       "fuzzy redirect",
	ErrFuzzyNotUnique:      "not unique",
}

func (e ErrorType) Error() string {
	return ErrMap[e]
}

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
	frontUrl string
	depth    int // redirect depth
}

type Task struct {
	baseUrl string
	depth   int
	rule    []rule.Expression
	origin  *pkg.Statistor
}
