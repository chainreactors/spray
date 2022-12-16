package internal

import (
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/rule"
)

type ErrorType uint

const (
	ErrBadStatus ErrorType = iota
	ErrSameStatus
	ErrRequestFailed
	ErrWaf
	ErrRedirect
	ErrCompareFailed
	ErrFuzzyCompareFailed
	ErrCustomCompareFailed
	ErrCustomFilter
)

func (e ErrorType) Error() string {
	switch e {
	case ErrBadStatus:
		return "blacklist status"
	case ErrSameStatus:
		return "same status with random baseline"
	case ErrRequestFailed:
		return "request failed"
	case ErrWaf:
		return "maybe banned by waf"
	case ErrRedirect:
		return "duplicate redirect url"
	case ErrCompareFailed:
		return "compare failed"
	case ErrFuzzyCompareFailed:
		return "fuzzy compare failed"
	case ErrCustomCompareFailed:
		return "custom compare failed"
	case ErrCustomFilter:
		return "custom filtered"
	default:
		return "unknown error"
	}
}

type sourceType int

const (
	CheckSource sourceType = iota + 1
	InitRandomSource
	InitIndexSource
	RedirectSource
	WordSource
	WafSource
)

func newUnit(path string, source sourceType) *Unit {
	return &Unit{path: path, source: source}
}

func newUnitWithNumber(path string, source sourceType, number int) *Unit {
	return &Unit{number: number, path: path, source: source}
}

type Unit struct {
	number   int
	path     string
	source   sourceType
	frontUrl string
	reCount  int // redirect number
}

type Task struct {
	baseUrl string
	depth   int
	rule    []rule.Expression
	origin  *pkg.Statistor
}
