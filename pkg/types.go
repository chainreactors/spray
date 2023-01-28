package pkg

import (
	"github.com/chainreactors/parsers"
	"strings"
)

type Frameworks []*parsers.Framework

func (fs Frameworks) String() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		frameworkStrs[i] = " [" + f.String() + "]"
	}
	return strings.Join(frameworkStrs, " ") + " "
}

func GetSourceName(s int) string {
	switch s {
	case 1:
		return "check"
	case 2:
		return "random"
	case 3:
		return "index"
	case 4:
		return "redirect"
	case 5:
		return "crawl"
	case 6:
		return "active"
	case 7:
		return "word"
	case 8:
		return "waf"
	case 9:
		return "rule"
	case 10:
		return "bak"
	case 11:
		return "common"
	default:
		return "unknown"
	}
}
