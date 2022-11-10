package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/parsers"
	"strings"
)

type Frameworks []*parsers.Framework

func (fs Frameworks) ToString() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		frameworkStrs[i] = "[" + f.ToString() + "]"
	}
	return strings.Join(frameworkStrs, " ")
}

type Extracteds []*fingers.Extracted

var Extractors = make(fingers.Extractors)
