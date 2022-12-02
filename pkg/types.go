package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/parsers"
	"strings"
)

type Frameworks []*parsers.Framework

func (fs Frameworks) String() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		frameworkStrs[i] = "[" + f.ToString() + "]"
	}
	return strings.Join(frameworkStrs, " ") + " "
}

type Extracteds []*fingers.Extracted

func (es Extracteds) String() string {
	var s strings.Builder
	for _, e := range es {
		s.WriteString("[ " + e.ToString() + " ]")
	}
	return s.String() + " "
}

var Extractors = make(fingers.Extractors)
