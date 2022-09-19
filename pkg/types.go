package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"strings"
)

var Fingers fingers.Fingers

func FingerDetect(content string) Frameworks {
	var frames Frameworks
	//content := string(body)
	for _, finger := range Fingers {
		frame, _, ok := fingers.FingerMatcher(finger, content, 0, nil)
		if ok {
			frames = append(frames, frame)
		}
	}
	return frames
}

type Frameworks []*fingers.Framework

func (fs Frameworks) ToString() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		frameworkStrs[i] = "[" + f.ToString() + "]"
	}
	return strings.Join(frameworkStrs, " ")
}

type Extracteds []*fingers.Extracted

var Extractors = make(fingers.Extractors)
