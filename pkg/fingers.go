package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/parsers"
)

// gogo fingers engine
func FingerDetect(content []byte) parsers.Frameworks {
	frames := make(parsers.Frameworks)
	for _, finger := range Fingers {
		// sender置空, 所有的发包交给spray的pool
		frame, _, ok := fingers.FingerMatcher(finger, map[string]interface{}{"content": content}, 0, nil)
		if ok {
			frames[frame.Name] = frame
		}
	}
	return frames
}
