package pkg

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
)

// gogo fingers engine
func FingersDetect(content []byte) common.Frameworks {
	frames, _ := FingerEngine.Fingers().HTTPMatch(bytes.ToLower(content), "")
	return frames
}

func EngineDetect(content []byte) common.Frameworks {
	frames, _ := FingerEngine.DetectContent(content)
	return frames
}
