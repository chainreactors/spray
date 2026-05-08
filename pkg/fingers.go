package pkg

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
)

// gogo fingers engine
func FingersDetect(content []byte) common.Frameworks {
	if FingerEngine == nil || FingerEngine.Fingers() == nil {
		return nil
	}
	frames, _ := FingerEngine.Fingers().HTTPMatch(bytes.ToLower(content), "")
	return frames
}

func EngineDetect(content []byte) common.Frameworks {
	if FingerEngine == nil {
		return nil
	}
	frames, _ := FingerEngine.DetectContent(content)
	return frames
}
