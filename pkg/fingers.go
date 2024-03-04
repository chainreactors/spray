package pkg

import (
	"bytes"
	"github.com/chainreactors/fingers/common"
	"net/http"
)

// gogo fingers engine
func FingersDetect(content []byte) common.Frameworks {
	frames, _ := FingerEngine.FingersEngine.Match(bytes.ToLower(content), "")
	return frames
}

func FingerPrintHubDetect(header http.Header, body string) common.Frameworks {
	frames := FingerEngine.FingerPrintEngine.Match(header, body)
	return frames
}

func WappalyzerDetect(header http.Header, body []byte) common.Frameworks {
	frames := FingerEngine.WappalyzerEngine.Fingerprint(header, body)
	return frames
}
