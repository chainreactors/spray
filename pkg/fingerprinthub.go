package pkg

import (
	"github.com/chainreactors/parsers"
	"strings"
)

type FingerPrintHub struct {
	Name        string            `json:"name"`
	FaviconHash []string          `json:"favicon_hash"`
	Keyword     []string          `json:"keyword"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
}

func FingerPrintHubDetect(header, body string) parsers.Frameworks {
	frames := make(parsers.Frameworks)
	for _, finger := range FingerPrintHubs {
		status := false
		for _, key := range finger.Keyword {
			if strings.Contains(body, key) {
				status = true
			} else {
				status = false
			}
		}
		for k, v := range finger.Headers {
			if v == "*" && strings.Contains(header, k) {
				status = true
			} else if strings.Contains(header, k) && strings.Contains(header, v) {
				status = true
			} else {
				status = false
			}
		}
		if status {
			frame := &parsers.Framework{
				Name: finger.Name,
				From: parsers.FrameFromDefault,
				Tags: []string{"fingerprinthub"},
			}
			frames[frame.Name] = frame
		}
	}
	return frames
}
