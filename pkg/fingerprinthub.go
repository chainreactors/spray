package pkg

import (
	"github.com/chainreactors/parsers"
	"strings"
)

type FingerPrintHub struct {
	Name        string            `json:"name"`
	FaviconHash []string          `json:"favicon_hash,omitempty"`
	Keyword     []string          `json:"keyword,omitempty"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func FingerPrintHubDetect(header, body string) parsers.Frameworks {
	frames := make(parsers.Frameworks)
	for _, finger := range FingerPrintHubs {
		status := false
		if fingerPrintHubMatchHeader(finger, header) && fingerPrintHubMatchBody(finger, body) {
			status = true
		}

		if status {
			frames.Add(&parsers.Framework{
				Name: finger.Name,
				From: parsers.FrameFromDefault,
				Tags: []string{"fingerprinthub"},
			})
		}
	}
	return frames
}

func fingerPrintHubMatchHeader(finger *FingerPrintHub, header string) bool {
	if len(finger.Headers) == 0 {
		return true
	}
	status := true
	for k, v := range finger.Headers {
		if v == "*" && strings.Contains(header, k) {
			status = true
		} else if strings.Contains(header, k) && strings.Contains(header, v) {
			status = true
		} else {
			return false
		}
	}
	return status
}

func fingerPrintHubMatchBody(finger *FingerPrintHub, body string) bool {
	if len(finger.Keyword) == 0 {
		return true
	}
	if body == "" {
		return false
	}
	status := true
	for _, key := range finger.Keyword {
		if strings.Contains(body, key) {
			status = true
		} else {
			return false
		}
	}
	return status
}
