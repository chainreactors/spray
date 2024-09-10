package pkg

import "strings"

var (
	SkipChar = "%SKIP%"
	EXTChar  = "%EXT%"
)

func ParseEXTPlaceholderFunc(exts []string) func(string) []string {
	return func(s string) []string {
		ss := make([]string, len(exts))
		for i, e := range exts {
			if strings.Contains(s, EXTChar) {
				ss[i] = strings.Replace(s, EXTChar, e, -1)
			}
		}
		return ss
	}
}
