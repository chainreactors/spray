package pkg

import "strings"

var (
	SkipChar = "%SKIP%"
	EXTChar  = "%EXT%"
)

func ParseEXTPlaceholderFunc(exts []string) func(string) []string {
	return func(s string) []string {
		ss := make([]string, len(exts))
		var n int
		for i, e := range exts {
			if strings.Contains(s, EXTChar) {
				n++
				ss[i] = strings.Replace(s, EXTChar, e, -1)
			}
		}
		if n == 0 {
			return []string{s}
		} else {
			return ss
		}
	}
}
