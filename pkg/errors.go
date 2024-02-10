package pkg

type ErrorType uint

const (
	NoErr ErrorType = iota
	ErrBadStatus
	ErrSameStatus
	ErrRequestFailed
	ErrWaf
	ErrRedirect
	ErrCompareFailed
	ErrCustomCompareFailed
	ErrCustomFilter
	ErrFuzzyCompareFailed
	ErrFuzzyRedirect
	ErrFuzzyNotUnique
	ErrUrlError
)

var ErrMap = map[ErrorType]string{
	NoErr:                  "",
	ErrBadStatus:           "blacklist status",
	ErrSameStatus:          "same status with random baseline",
	ErrRequestFailed:       "request failed",
	ErrWaf:                 "maybe banned by waf",
	ErrRedirect:            "duplicate redirect url",
	ErrCompareFailed:       "compare failed",
	ErrCustomCompareFailed: "custom compare failed",
	ErrCustomFilter:        "custom filtered",
	ErrFuzzyCompareFailed:  "fuzzy compare failed",
	ErrFuzzyRedirect:       "fuzzy redirect",
	ErrFuzzyNotUnique:      "not unique",
	ErrUrlError:            "url parse error",
}

func (e ErrorType) Error() string {
	return ErrMap[e]
}
