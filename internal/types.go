package internal

type ErrorType uint

const (
	ErrBadStatus ErrorType = iota
	ErrWaf
	ErrRedirect
)

func (e ErrorType) Error() string {
	switch e {
	case ErrBadStatus:
		return "bad status"
	case ErrWaf:
		return "maybe ban of waf"
	case ErrRedirect:
		return "duplicate redirect url"
	default:
		return "unknown error"
	}
}
