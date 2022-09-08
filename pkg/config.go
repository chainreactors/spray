package pkg

import (
	"net/http"
)

type SprayMod int

const (
	PathSpray SprayMod = iota + 1
	HostSpray
	ParamSpray
	CustomSpray
)

type Config struct {
	BaseURL  string
	Wordlist []string
	Thread   int
	Timeout  int
	BaseReq  *http.Request
	Method   string
	Mod      SprayMod
	Headers  http.Header
}

func (c *Config) Init() (err error) {
	c.BaseReq, err = http.NewRequest(c.Method, c.BaseURL, nil)
	if err != nil {
		return err
	}
	c.BaseReq.Header = c.Headers
	return nil
}
