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

var ModMap = map[string]SprayMod{
	"path": PathSpray,
	"host": HostSpray,
}

type Config struct {
	BaseURL      string
	Wordlist     []string
	Thread       int
	Timeout      int
	BaseReq      *http.Request
	Method       string
	Mod          SprayMod
	Headers      http.Header
	DeadlineTime int
}

func (c *Config) Init() (err error) {
	c.BaseReq, err = http.NewRequest(c.Method, c.BaseURL, nil)
	if err != nil {
		return err
	}
	c.BaseReq.Header = c.Headers
	return nil
}
