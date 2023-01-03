package pkg

import (
	"github.com/antonmedv/expr/vm"
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
	BaseURL        string
	Thread         int
	Wordlist       []string
	Timeout        int
	CheckPeriod    int
	ErrPeriod      int
	BreakThreshold int
	Method         string
	Mod            SprayMod
	Headers        http.Header
	ClientType     int
	MatchExpr      *vm.Program
	FilterExpr     *vm.Program
	RecuExpr       *vm.Program
	OutputCh       chan *Baseline
	FuzzyCh        chan *Baseline
	Fuzzy          bool
	IgnoreWaf      bool
	Crawl          bool
}
