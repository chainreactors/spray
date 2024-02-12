package pool

import (
	"github.com/antonmedv/expr/vm"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/rule"
	"sync"
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
	BaseURL         string
	ProxyAddr       string
	Thread          int
	Wordlist        []string
	Timeout         int
	OutputCh        chan *pkg.Baseline
	FuzzyCh         chan *pkg.Baseline
	OutLocker       *sync.WaitGroup
	RateLimit       int
	CheckPeriod     int
	ErrPeriod       int32
	BreakThreshold  int32
	Method          string
	Mod             SprayMod
	Headers         map[string]string
	ClientType      int
	MatchExpr       *vm.Program
	FilterExpr      *vm.Program
	RecuExpr        *vm.Program
	AppendRule      *rule.Program
	AppendWords     []string
	Fuzzy           bool
	IgnoreWaf       bool
	Crawl           bool
	Scope           []string
	Active          bool
	Bak             bool
	Common          bool
	Retry           int
	RandomUserAgent bool
	Random          string
	Index           string
}
