package pool

import (
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr/vm"
	"sync"
	"time"
)

func newUnit(path string, source parsers.SpraySource) *Unit {
	return &Unit{path: path, source: source}
}

type Unit struct {
	number   int
	host     string
	path     string
	source   parsers.SpraySource
	retry    int
	frontUrl string
	depth    int // redirect depth
}

func NewBaselines() *Baselines {
	return &Baselines{
		baselines: map[int]*pkg.Baseline{},
	}
}

type Baselines struct {
	FailedBaselines []*pkg.Baseline
	random          *pkg.Baseline
	index           *pkg.Baseline
	baselines       map[int]*pkg.Baseline
}

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
	Timeout         time.Duration
	ProcessCh       chan *pkg.Baseline
	OutputCh        chan *pkg.Baseline
	FuzzyCh         chan *pkg.Baseline
	Outwg           *sync.WaitGroup
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
	Fns             []words.WordFunc
	AppendWords     []string
	Fuzzy           bool
	IgnoreWaf       bool
	Crawl           bool
	Scope           []string
	Active          bool
	Bak             bool
	Common          bool
	RetryLimit      int
	RandomUserAgent bool
	Random          string
	Index           string
}

func NewBruteWords(config *Config, list []string) *words.Worder {
	word := words.NewWorderWithList(list)
	word.Fns = config.Fns
	word.Run()
	return word
}

func NewBruteDSL(config *Config, dsl string, params [][]string) *words.Worder {
	word, err := words.NewWorderWithDsl(dsl, params, nil)
	if err != nil {
		logs.Log.Error(err.Error())
	}
	word.Fns = config.Fns
	word.Run()
	return word
}
