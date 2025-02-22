package pool

import (
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr/vm"
	"sync"
	"time"
)

type Config struct {
	BaseURL           string
	ProxyAddr         string
	Thread            int
	Wordlist          []string
	Timeout           time.Duration
	ProcessCh         chan *baseline.Baseline
	OutputCh          chan *baseline.Baseline
	FuzzyCh           chan *baseline.Baseline
	Outwg             *sync.WaitGroup
	RateLimit         int
	CheckPeriod       int
	ErrPeriod         int32
	BreakThreshold    int32
	Method            string
	Mod               SprayMod
	Headers           map[string]string
	ClientType        int
	MatchExpr         *vm.Program
	FilterExpr        *vm.Program
	RecuExpr          *vm.Program
	AppendRule        *rule.Program
	Fns               []words.WordFunc
	AppendWords       []string
	Fuzzy             bool
	IgnoreWaf         bool
	Crawl             bool
	Scope             []string
	Active            bool
	Bak               bool
	Common            bool
	RetryLimit        int
	RandomUserAgent   bool
	Random            string
	Index             string
	MaxRedirect       int
	MaxCrawlDepth     int
	MaxRecursionDepth int
	MaxAppendDepth    int
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
