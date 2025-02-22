package pool

import (
	"context"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"sync"
	"sync/atomic"
)

type BasePool struct {
	*Config
	Statistor   *pkg.Statistor
	Bar         *pkg.Bar
	Worder      *words.Worder
	Cancel      context.CancelFunc
	client      *ihttp.Client
	ctx         context.Context
	processCh   chan *baseline.Baseline // 待处理的baseline
	dir         string
	reqCount    int
	failedCount int
	additionCh  chan *Unit
	closeCh     chan struct{}
	wg          *sync.WaitGroup
	isFallback  atomic.Bool
}

func (pool *BasePool) doRetry(bl *baseline.Baseline) {
	if bl.Retry >= pool.RetryLimit {
		return
	}
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.addAddition(&Unit{
			path:   bl.Path,
			parent: bl.Number,
			host:   bl.Host,
			source: parsers.RetrySource,
			from:   bl.Source,
			retry:  bl.Retry + 1,
		})
	}()
}

func (pool *BasePool) addAddition(u *Unit) {
	// 强行屏蔽报错, 防止goroutine泄露
	pool.wg.Add(1)
	defer func() {
		if err := recover(); err != nil {
		}
	}()
	pool.additionCh <- u
}

func (pool *BasePool) putToOutput(bl *baseline.Baseline) {
	if bl.IsValid || bl.IsFuzzy {
		bl.Collect()
	}
	pool.Outwg.Add(1)
	pool.OutputCh <- bl
}

func (pool *BasePool) putToFuzzy(bl *baseline.Baseline) {
	pool.Outwg.Add(1)
	bl.IsFuzzy = true
	pool.FuzzyCh <- bl
}
