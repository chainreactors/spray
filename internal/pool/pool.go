package pool

import (
	"context"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
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
	processCh   chan *pkg.Baseline // 待处理的baseline
	dir         string
	reqCount    int
	failedCount int
	additionCh  chan *Unit
	closeCh     chan struct{}
	wg          *sync.WaitGroup
	isFallback  atomic.Bool
}

func (pool *BasePool) doRedirect(bl *pkg.Baseline, depth int) {
	if depth >= pool.MaxRedirect {
		return
	}
	reURL := pkg.FormatURL(bl.Url.Path, bl.RedirectURL)
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.addAddition(&Unit{
			path:     reURL,
			host:     bl.Host,
			source:   parsers.RedirectSource,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		})
	}()
}

func (pool *BasePool) doRetry(bl *pkg.Baseline) {
	if bl.Retry >= pool.RetryLimit {
		return
	}
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.addAddition(&Unit{
			path:   bl.Path,
			host:   bl.Host,
			source: parsers.RetrySource,
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

func (pool *BasePool) putToOutput(bl *pkg.Baseline) {
	if bl.IsValid || bl.IsFuzzy {
		bl.Collect()
	}
	pool.Outwg.Add(1)
	pool.OutputCh <- bl
}

func (pool *BasePool) putToFuzzy(bl *pkg.Baseline) {
	pool.Outwg.Add(1)
	bl.IsFuzzy = true
	pool.FuzzyCh <- bl
}
