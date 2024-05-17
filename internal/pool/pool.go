package pool

import (
	"context"
	"fmt"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"github.com/panjf2000/ants/v2"
	"path"
	"sync"
)

type BasePool struct {
	*Config
	Statistor   *pkg.Statistor
	Pool        *ants.PoolWithFunc
	Bar         *pkg.Bar
	Worder      *words.Worder
	client      *ihttp.Client
	ctx         context.Context
	Cancel      context.CancelFunc
	dir         string
	reqCount    int
	failedCount int
	additionCh  chan *Unit
	closeCh     chan struct{}
	wg          sync.WaitGroup
}

func (pool *BasePool) doRedirect(bl *pkg.Baseline, depth int) {
	if depth >= MaxRedirect {
		return
	}
	reURL := pkg.FormatURL(bl.Url.Path, bl.RedirectURL)
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.addAddition(&Unit{
			path:     reURL,
			source:   parsers.RedirectSource,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		})
	}()
}

func (pool *BasePool) doRule(bl *pkg.Baseline) {
	if pool.AppendRule == nil {
		pool.wg.Done()
		return
	}
	if bl.Source == parsers.RuleSource {
		pool.wg.Done()
		return
	}

	go func() {
		defer pool.wg.Done()
		for u := range rule.RunAsStream(pool.AppendRule.Expressions, path.Base(bl.Path)) {
			pool.addAddition(&Unit{
				path:   pkg.Dir(bl.Url.Path) + u,
				source: parsers.RuleSource,
			})
		}
	}()
}

func (pool *BasePool) doAppendWords(bl *pkg.Baseline) {
	if pool.AppendWords == nil {
		pool.wg.Done()
		return
	}
	if bl.Source == parsers.AppendSource {
		pool.wg.Done()
		return
	}

	go func() {
		defer pool.wg.Done()
		for _, u := range pool.AppendWords {
			pool.addAddition(&Unit{
				path:   pkg.SafePath(bl.Path, u),
				source: parsers.AppendSource,
			})
		}
	}()
}

func (pool *BasePool) doRetry(bl *pkg.Baseline) {
	if bl.Retry >= pool.Retry {
		return
	}
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.addAddition(&Unit{
			path:   bl.Path,
			source: parsers.RetrySource,
			retry:  bl.Retry + 1,
		})
	}()
}

func (pool *BasePool) doActive() {
	defer pool.wg.Done()
	for _, u := range pkg.ActivePath {
		pool.addAddition(&Unit{
			path:   pool.dir + u[1:],
			source: parsers.FingerSource,
		})
	}
}

func (pool *BasePool) doCommonFile() {
	defer pool.wg.Done()
	for _, u := range mask.SpecialWords["common_file"] {
		pool.addAddition(&Unit{
			path:   pool.dir + u,
			source: parsers.CommonFileSource,
		})
	}
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

func (pool *BasePool) Close() {
	pool.Bar.Close()
}

func (pool *BasePool) genReq(s string) (*ihttp.Request, error) {
	if pool.Mod == HostSpray {
		return ihttp.BuildHostRequest(pool.ClientType, pool.BaseURL, s)
	} else if pool.Mod == PathSpray {
		return ihttp.BuildPathRequest(pool.ClientType, pool.BaseURL, s, pool.Method)
	}
	return nil, fmt.Errorf("unknown mod")
}

func (pool *BasePool) putToOutput(bl *pkg.Baseline) {
	pool.OutLocker.Add(1)
	pool.OutputCh <- bl
}

func (pool *BasePool) putToFuzzy(bl *pkg.Baseline) {
	pool.OutLocker.Add(1)
	bl.IsFuzzy = true
	pool.FuzzyCh <- bl
}
