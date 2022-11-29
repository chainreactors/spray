package internal

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"sync"
)

func NewCheckPool(ctx context.Context, config *pkg.Config) (*CheckPool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &CheckPool{
		Config:      config,
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		worder:      words.NewWorder(config.Wordlist, config.Fns),
		wg:          sync.WaitGroup{},
		reqCount:    1,
		failedCount: 1,
	}

	switch config.Mod {
	case pkg.PathSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return ihttp.BuildPathRequest(pool.ClientType, s, "")
		}
	case pkg.HostSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return ihttp.BuildHostRequest(pool.ClientType, s, "")
		}
	}

	p, _ := ants.NewPoolWithFunc(config.Thread, func(i interface{}) {
		unit := i.(*Unit)
		req, err := pool.genReq(unit.path)
		if err != nil {
			logs.Log.Error(err.Error())
		}

		var bl *pkg.Baseline
		resp, reqerr := pool.client.Do(pctx, req)
		if pool.ClientType == ihttp.FAST {
			defer fasthttp.ReleaseResponse(resp.FastResponse)
			defer fasthttp.ReleaseRequest(req.FastRequest)
		}

		if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
			pool.failedCount++
			bl = &pkg.Baseline{UrlString: pool.BaseURL + unit.path, IsValid: false, ErrString: reqerr.Error(), Reason: ErrRequestFailed.Error()}
		} else {
			bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
			bl.Collect()
		}

		pool.OutputCh <- bl
		pool.reqCount++
		pool.wg.Done()
		pool.bar.Done()
	})

	pool.pool = p
	return pool, nil
}

type CheckPool struct {
	*pkg.Config
	client      *ihttp.Client
	pool        *ants.PoolWithFunc
	bar         *pkg.Bar
	ctx         context.Context
	cancel      context.CancelFunc
	reqCount    int
	failedCount int
	genReq      func(s string) (*ihttp.Request, error)
	worder      *words.Worder
	wg          sync.WaitGroup
}

func (p *CheckPool) Close() {
	p.bar.Close()
}

func (p *CheckPool) Run(ctx context.Context, offset, limit int) {
Loop:
	for {
		select {
		case u, ok := <-p.worder.C:
			if !ok {
				break Loop
			}

			if p.reqCount < offset {
				p.reqCount++
				continue
			}

			if p.reqCount > limit {
				break Loop
			}

			p.wg.Add(1)
			_ = p.pool.Invoke(newUnit(u, WordSource))
		case <-ctx.Done():
			break Loop
		case <-p.ctx.Done():
			break Loop
		}
	}
	p.wg.Wait()
	p.Close()
}
