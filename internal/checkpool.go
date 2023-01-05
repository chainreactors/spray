package internal

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"sync"
	"time"
)

func NewCheckPool(ctx context.Context, config *pkg.Config) (*CheckPool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &CheckPool{
		Config:      config,
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		wg:          sync.WaitGroup{},
		reqCount:    1,
		failedCount: 1,
	}

	p, _ := ants.NewPoolWithFunc(config.Thread, func(i interface{}) {
		unit := i.(*Unit)
		req, err := pool.genReq(unit.path)
		if err != nil {
			logs.Log.Error(err.Error())
		}

		start := time.Now()
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

		bl.Spended = time.Since(start).Milliseconds()
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
	worder      *words.Worder
	wg          sync.WaitGroup
}

func (p *CheckPool) Close() {
	p.bar.Close()
}

func (p *CheckPool) genReq(s string) (*ihttp.Request, error) {
	if p.Mod == pkg.HostSpray {
		return ihttp.BuildHostRequest(p.ClientType, p.BaseURL, s)
	} else if p.Mod == pkg.PathSpray {
		return ihttp.BuildPathRequest(p.ClientType, p.BaseURL, s)
	}
	return nil, fmt.Errorf("unknown mod")
}

func (p *CheckPool) Run(ctx context.Context, offset, limit int) {
	p.worder.Run()
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
