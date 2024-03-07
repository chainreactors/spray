package pool

import (
	"context"
	"errors"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 类似httpx的无状态, 无scope, 无并发池的检测模式
func NewCheckPool(ctx context.Context, config *Config) (*CheckPool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &CheckPool{
		&This{
			Config:    config,
			Statistor: pkg.NewStatistor(""),
			ctx:       pctx,
			Cancel:    cancel,
			client: ihttp.NewClient(&ihttp.ClientConfig{
				Thread:    config.Thread,
				Type:      config.ClientType,
				Timeout:   time.Duration(config.Timeout) * time.Second,
				ProxyAddr: config.ProxyAddr,
			}),
			wg:         sync.WaitGroup{},
			additionCh: make(chan *Unit, 100),
			closeCh:    make(chan struct{}),
		},
	}
	pool.Headers = map[string]string{"Connection": "close"}
	p, _ := ants.NewPoolWithFunc(config.Thread, pool.Invoke)

	pool.This.Pool = p
	return pool, nil
}

type CheckPool struct {
	*This
}

func (pool *CheckPool) Run(ctx context.Context, offset, limit int) {
	pool.Worder.Run()

	var done bool
	// 挂起一个监控goroutine, 每100ms判断一次done, 如果已经done, 则关闭closeCh, 然后通过Loop中的select case closeCh去break, 实现退出
	go func() {
		for {
			if done {
				pool.wg.Wait()
				close(pool.closeCh)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

Loop:
	for {
		select {
		case u, ok := <-pool.Worder.C:
			if !ok {
				done = true
				continue
			}

			if pool.reqCount < offset {
				pool.reqCount++
				continue
			}

			if pool.reqCount > limit {
				continue
			}

			pool.wg.Add(1)
			_ = pool.This.Pool.Invoke(newUnit(u, parsers.CheckSource))
		case u, ok := <-pool.additionCh:
			if !ok {
				continue
			}
			_ = pool.This.Pool.Invoke(u)
		case <-pool.closeCh:
			break Loop
		case <-ctx.Done():
			break Loop
		case <-pool.ctx.Done():
			break Loop
		}
	}

	pool.Close()
}

func (pool *CheckPool) Invoke(v interface{}) {
	unit := v.(*Unit)
	req, err := pool.genReq(unit.path)
	if err != nil {
		logs.Log.Error(err.Error())
	}
	req.SetHeaders(pool.Headers)
	start := time.Now()
	var bl *pkg.Baseline
	resp, reqerr := pool.client.Do(pool.ctx, req)
	if pool.ClientType == ihttp.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}

	if reqerr != nil && !errors.Is(reqerr, fasthttp.ErrBodyTooLarge) {
		pool.failedCount++
		bl = &pkg.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				IsValid:   false,
				ErrString: reqerr.Error(),
				Reason:    pkg.ErrRequestFailed.Error(),
				ReqDepth:  unit.depth,
			},
		}

		if strings.Contains(reqerr.Error(), "timed out") || strings.Contains(reqerr.Error(), "actively refused") {

		} else {
			pool.doUpgrade(bl)
		}

	} else {
		bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
		bl.Collect()
	}
	bl.ReqDepth = unit.depth
	bl.Source = unit.source
	bl.Spended = time.Since(start).Milliseconds()

	// 手动处理重定向
	if bl.IsValid {
		if bl.RedirectURL != "" {
			pool.doRedirect(bl, unit.depth)
			pool.putToFuzzy(bl)
		} else if bl.Status == 400 {
			pool.doUpgrade(bl)
			pool.putToFuzzy(bl)
		} else {
			params := map[string]interface{}{
				"current": bl,
			}
			if pool.MatchExpr == nil || pkg.CompareWithExpr(pool.MatchExpr, params) {
				pool.putToOutput(bl)
			}
		}
	}

	if bl.Source == parsers.CheckSource {
		pool.Bar.Done()
	}
	pool.reqCount++
	pool.wg.Done()
}

func (pool *CheckPool) doRedirect(bl *pkg.Baseline, depth int) {
	if depth >= MaxRedirect {
		return
	}
	var reURL string
	if strings.HasPrefix(bl.RedirectURL, "http") {
		_, err := url.Parse(bl.RedirectURL)
		if err != nil {
			return
		}
		reURL = bl.RedirectURL
	} else {
		reURL = pkg.BaseURL(bl.Url) + pkg.FormatURL(pkg.BaseURL(bl.Url), bl.RedirectURL)
	}

	pool.wg.Add(1)
	go func() {
		pool.additionCh <- &Unit{
			path:     reURL,
			source:   parsers.RedirectSource,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		}
	}()
}

// tcp与400进行协议转换
func (pool *CheckPool) doUpgrade(bl *pkg.Baseline) {
	if bl.ReqDepth >= 1 {
		return
	}
	pool.wg.Add(1)
	var reurl string
	if strings.HasPrefix(bl.UrlString, "https") {
		reurl = strings.Replace(bl.UrlString, "https", "http", 1)
	} else {
		reurl = strings.Replace(bl.UrlString, "http", "https", 1)
	}
	go func() {
		pool.additionCh <- &Unit{
			path:   reurl,
			source: parsers.UpgradeSource,
			depth:  bl.ReqDepth + 1,
		}
	}()
}
