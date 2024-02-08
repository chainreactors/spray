package internal

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	ihttp2 "github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
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
		Config: config,
		ctx:    pctx,
		cancel: cancel,
		client: ihttp2.NewClient(&ihttp2.ClientConfig{
			Thread:    config.Thread,
			Type:      config.ClientType,
			Timeout:   time.Duration(config.Timeout) * time.Second,
			ProxyAddr: config.ProxyAddr,
		}),
		wg:          sync.WaitGroup{},
		additionCh:  make(chan *Unit, 100),
		closeCh:     make(chan struct{}),
		reqCount:    1,
		failedCount: 1,
	}
	pool.Headers = map[string]string{"Connection": "close"}
	p, _ := ants.NewPoolWithFunc(config.Thread, pool.Invoke)

	pool.pool = p
	return pool, nil
}

type CheckPool struct {
	*Config
	client      *ihttp2.Client
	pool        *ants.PoolWithFunc
	bar         *pkg.Bar
	ctx         context.Context
	cancel      context.CancelFunc
	reqCount    int
	failedCount int
	additionCh  chan *Unit
	closeCh     chan struct{}
	worder      *words.Worder
	wg          sync.WaitGroup
}

func (pool *CheckPool) Close() {
	pool.bar.Close()
}

func (pool *CheckPool) genReq(s string) (*ihttp2.Request, error) {
	if pool.Mod == HostSpray {
		return ihttp2.BuildHostRequest(pool.ClientType, pool.BaseURL, s)
	} else if pool.Mod == PathSpray {
		return ihttp2.BuildPathRequest(pool.ClientType, pool.BaseURL, s)
	}
	return nil, fmt.Errorf("unknown mod")
}

func (pool *CheckPool) Run(ctx context.Context, offset, limit int) {
	pool.worder.Run()

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
		case u, ok := <-pool.worder.C:
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
			_ = pool.pool.Invoke(newUnit(u, CheckSource))
		case u, ok := <-pool.additionCh:
			if !ok {
				continue
			}
			_ = pool.pool.Invoke(u)
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
	var bl *Baseline
	resp, reqerr := pool.client.Do(pool.ctx, req)
	if pool.ClientType == ihttp2.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}

	if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
		pool.failedCount++
		bl = &Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				IsValid:   false,
				ErrString: reqerr.Error(),
				Reason:    ErrRequestFailed.Error(),
				ReqDepth:  unit.depth,
			},
		}

		if strings.Contains(reqerr.Error(), "timed out") || strings.Contains(reqerr.Error(), "actively refused") {

		} else {
			pool.doUpgrade(bl)
		}

	} else {
		bl = NewBaseline(req.URI(), req.Host(), resp)
		bl.Collect()
	}
	bl.ReqDepth = unit.depth
	bl.Source = unit.source
	bl.Spended = time.Since(start).Milliseconds()

	// 手动处理重定向
	if bl.IsValid {
		if bl.RedirectURL != "" {
			pool.doRedirect(bl, unit.depth)
			pool.FuzzyCh <- bl
		} else if bl.Status == 400 {
			pool.doUpgrade(bl)
			pool.FuzzyCh <- bl
		} else {
			params := map[string]interface{}{
				"current": bl,
			}
			if pool.MatchExpr == nil || CompareWithExpr(pool.MatchExpr, params) {
				pool.OutputCh <- bl
			}
		}
	}

	pool.reqCount++
	pool.wg.Done()
	pool.bar.Done()
}

func (pool *CheckPool) doRedirect(bl *Baseline, depth int) {
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
		reURL = BaseURL(bl.Url) + FormatURL(BaseURL(bl.Url), bl.RedirectURL)
	}

	pool.wg.Add(1)
	go func() {
		pool.additionCh <- &Unit{
			path:     reURL,
			source:   RedirectSource,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		}
	}()
}

// tcp与400进行协议转换
func (pool *CheckPool) doUpgrade(bl *Baseline) {
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
			source: UpgradeSource,
			depth:  bl.ReqDepth + 1,
		}
	}()
}
