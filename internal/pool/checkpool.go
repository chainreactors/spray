package pool

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/panjf2000/ants/v2"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 类似httpx的无状态, 无scope, 无并发池的检测模式
func NewCheckPool(ctx context.Context, config *Config) (*CheckPool, error) {
	pctx, cancel := context.WithCancel(ctx)
	config.ClientType = ihttp.STANDARD
	pool := &CheckPool{
		&BasePool{
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
			additionCh: make(chan *Unit, 1024),
			closeCh:    make(chan struct{}),
			processCh:  make(chan *pkg.Baseline, config.Thread),
		},
	}
	pool.Headers = map[string]string{"Connection": "close"}
	p, _ := ants.NewPoolWithFunc(config.Thread, pool.Invoke)

	pool.BasePool.Pool = p
	go pool.Handler()
	return pool, nil
}

type CheckPool struct {
	*BasePool
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
			_ = pool.BasePool.Pool.Invoke(newUnit(u, parsers.CheckSource))
		case u, ok := <-pool.additionCh:
			if !ok {
				continue
			}
			_ = pool.BasePool.Pool.Invoke(u)
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
	defer func() {
		pool.reqCount++
		pool.wg.Done()
	}()

	unit := v.(*Unit)
	req, err := pool.genReq(unit.path)
	if err != nil {
		logs.Log.Debug(err.Error())
		bl := &pkg.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				IsValid:   false,
				ErrString: err.Error(),
				Reason:    pkg.ErrUrlError.Error(),
				ReqDepth:  unit.depth,
			},
		}
		pool.processCh <- bl
		return
	}
	req.SetHeaders(pool.Headers)
	start := time.Now()
	var bl *pkg.Baseline
	resp, reqerr := pool.client.Do(pool.ctx, req)
	if reqerr != nil {
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
		logs.Log.Debugf("%s, %s", unit.path, reqerr.Error())
		pool.doUpgrade(bl)
	} else {
		bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
		bl.Collect()
	}
	bl.ReqDepth = unit.depth
	bl.Source = unit.source
	bl.Spended = time.Since(start).Milliseconds()
	pool.processCh <- bl
}

func (pool *CheckPool) Handler() {
	for bl := range pool.processCh {
		if bl.IsValid {
			if bl.RedirectURL != "" {
				pool.doRedirect(bl, bl.ReqDepth)
				pool.putToOutput(bl)
			} else if bl.Status == 400 {
				pool.doUpgrade(bl)
				pool.putToOutput(bl)
			} else {
				params := map[string]interface{}{
					"current": bl,
				}
				if pool.MatchExpr != nil && pkg.CompareWithExpr(pool.MatchExpr, params) {
					bl.IsValid = true
				}
			}
		}
		if bl.Source == parsers.CheckSource {
			pool.Bar.Done()
		}
		pool.putToOutput(bl)
	}
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
