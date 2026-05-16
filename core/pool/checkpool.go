package pool

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/panjf2000/ants/v2"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 类似httpx的无状态, 无scope, 无并发池的检测模式
func NewCheckPool(ctx context.Context, config *Config) (*CheckPool, error) {
	pctx, cancel := context.WithCancel(ctx)
	config.ClientType = ihttp.STANDARD
	pool := &CheckPool{
		BasePool: &BasePool{
			Config:    config,
			Statistor: pkg.NewStatistor(""),
			ctx:       pctx,
			Cancel:    cancel,
			client: ihttp.NewClient(&ihttp.ClientConfig{
				Thread:      config.Thread,
				Type:        config.ClientType,
				Timeout:     config.Timeout,
				ProxyClient: config.ProxyClient,
			}),
			wg:          &sync.WaitGroup{},
			additionCh:  make(chan *Unit, config.Thread*10),
			closeCh:     make(chan struct{}),
			processCh:   make(chan *baseline.Baseline, config.Thread*2),
			handlerDone: make(chan struct{}),
		},
	}
	pool.Request.Headers.Set("Connection", "close")
	p, _ := ants.NewPoolWithFunc(config.Thread, pool.Invoke)

	pool.Pool = p
	go pool.Handler()
	return pool, nil
}

type CheckPool struct {
	*BasePool
	Pool *ants.PoolWithFunc
}

func (pool *CheckPool) Run(ctx context.Context, offset, limit int) {
	pool.Worder.Run()

	var done atomic.Bool
	// 挂起一个监控goroutine, 每100ms判断一次done, 如果已经done, 则关闭closeCh, 然后通过Loop中的select case closeCh去break, 实现退出
	go func() {
		for {
			if done.Load() {
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
		case u, ok := <-pool.Worder.Output:
			if !ok {
				done.Store(true)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if pool.reqCount.Load() < int64(offset) {
				pool.reqCount.Add(1)
				continue
			}

			if pool.reqCount.Load() > int64(limit) {
				continue
			}

			pool.wg.Add(1)
			if err := pool.Pool.Invoke(newUnit(u, parsers.CheckSource)); err != nil {
				pool.wg.Done()
			}
		case u, ok := <-pool.additionCh:
			if !ok {
				continue
			}
			if err := pool.Pool.Invoke(u); err != nil {
				pool.wg.Done()
			}
		case <-pool.closeCh:
			break Loop
		case <-ctx.Done():
			// 手动退出，不等待任务完成，直接退出
			done.Store(true)
			break Loop
		case <-pool.ctx.Done():
			// 手动退出，不等待任务完成，直接退出
			done.Store(true)
			break Loop
		}
	}

	pool.Close()
}
func (pool *CheckPool) Close() {
	pool.Cancel()
	pool.waitWorkers()
	close(pool.processCh)
	<-pool.handlerDone
	if pool.Bar != nil {
		pool.Bar.Close()
	}
	if pool.Pool != nil {
		pool.Pool.Release()
	}
}

func (pool *CheckPool) waitWorkers() {
	done := make(chan struct{})
	go func() {
		pool.wg.Wait()
		close(done)
	}()

	for {
		select {
		case <-done:
			return
		case _, ok := <-pool.additionCh:
			if !ok {
				return
			}
			pool.wg.Done()
		}
	}
}

func (pool *CheckPool) Invoke(v interface{}) {
	defer func() {
		pool.reqCount.Add(1)
		pool.wg.Done()
	}()

	unit := v.(*Unit)

	// 为Check请求创建RequestConfig，使用配置的参数
	checkReqConfig := &ihttp.RequestConfig{
		Method:          pool.Request.Method, // 使用配置的 Method
		Headers:         pool.Request.Headers,
		Host:            pool.Request.Host, // 使用配置的 Host
		Path:            pool.Request.Path, // 使用配置的 Path
		Body:            pool.Request.Body, // 使用配置的 Body
		RandomUserAgent: pool.Request.RandomUserAgent,
	}

	req, err := checkReqConfig.Build(pool.ctx, pool.ClientType, unit.path, "", "")
	if err != nil {
		logs.Log.Debug(err.Error())
		bl := &baseline.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				IsValid:   false,
				ErrString: err.Error(),
				Reason:    pkg.ErrUrlError.Error(),
				ReqDepth:  unit.depth,
			},
		}
		pool.sendProcess(bl)
		return
	}
	start := time.Now()
	var bl *baseline.Baseline
	resp, reqerr := pool.client.Do(req)
	if reqerr != nil {
		pool.failedCount.Add(1)
		bl = &baseline.Baseline{
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
		bl = baseline.NewBaseline(req.URI(), req.Host(), resp)
		bl.ReqDepth = unit.depth
		bl.Collect()
		if bl.Status == 400 {
			pool.doUpgrade(bl)
		}
	}
	bl.ReqDepth = unit.depth
	bl.Source = unit.source
	bl.Spended = time.Since(start).Milliseconds()
	if bl.RedirectURL != "" {
		pool.doRedirect(bl, bl.ReqDepth)
	}
	pool.sendProcess(bl)
}

func (pool *CheckPool) Handler() {
	defer close(pool.handlerDone)
	for bl := range pool.processCh {
		if bl.IsValid {
			params := map[string]interface{}{
				"current": bl,
			}
			if pool.MatchExpr != nil && pkg.CompareWithExpr(pool.MatchExpr, params) {
				bl.IsValid = true
			}
		}
		if bl.Source == parsers.CheckSource {
			pool.Bar.Done()
		}
		pool.recordCheckStat(bl)
		pool.putToOutput(bl)
	}
}

func (pool *CheckPool) recordCheckStat(bl *baseline.Baseline) {
	if pool.Statistor == nil || bl == nil || bl.SprayResult == nil {
		return
	}
	if pool.Statistor.Counts == nil {
		pool.Statistor.Counts = make(map[int]int)
	}
	if pool.Statistor.Sources == nil {
		pool.Statistor.Sources = make(map[parsers.SpraySource]int)
	}
	if bl.Status != 0 {
		pool.Statistor.Counts[bl.Status]++
	}
	if bl.Source.Name() != "" {
		pool.Statistor.Sources[bl.Source]++
	}
	if bl.IsValid {
		pool.Statistor.FoundNumber++
	}
	if bl.IsFuzzy {
		pool.Statistor.FuzzyNumber++
	}
}

func (pool *CheckPool) doRedirect(bl *baseline.Baseline, depth int) {
	if depth >= pool.MaxRedirect {
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

	pool.addAddition(&Unit{
		path:     reURL,
		parent:   bl.Number,
		source:   parsers.RedirectSource,
		frontUrl: bl.UrlString,
		depth:    depth + 1,
		from:     bl.Source,
	})
}

// tcp与400进行协议转换
func (pool *CheckPool) doUpgrade(bl *baseline.Baseline) {
	if bl.ReqDepth >= 1 {
		return
	}
	var reurl string
	if strings.HasPrefix(bl.UrlString, "https") {
		reurl = strings.Replace(bl.UrlString, "https", "http", 1)
	} else {
		reurl = strings.Replace(bl.UrlString, "http", "https", 1)
	}
	pool.addAddition(&Unit{
		path:   reurl,
		parent: bl.Number,
		source: parsers.UpgradeSource,
		depth:  bl.ReqDepth + 1,
		from:   bl.Source,
	})
}
