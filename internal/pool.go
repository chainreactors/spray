package internal

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"net/http"
	"sync"
	"time"
)

var (
	CheckStatusCode func(int) bool
	CheckRedirect   func(string) bool
	CheckWaf        func([]byte) bool
)

var breakThreshold int = 10

func NewPool(ctx context.Context, config *pkg.Config, outputCh chan *baseline) (*Pool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config:      config,
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		worder:      words.NewWorder(config.Wordlist),
		outputCh:    outputCh,
		tempCh:      make(chan *baseline, config.Thread),
		wg:          sync.WaitGroup{},
		initwg:      sync.WaitGroup{},
		checkPeriod: 100,
		errPeriod:   10,
	}

	switch config.Mod {
	case pkg.PathSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return pool.buildPathRequest(s)
		}
		pool.check = func() {
			pool.wg.Add(1)
			_ = pool.pool.Invoke(newUnit(pkg.RandPath(), CheckSource))

			if pool.failedCount > breakThreshold {
				// 当报错次数超过上限是, 结束任务
				pool.cancel()
			}
		}
	case pkg.HostSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return pool.buildHostRequest(s)
		}

		pool.check = func() {
			pool.wg.Add(1)
			_ = pool.pool.Invoke(newUnit(pkg.RandHost(), CheckSource))

			if pool.failedCount > breakThreshold {
				// 当报错次数超过上限是, 结束任务
				pool.cancel()
			}
		}
	}

	p, _ := ants.NewPoolWithFunc(config.Thread, func(i interface{}) {
		unit := i.(*Unit)
		req, err := pool.genReq(unit.path)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}

		var bl *baseline
		resp, reqerr := pool.client.Do(pctx, req)
		if pool.ClientType == ihttp.FAST {
			defer fasthttp.ReleaseResponse(resp.FastResponse)
			defer fasthttp.ReleaseRequest(req.FastRequest)
		}

		if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
			pool.failedCount++
			bl = &baseline{Url: pool.BaseURL + unit.path, Err: reqerr}
		} else {
			pool.failedCount = 0 // 如果后续访问正常, 重置错误次数
			if err = pool.PreCompare(resp); err == nil || unit.source == CheckSource || unit.source == InitSource {
				// 通过预对比跳过一些无用数据, 减少性能消耗
				bl = NewBaseline(req.URI(), req.Host(), resp)
			} else {
				bl = NewInvalidBaseline(req.URI(), req.Host(), resp)
			}
		}

		switch unit.source {
		case InitSource:
			pool.base = bl
			pool.initwg.Done()
			logs.Log.Important("[init] " + bl.String())
			return
		case CheckSource:
			logs.Log.Debugf("[check] " + bl.String())
			if bl.Err != nil {
				logs.Log.Warnf("maybe ip has banned by waf, break (%d/%d), error: %s", pool.failedCount, breakThreshold, bl.Err.Error())
			} else if pool.base.Compare(bl) < 1 {
				logs.Log.Warn("maybe trigger risk control")
			}

		case WordSource:
			// 异步进行性能消耗较大的深度对比
			pool.reqCount++
			pool.tempCh <- bl

			if pool.reqCount%pool.checkPeriod == 0 {
				go pool.check()
			} else if pool.failedCount%pool.errPeriod == 0 {
				go pool.check()
			}
		}

		pool.bar.Done()
		pool.wg.Done()
	})

	pool.pool = p
	go pool.comparing()
	return pool, nil
}

type Pool struct {
	*pkg.Config
	client *ihttp.Client
	pool   *ants.PoolWithFunc
	bar    *pkg.Bar
	ctx    context.Context
	cancel context.CancelFunc
	//baseReq      *http.Request
	base        *baseline
	outputCh    chan *baseline // 输出的chan, 全局统一
	tempCh      chan *baseline // 待处理的baseline
	reqCount    int
	failedCount int
	checkPeriod int
	errPeriod   int
	analyzeDone bool
	genReq      func(s string) (*ihttp.Request, error)
	check       func()
	worder      *words.Worder
	wg          sync.WaitGroup
	initwg      sync.WaitGroup // 初始化用, 之后改成锁
}

func (p *Pool) Init() error {
	p.initwg.Add(1)
	p.pool.Invoke(newUnit(pkg.RandPath(), InitSource))
	p.initwg.Wait()
	// todo 分析baseline
	// 检测基本访问能力

	if p.base.Err != nil {
		p.cancel()
		return p.base.Err
	}

	p.base.Collect()
	if p.base.RedirectURL != "" {
		CheckRedirect = func(redirectURL string) bool {
			if redirectURL == p.base.RedirectURL {
				// 相同的RedirectURL将被认为是无效数据
				return false
			} else {
				// path为3xx, 且与baseline中的RedirectURL不同时, 为有效数据
				return true
			}
		}
	}

	return nil
}

func (p *Pool) Run(ctx context.Context) {

Loop:
	for {
		select {
		case u, ok := <-p.worder.C:
			if !ok {
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

	p.Close()
}

func (p *Pool) PreCompare(resp *ihttp.Response) error {
	if !CheckStatusCode(resp.StatusCode()) {
		return ErrBadStatus
	}

	if CheckRedirect != nil && !CheckRedirect(string(resp.GetHeader("Location"))) {
		return ErrRedirect
	}

	if CheckWaf != nil && !CheckWaf(nil) {
		// todo check waf
		return ErrWaf
	}

	return nil
}

func (p *Pool) comparing() {
	for bl := range p.tempCh {
		if p.base.Compare(bl) == 1 {
			// 如果是同一个包则设置为无效包
			bl.IsValid = false
			p.outputCh <- bl
			continue
		}

		bl.Collect()
		if p.EnableFuzzy && p.base.FuzzyEqual(bl) {
			bl.IsValid = false
			p.outputCh <- bl
			continue
		}

		p.outputCh <- bl
	}

	p.analyzeDone = true
}

func (p *Pool) Close() {
	p.wg.Wait()
	p.bar.Close()

	close(p.tempCh)
	for !p.analyzeDone {
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
}

func (p *Pool) buildPathRequest(path string) (*ihttp.Request, error) {
	if p.Config.ClientType == ihttp.FAST {
		req := fasthttp.AcquireRequest()
		req.SetRequestURI(p.BaseURL + path)
		return &ihttp.Request{FastRequest: req, ClientType: p.ClientType}, nil
	} else {
		req, err := http.NewRequest("GET", p.BaseURL+path, nil)
		return &ihttp.Request{StandardRequest: req, ClientType: p.ClientType}, err
	}
}

func (p *Pool) buildHostRequest(host string) (*ihttp.Request, error) {
	if p.Config.ClientType == ihttp.FAST {
		req := fasthttp.AcquireRequest()
		req.SetRequestURI(p.BaseURL)
		req.SetHost(host)
		return &ihttp.Request{FastRequest: req, ClientType: p.ClientType}, nil
	} else {
		req, err := http.NewRequest("GET", p.BaseURL, nil)
		req.Host = host
		return &ihttp.Request{StandardRequest: req, ClientType: p.ClientType}, err
	}
}
