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
	"net/http"
	"sync"
	"time"
)

var (
	CheckStatusCode func(int) bool
	CheckRedirect   func(string) bool
	CheckWaf        func([]byte) bool
)

var breakThreshold int = 20

func NewPool(ctx context.Context, config *pkg.Config) (*Pool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config:      config,
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		worder:      words.NewWorder(config.Wordlist),
		outputCh:    config.OutputCh,
		fuzzyCh:     config.FuzzyCh,
		baselines:   make(map[int]*pkg.Baseline),
		tempCh:      make(chan *pkg.Baseline, config.Thread),
		wg:          sync.WaitGroup{},
		initwg:      sync.WaitGroup{},
		checkPeriod: 100,
		errPeriod:   10,
		reqCount:    1,
		failedCount: 1,
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
				pool.recover()
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
				pool.recover()
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

		var bl *pkg.Baseline
		resp, reqerr := pool.client.Do(pctx, req)
		if pool.ClientType == ihttp.FAST {
			defer fasthttp.ReleaseResponse(resp.FastResponse)
			defer fasthttp.ReleaseRequest(req.FastRequest)
		}

		if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
			pool.failedCount++
			bl = &pkg.Baseline{Url: pool.BaseURL + unit.path, Err: reqerr.Error(), Reason: ErrRequestFailed.Error()}
			pool.failedBaselines = append(pool.failedBaselines, bl)
		} else {
			if err = pool.PreCompare(resp); unit.source == CheckSource || unit.source == InitSource || err == nil {
				// 通过预对比跳过一些无用数据, 减少性能消耗
				bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
				pool.addFuzzyBaseline(bl)
			} else {
				bl = pkg.NewInvalidBaseline(req.URI(), req.Host(), resp, err.Error())
			}
		}

		switch unit.source {
		case InitSource:
			pool.base = bl
			pool.addFuzzyBaseline(bl)
			pool.initwg.Done()
			return
		case CheckSource:
			if bl.Err != "" {
				logs.Log.Warnf("[check.error] maybe ip had banned by waf, break (%d/%d), error: %s", pool.failedCount, breakThreshold, bl.Err)
				pool.failedBaselines = append(pool.failedBaselines, bl)
			} else if i := pool.base.Compare(bl); i < 1 {
				if i == 0 {
					logs.Log.Debug("[check.fuzzy] maybe trigger risk control, " + bl.String())
				} else {
					logs.Log.Warn("[check.failed] maybe trigger risk control, " + bl.String())
				}

				pool.failedBaselines = append(pool.failedBaselines, bl)
			} else {
				pool.resetFailed() // 如果后续访问正常, 重置错误次数
				logs.Log.Debug("[check.pass] " + bl.String())
			}

		case WordSource:
			// 异步进行性能消耗较大的深度对比
			pool.tempCh <- bl

			if pool.reqCount%pool.checkPeriod == 0 {
				go pool.check()
			} else if pool.failedCount%pool.errPeriod == 0 {
				go pool.check()
			}
			pool.bar.Done()
		}

		pool.wg.Done()
	})

	pool.pool = p
	go pool.comparing()
	return pool, nil
}

type Pool struct {
	*pkg.Config
	client          *ihttp.Client
	pool            *ants.PoolWithFunc
	bar             *pkg.Bar
	ctx             context.Context
	cancel          context.CancelFunc
	outputCh        chan *pkg.Baseline // 输出的chan, 全局统一
	fuzzyCh         chan *pkg.Baseline
	tempCh          chan *pkg.Baseline // 待处理的baseline
	reqCount        int
	failedCount     int
	checkPeriod     int
	errPeriod       int
	failedBaselines []*pkg.Baseline
	base            *pkg.Baseline
	baselines       map[int]*pkg.Baseline
	analyzeDone     bool
	genReq          func(s string) (*ihttp.Request, error)
	check           func()
	worder          *words.Worder
	wg              sync.WaitGroup
	initwg          sync.WaitGroup // 初始化用, 之后改成锁
}

func (p *Pool) Init() error {
	p.initwg.Add(1)
	p.pool.Invoke(newUnit(pkg.RandPath(), InitSource))
	p.initwg.Wait()
	// todo 分析baseline
	// 检测基本访问能力

	if p.base.Err != "" {
		p.cancel()
		return fmt.Errorf(p.base.String())
	}

	p.base.Collect()
	logs.Log.Important("[baseline.init] " + p.base.String())
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

func (p *Pool) Run(ctx context.Context, offset, limit int) {
	maxreq := offset + limit
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

			if p.reqCount > maxreq {
				break Loop
			}

			for _, fn := range p.Fns {
				u = fn(u)
			}
			if u == "" {
				continue
			}
			p.reqCount++
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
	if p.base != nil && p.base.Status != 200 && p.base.Status == resp.StatusCode() {
		return ErrSameStatus
	}

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
		if !bl.IsValid {
			// precompare 确认无效数据直接送入管道
			p.outputCh <- bl
			continue
		}

		if p.base.Compare(bl) == 1 {
			// 如果是同一个包则设置为无效包
			bl.IsValid = false
			p.outputCh <- bl
			continue
		} else if base, ok := p.baselines[bl.Status]; ok && base.Compare(bl) == 1 {
			bl.IsValid = false
			bl.IsFuzzy = true
			p.outputCh <- bl
			p.fuzzyCh <- bl
			continue
		}

		bl.Collect()
		// todo fuzzy compare
		if p.base.FuzzyCompare(bl) {
			bl.IsValid = false
			bl.IsFuzzy = true
			p.outputCh <- bl
			p.fuzzyCh <- bl
			continue
		}

		p.outputCh <- bl
	}

	p.analyzeDone = true
}

func (p *Pool) addFuzzyBaseline(bl *pkg.Baseline) {
	if !IntsContains(FuzzyStatus, bl.Status) {
		return
	}

	if _, ok := p.baselines[bl.Status]; !ok {
		bl.Collect()
		p.baselines[bl.Status] = bl
		logs.Log.Importantf("[baseline.%dinit] %s", bl.Status, bl.String())
	}
}

func (p *Pool) resetFailed() {
	p.failedCount = 0
	p.failedBaselines = nil
}

func (p *Pool) recover() {
	logs.Log.Errorf("failed request exceeds the threshold , task will exit. Breakpoint %d", p.reqCount)
	logs.Log.Error("collecting failed check")
	for i, bl := range p.failedBaselines {
		logs.Log.Errorf("[failed.%d] %s", i, bl.String())
	}
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
