package internal

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
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
	CheckWaf        func(*http.Response) bool
)

var breakThreshold int = 10

func NewPool(ctx context.Context, config *pkg.Config, outputCh chan *baseline) (*Pool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config:      config,
		ctx:         pctx,
		cancel:      cancel,
		client:      pkg.NewClient(config.Thread, 2),
		worder:      words.NewWorder(config.Wordlist),
		outputCh:    outputCh,
		tempCh:      make(chan *baseline, config.Thread),
		wg:          &sync.WaitGroup{},
		checkPeriod: 100,
		errPeriod:   10,
	}

	switch config.Mod {
	case pkg.PathSpray:
		pool.genReq = func(s string) (*fasthttp.Request, error) {
			return pool.BuildPathRequest(s)
		}
	case pkg.HostSpray:
		pool.genReq = func(s string) (*fasthttp.Request, error) {
			return pool.BuildHostRequest(s)
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
		resp, err := pool.client.Do(pctx, req)
		if err != nil {
			//logs.Log.Debugf("%s request error, %s", strurl, err.Error())
			pool.errorCount++
			bl = &baseline{Err: err}

		} else {
			defer fasthttp.ReleaseResponse(resp)
			defer fasthttp.ReleaseRequest(req)
			//defer resp.Body.Close() // 必须要关闭body ,否则keep-alive无法生效
			if err = pool.PreCompare(resp); err == nil || unit.source == CheckSource {
				// 通过预对比跳过一些无用数据, 减少性能消耗
				bl = NewBaseline(req.URI(), resp)
			} else {
				bl = NewInvalidBaseline(req.URI(), resp)
			}
		}

		switch unit.source {
		case CheckSource:
			if pool.baseline == nil {
				//初次check覆盖baseline
				pool.baseline = bl
			} else if bl.Err != nil {
				logs.Log.Warn("maybe ip banned by waf")
			} else if !pool.baseline.Equal(bl) {
				logs.Log.Warn("maybe trigger risk control")
			}

		case WordSource:
			// 异步进行性能消耗较大的深度对比
			pool.tempCh <- bl
		}
		//todo connectivity check
		pool.bar.Done()
		pool.wg.Done()
	})

	pool.pool = p
	go pool.Comparing()
	return pool, nil
}

type Pool struct {
	//url    string
	//thread int
	*pkg.Config
	client *pkg.Client
	pool   *ants.PoolWithFunc
	bar    *pkg.Bar
	ctx    context.Context
	cancel context.CancelFunc
	//baseReq      *http.Request
	baseline    *baseline
	outputCh    chan *baseline
	tempCh      chan *baseline
	reqCount    int
	errorCount  int
	failedCount int
	checkPeriod int
	errPeriod   int
	genReq      func(s string) (*fasthttp.Request, error)
	//wordlist     []string
	worder *words.Worder
	wg     *sync.WaitGroup
}

func (p *Pool) check() {
	var wg sync.WaitGroup
	wg.Add(1)
	_ = p.pool.Invoke(newUnit(pkg.RandPath(), CheckSource))
	//}
	wg.Wait()

	if p.failedCount > breakThreshold {
		p.cancel()
	}
}

func (p *Pool) Init() error {
	p.check()
	// todo 分析baseline
	// 检测基本访问能力

	if p.baseline != nil && p.baseline.Err != nil {
		p.cancel()
		return p.baseline.Err
	}

	p.baseline.Collect()

	if p.baseline.RedirectURL != "" {
		CheckRedirect = func(redirectURL string) bool {
			if redirectURL == p.baseline.RedirectURL {
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
			p.reqCount++
			p.wg.Add(1)
			if p.reqCount%p.checkPeriod == 0 {
				go p.check()
			} else if p.reqCount%p.errPeriod == 0 {
				go p.check()
			}
			_ = p.pool.Invoke(newUnit(u, WordSource))
		case <-time.NewTimer(time.Duration(p.DeadlineTime) * time.Second).C:
			break Loop
		case <-ctx.Done():
			break Loop
		case <-p.ctx.Done():
			break Loop
		}
	}
	p.bar.Close()
	p.wg.Wait()
}

func (p *Pool) PreCompare(resp *fasthttp.Response) error {
	if !CheckStatusCode(resp.StatusCode()) {
		return ErrBadStatus
	}

	if CheckRedirect != nil && !CheckRedirect(string(resp.Header.Peek("Location"))) {
		return ErrRedirect
	}

	//if CheckWaf != nil && !CheckWaf(resp) {
	//	return ErrWaf
	//}

	return nil
}

func (p *Pool) RunWithWord(words []string) {

}

func (p *Pool) Comparing() {
	for bl := range p.tempCh {
		if p.baseline.Equal(bl) {
			// 如果是同一个包则设置为无效包
			bl.IsValid = false
			p.outputCh <- bl
			continue
		}

		bl.Collect()
		if p.EnableFuzzy && p.baseline.FuzzyEqual(bl) {
			bl.IsValid = false
			p.outputCh <- bl
			continue
		}

		p.outputCh <- bl
	}
}

func (p *Pool) BuildPathRequest(path string) (*fasthttp.Request, error) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(p.BaseURL + path)
	return req, nil
}

func (p *Pool) BuildHostRequest(host string) (*fasthttp.Request, error) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(p.BaseURL)
	req.SetHost(host)
	return req, nil
}

type sourceType int

const (
	CheckSource sourceType = iota + 1
	WordSource
	WafSource
)

//var sourceMap = map[int]string{
//
//}

func newUnit(path string, source sourceType) *Unit {
	return &Unit{path: path, source: source}
}

type Unit struct {
	path   string
	source sourceType
	//callback func()
}
