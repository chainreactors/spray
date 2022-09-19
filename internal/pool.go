package internal

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"net/http"
	"sync"
	"time"
)

var (
	CheckStatusCode func(int) bool
	CheckRedirect   func(*http.Response) bool
	CheckWaf        func(*http.Response) bool
)

func NewPool(ctx context.Context, config *pkg.Config, outputCh chan *baseline) (*Pool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config: config,
		ctx:    pctx,
		client: pkg.NewClient(config.Thread, 2),
		worder: words.NewWorder(config.Wordlist),
		//baseReq:  req,
		outputCh: outputCh,
		wg:       &sync.WaitGroup{},
	}

	switch config.Mod {
	case pkg.PathSpray:
		pool.genReq = func(s string) (*http.Request, error) {
			return pool.BuildPathRequest(s)
		}
	case pkg.HostSpray:
		pool.genReq = func(s string) (*http.Request, error) {
			return pool.BuildHostRequest(s)
		}
	}

	p, _ := ants.NewPoolWithFunc(config.Thread, func(i interface{}) {
		var bl *baseline
		unit := i.(*Unit)
		req, err := pool.genReq(unit.path)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}

		resp, err := pool.client.Do(pctx, req)
		if err != nil {
			//logs.Log.Debugf("%s request error, %s", strurl, err.Error())
			pool.errorCount++
			bl = &baseline{Err: err}
		} else {
			defer resp.Body.Close() // 必须要关闭body ,否则keep-alive无法生效
			if err = pool.PreCompare(resp); err == nil {
				// 通过预对比跳过一些无用数据, 减少性能消耗
				bl = NewBaseline(req.URL, resp)
			} else if err == ErrWaf {
				cancel()
			} else {
				bl = NewInvalidBaseline(req.URL, resp)
			}
		}

		switch unit.source {
		case InitSource:
			pool.baseline = bl
		case WordSource:
			// todo compare
			//pool.outputCh <- bl
			// todo 重构output
			if bl.IsValid {
				pool.bar.Print(bl.String())
			}
		}
		//todo connectivity check
		pool.bar.Done()
		pool.wg.Done()
	})

	pool.pool = p

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
	//baseReq      *http.Request
	baseline   *baseline
	outputCh   chan *baseline
	totalCount int
	errorCount int
	genReq     func(s string) (*http.Request, error)
	//wordlist     []string
	worder *words.Worder
	wg     *sync.WaitGroup
}

func (p *Pool) Init() error {
	//for i := 0; i < p.baseReqCount; i++ {
	p.wg.Add(1)
	_ = p.pool.Invoke(newUnit(pkg.RandPath(), InitSource))
	//}
	p.wg.Wait()
	// todo 分析baseline
	// 检测基本访问能力

	if p.baseline != nil && p.baseline.Err != nil {
		return p.baseline.Err
	}

	if p.baseline.RedirectURL != "" {
		CheckRedirect = func(resp *http.Response) bool {
			redirectURL, err := resp.Location()
			if err != nil {
				// baseline 为3xx, 但path不为3xx时, 为有效数据
				return true
			} else if redirectURL.String() != p.baseline.RedirectURL {
				// path为3xx, 且与baseline中的RedirectURL不同时, 为有效数据
				return true
			} else {
				// 相同的RedirectURL将被认为是无效数据
				return false
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
			p.totalCount++
			p.wg.Add(1)
			_ = p.pool.Invoke(newUnit(u, WordSource))
		case <-time.NewTimer(time.Duration(p.DeadlineTime) * time.Second).C:
			break Loop
		case <-ctx.Done():
			break Loop
		case <-p.ctx.Done():
			break Loop
		}
	}

	p.wg.Wait()
}

func (p *Pool) PreCompare(resp *http.Response) error {
	if !CheckStatusCode(resp.StatusCode) {
		return ErrBadStatus
	}

	if CheckRedirect != nil && !CheckRedirect(resp) {
		return ErrRedirect
	}

	if CheckWaf != nil && !CheckWaf(resp) {
		return ErrWaf
	}

	return nil
}

func (p *Pool) RunWithWord(words []string) {

}

func (p *Pool) BuildPathRequest(path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", p.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (p *Pool) BuildHostRequest(host string) (*http.Request, error) {
	req, err := http.NewRequest("GET", p.BaseURL, nil)
	req.Host = host
	if err != nil {
		return nil, err
	}
	return req, nil
}

type sourceType int

const (
	InitSource sourceType = iota + 1
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
