package internal

import (
	"context"
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	CheckRedirect func(string) bool
)

var max = 2147483647
var maxRedirect = 3
var maxRecuDepth = 0

func NewPool(ctx context.Context, config *pkg.Config) (*Pool, error) {
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config:      config,
		Statistor:   pkg.NewStatistor(config.BaseURL),
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		worder:      words.NewWorder(config.Wordlist, config.Fns),
		baselines:   make(map[int]*pkg.Baseline),
		tempCh:      make(chan *pkg.Baseline, config.Thread),
		wg:          sync.WaitGroup{},
		initwg:      sync.WaitGroup{},
		reqCount:    1,
		failedCount: 1,
	}

	pool.worder.Rules = pool.Rules
	pool.worder.RunWithRules()
	switch config.Mod {
	case pkg.PathSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return ihttp.BuildPathRequest(pool.ClientType, pool.BaseURL, s)
		}
		pool.check = func() {
			_ = pool.pool.Invoke(newUnit(pkg.RandPath(), CheckSource))

			if pool.failedCount > pool.BreakThreshold {
				// 当报错次数超过上限是, 结束任务
				pool.recover()
				pool.cancel()
			}
		}
	case pkg.HostSpray:
		pool.genReq = func(s string) (*ihttp.Request, error) {
			return ihttp.BuildHostRequest(pool.ClientType, pool.BaseURL, s)
		}

		pool.check = func() {
			_ = pool.pool.Invoke(newUnit(pkg.RandHost(), CheckSource))

			if pool.failedCount > pool.BreakThreshold {
				// 当报错次数超过上限是, 结束任务
				pool.recover()
				pool.cancel()
			}
		}
	}

	p, _ := ants.NewPoolWithFunc(config.Thread, func(i interface{}) {
		pool.Statistor.Total++
		unit := i.(*Unit)
		req, err := pool.genReq(unit.path)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		start := time.Now()
		resp, reqerr := pool.client.Do(pctx, req)
		if pool.ClientType == ihttp.FAST {
			defer fasthttp.ReleaseResponse(resp.FastResponse)
			defer fasthttp.ReleaseRequest(req.FastRequest)
		}

		// compare与各种错误处理
		var bl *pkg.Baseline
		if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
			pool.failedCount++
			pool.Statistor.FailedNumber++
			bl = &pkg.Baseline{UrlString: pool.BaseURL + unit.path, IsValid: false, ErrString: reqerr.Error(), Reason: ErrRequestFailed.Error()}
			pool.failedBaselines = append(pool.failedBaselines, bl)
		} else {
			if unit.source != WordSource && unit.source != RedirectSource {
				bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
			} else {
				if pool.MatchExpr != nil {
					// 如果非wordsource, 或自定义了match函数, 则所有数据送入tempch中
					bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
				} else if err = pool.PreCompare(resp); err == nil {
					// 通过预对比跳过一些无用数据, 减少性能消耗
					bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
					if err != ErrRedirect && bl.RedirectURL != "" {
						if bl.RedirectURL != "" && !strings.HasPrefix(bl.RedirectURL, "http") {
							bl.RedirectURL = "/" + strings.TrimLeft(bl.RedirectURL, "/")
							bl.RedirectURL = pool.BaseURL + bl.RedirectURL
						}
						pool.addRedirect(bl, unit.reCount)
					}
					pool.addFuzzyBaseline(bl)
				} else {
					bl = pkg.NewInvalidBaseline(req.URI(), req.Host(), resp, err.Error())
				}
			}
		}

		bl.Spended = time.Since(start).Milliseconds()
		switch unit.source {
		case InitRandomSource:
			pool.random = bl
			pool.addFuzzyBaseline(bl)
			pool.initwg.Done()
		case InitIndexSource:
			pool.index = bl
			pool.initwg.Done()
		case CheckSource:
			if bl.ErrString != "" {
				logs.Log.Warnf("[check.error] %s maybe ip had banned, break (%d/%d), error: %s", pool.BaseURL, pool.failedCount, pool.BreakThreshold, bl.ErrString)
				pool.failedBaselines = append(pool.failedBaselines, bl)
			} else if i := pool.random.Compare(bl); i < 1 {
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
			pool.reqCount++
			if pool.reqCount%pool.CheckPeriod == 0 {
				pool.reqCount++
				pool.Statistor.CheckNumber++
				go pool.check()
			} else if pool.failedCount%pool.ErrPeriod == 0 {
				pool.failedCount++
				pool.Statistor.CheckNumber++
				go pool.check()
			}
			pool.bar.Done()
		case RedirectSource:
			bl.FrontURL = unit.frontUrl
			pool.tempCh <- bl
		}

	})

	pool.pool = p
	// 挂起一个异步的处理结果线程, 不干扰主线程的请求并发
	go func() {
		for bl := range pool.tempCh {
			if _, ok := pool.Statistor.Counts[bl.Status]; ok {
				pool.Statistor.Counts[bl.Status]++
			} else {
				pool.Statistor.Counts[bl.Status] = 1
			}
			params := map[string]interface{}{
				"index":   pool.index,
				"random":  pool.random,
				"current": bl,
			}
			for _, status := range FuzzyStatus {
				if bl, ok := pool.baselines[status]; ok {
					params["bl"+strconv.Itoa(status)] = bl
				} else {
					params["bl"+strconv.Itoa(status)] = &pkg.Baseline{}
				}
			}

			var status bool
			if pool.MatchExpr != nil {
				if CompareWithExpr(pool.MatchExpr, params) {
					status = true
				}
			} else {
				if pool.BaseCompare(bl) {
					status = true
				}
			}

			if status {
				pool.Statistor.FoundNumber++
				if pool.FilterExpr != nil && CompareWithExpr(pool.FilterExpr, params) {
					pool.Statistor.FilteredNumber++
					bl.Reason = ErrCustomFilter.Error()
					bl.IsValid = false
				}
			} else {
				bl.IsValid = false
			}

			// 如果要进行递归判断, 要满足 bl有效, mod为path-spray, 当前深度小于最大递归深度
			if bl.IsValid && pool.Mod == pkg.PathSpray && bl.RecuDepth < maxRecuDepth {
				if CompareWithExpr(pool.RecuExpr, params) {
					bl.Recu = true
				}
			}
			pool.OutputCh <- bl
			pool.wg.Done()
		}

		pool.analyzeDone = true
	}()
	return pool, nil
}

type Pool struct {
	*pkg.Config
	Statistor       *pkg.Statistor
	client          *ihttp.Client
	pool            *ants.PoolWithFunc
	bar             *pkg.Bar
	ctx             context.Context
	cancel          context.CancelFunc
	tempCh          chan *pkg.Baseline // 待处理的baseline
	reqCount        int
	failedCount     int
	failedBaselines []*pkg.Baseline
	random          *pkg.Baseline
	index           *pkg.Baseline
	baselines       map[int]*pkg.Baseline
	analyzeDone     bool
	genReq          func(s string) (*ihttp.Request, error)
	check           func()
	worder          *words.Worder
	locker          sync.Mutex
	wg              sync.WaitGroup
	initwg          sync.WaitGroup // 初始化用, 之后改成锁
}

func (p *Pool) Init() error {
	// 分成两步是为了避免闭包的线程安全问题
	p.initwg.Add(1)
	p.pool.Invoke(newUnit("/", InitIndexSource))
	p.initwg.Wait()
	if p.index.ErrString != "" {
		return fmt.Errorf(p.index.String())
	}
	p.index.Collect()
	logs.Log.Important("[baseline.index] " + p.index.String())

	p.initwg.Add(1)
	p.pool.Invoke(newUnit(pkg.RandPath(), InitRandomSource))
	p.initwg.Wait()
	// 检测基本访问能力
	if p.random.ErrString != "" {
		return fmt.Errorf(p.random.String())
	}
	p.random.Collect()
	logs.Log.Important("[baseline.random] " + p.random.String())

	if p.random.RedirectURL != "" {
		// 自定协议升级
		// 某些网站http会重定向到https, 如果发现随机目录出现这种情况, 则自定将baseurl升级为https
		rurl, err := url.Parse(p.random.RedirectURL)
		if err == nil && rurl.Hostname() == p.random.Url.Hostname() && p.random.Url.Scheme == "http" && rurl.Scheme == "https" {
			logs.Log.Importantf("baseurl %s upgrade http to https", p.BaseURL)
			p.BaseURL = strings.Replace(p.BaseURL, "http", "https", 1)
		}
	}

	if p.random.RedirectURL != "" {
		CheckRedirect = func(redirectURL string) bool {
			if redirectURL == p.random.RedirectURL {
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

func (p *Pool) addRedirect(bl *pkg.Baseline, reCount int) {
	if reCount >= maxRedirect {
		return
	}

	if uu, err := url.Parse(bl.RedirectURL); err == nil && uu.Hostname() == p.index.Url.Hostname() {
		p.wg.Add(1)
		_ = p.pool.Invoke(&Unit{
			path:     uu.Path,
			source:   RedirectSource,
			frontUrl: bl.UrlString,
			reCount:  reCount + 1,
		})
	}
}

func (p *Pool) Run(ctx context.Context, offset, limit int) {
Loop:
	for {
		select {
		case u, ok := <-p.worder.C:
			if !ok {
				break Loop
			}
			p.Statistor.End++
			if p.reqCount < offset {
				p.reqCount++
				continue
			}

			if p.Statistor.End > limit {
				break Loop
			}

			for _, fn := range p.Fns {
				u = fn(u)
			}
			if u == "" {
				continue
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
	p.Statistor.ReqNumber = p.reqCount
	p.Statistor.EndTime = time.Now().Unix()
	p.Close()
}

func (p *Pool) PreCompare(resp *ihttp.Response) error {
	status := resp.StatusCode()
	if IntsContains(WhiteStatus, status) {
		// 如果为白名单状态码则直接返回
		return nil
	}
	if p.random != nil && p.random.Status != 200 && p.random.Status == status {
		return ErrSameStatus
	}

	if IntsContains(BlackStatus, status) {
		return ErrBadStatus
	}

	if IntsContains(WAFStatus, status) {
		return ErrWaf
	}

	if CheckRedirect != nil && !CheckRedirect(resp.GetHeader("Location")) {
		return ErrRedirect
	}

	return nil
}

func (p *Pool) BaseCompare(bl *pkg.Baseline) bool {
	if !bl.IsValid {
		return false
	}
	var status = -1
	base, ok := p.baselines[bl.Status] // 挑选对应状态码的baseline进行compare
	if !ok {
		if p.random.Status == bl.Status {
			// 当other的状态码与base相同时, 会使用base
			ok = true
			base = p.random
		} else if p.index.Status == bl.Status {
			// 当other的状态码与index相同时, 会使用index
			ok = true
			base = p.index
		}
	}

	if ok {
		if status = base.Compare(bl); status == 1 {
			bl.Reason = ErrCompareFailed.Error()
			return false
		}
	}

	bl.Collect()
	for _, f := range bl.Frameworks {
		if f.Tag == "waf" || f.Tag == "cdn" {
			p.Statistor.WafedNumber++
			bl.Reason = ErrWaf.Error()
			return false
		}
	}

	if ok && status == 0 && base.FuzzyCompare(bl) {
		p.Statistor.FuzzyNumber++
		bl.Reason = ErrFuzzyCompareFailed.Error()
		p.PutToFuzzy(bl)
		return false
	}

	return true
}

func CompareWithExpr(exp *vm.Program, params map[string]interface{}) bool {
	res, err := expr.Run(exp, params)
	if err != nil {
		logs.Log.Warn(err.Error())
	}

	if res == true {
		return true
	} else {
		return false
	}
}

func (p *Pool) addFuzzyBaseline(bl *pkg.Baseline) {
	if _, ok := p.baselines[bl.Status]; !ok && IntsContains(FuzzyStatus, bl.Status) {
		bl.Collect()
		p.locker.Lock()
		p.baselines[bl.Status] = bl
		p.locker.Unlock()
		logs.Log.Importantf("[baseline.%dinit] %s", bl.Status, bl.String())
	}
}

func (p *Pool) PutToInvalid(bl *pkg.Baseline, reason string) {
	bl.IsValid = false
	p.OutputCh <- bl
}

func (p *Pool) PutToFuzzy(bl *pkg.Baseline) {
	bl.IsFuzzy = true
	p.FuzzyCh <- bl
}

func (p *Pool) resetFailed() {
	p.failedCount = 1
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
	for p.analyzeDone {
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	close(p.tempCh)
	p.bar.Close()
}
