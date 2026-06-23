package pool

import (
	"context"
	"errors"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words/rule"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
	"math/rand"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	EnableAllFuzzy  = false
	EnableAllUnique = false
	//AllowHostModSource = []parsers.SpraySource{parsers.WordSource, parsers.CheckSource, parsers.InitIndexSource, parsers.InitRandomSource}
)

func NewBrutePool(ctx context.Context, config *Config) (*BrutePool, error) {
	var u *url.URL
	var err error
	if u, err = url.Parse(config.BaseURL); err != nil {
		return nil, err
	}

	// 将URL的RawQuery设置到RequestConfig中
	config.Request.RawQuery = u.RawQuery

	pctx, cancel := context.WithCancel(ctx)
	pool := &BrutePool{
		Baselines: NewBaselines(),
		BasePool: &BasePool{
			Config: config,
			ctx:    pctx,
			Cancel: cancel,
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
		base:        u.Scheme + "://" + u.Host,
		isDir:       strings.HasSuffix(u.Path, "/"),
		url:         u,
		urihost:     u.Hostname(),
		scopeurls:   make(map[string]struct{}),
		uniques:     make(map[uint16]struct{}),
		initwg:      sync.WaitGroup{},
		limiter:     rate.NewLimiter(rate.Limit(config.RateLimit), 1),
		failedCount: 1,
	}
	rand.Seed(time.Now().UnixNano())
	// 格式化dir, 保证至少有一个"/"
	if strings.HasSuffix(config.BaseURL, "/") {
		pool.dir = pool.url.Path
	} else if pool.url.Path == "" {
		pool.dir = "/"
	} else {
		pool.dir = pkg.Dir(pool.url.Path)
	}

	// 每个 BrutePool 自持请求/scope 线程池, 与其他 BrutePool 完全隔离
	pool.reqPool, err = ants.NewPoolWithFunc(config.Thread, pool.invoke)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create request pool: %w", err)
	}
	pool.scopePool, err = ants.NewPoolWithFunc(config.Thread, pool.invokeNoScope)
	if err != nil {
		pool.reqPool.Release()
		cancel()
		return nil, fmt.Errorf("create scope pool: %w", err)
	}

	// 挂起一个异步的处理结果线程, 不干扰主线程的请求并发
	go pool.Handler()
	return pool, nil
}

type BrutePool struct {
	*Baselines
	*BasePool
	base    string // url的根目录, 在爬虫或者redirect时, 会需要用到根目录进行拼接
	isDir   bool
	dir     string
	urihost string
	url     *url.URL

	wordOffset  atomic.Int64
	failedCount int32
	IsFailed    bool
	urls        sync.Map
	scopeurls   map[string]struct{}
	uniques     map[uint16]struct{}
	limiter     *rate.Limiter
	scopeLocker sync.Mutex
	initwg      sync.WaitGroup // 初始化用, 之后改成锁
	reqPool     *ants.PoolWithFunc
	scopePool   *ants.PoolWithFunc
}

// launchProducer 把一个生产者函数放到独立 goroutine, wg 跟踪生命周期.
func (pool *BrutePool) launchProducer(fn func()) {
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		fn()
	}()
}

func (pool *BrutePool) Init() error {
	pool.initwg.Add(2)

	// initSubmit 包装一次 init 派发: wg.Add 在 reqPool.Invoke 之前;
	// Invoke 失败时同时回滚 wg 与 initwg, 避免 initwg.Wait 死锁.
	initSubmit := func(unit *Unit) {
		pool.wg.Add(1)
		if err := pool.reqPool.Invoke(unit); err != nil {
			pool.wg.Done()
			pool.initwg.Done()
		}
	}

	if pool.Index != "/" {
		logs.Log.Logf(pkg.LogVerbose, "custom index url: %s", pkg.BaseURL(pool.url)+pkg.FormatURL(pkg.BaseURL(pool.url), pool.Index))
		initSubmit(&Unit{path: pool.Index, source: parsers.InitIndexSource})
	} else {
		initSubmit(&Unit{path: pool.url.Path, source: parsers.InitIndexSource})
	}

	if pool.Random != "" {
		logs.Log.Logf(pkg.LogVerbose, "custom random url: %s", pkg.BaseURL(pool.url)+pkg.FormatURL(pkg.BaseURL(pool.url), pool.Random))
		if pool.Mod == PathSpray {
			initSubmit(&Unit{path: pool.Random, source: parsers.InitRandomSource})
		} else {
			initSubmit(&Unit{host: pool.Random, source: parsers.InitRandomSource})
		}
	} else {
		if pool.Mod == PathSpray {
			initSubmit(&Unit{path: pool.safePath(pkg.RandPath()), source: parsers.InitRandomSource})
		} else {
			initSubmit(&Unit{host: pkg.RandHost(), source: parsers.InitRandomSource})
		}
	}

	pool.initwg.Wait()
	if pool.index == nil || pool.random == nil {
		if err := pool.ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("init baseline not available")
	}
	if pool.index.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf("%s", pool.index.ErrString)
	}
	if pool.index.Chunked && pool.ClientType == ihttp.FAST {
		logs.Log.Warn("chunk encoding! buf current client FASTHTTP not support chunk decode")
	}
	logs.Log.Logf(pkg.LogVerbose, "[baseline.index] %s", pool.index.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
	// 检测基本访问能力
	if pool.random.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf("%s", pool.index.ErrString)
	}
	logs.Log.Logf(pkg.LogVerbose, "[baseline.random] %s", pool.random.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))

	// 某些网站http会重定向到https, 如果发现随机目录出现这种情况, 则自定将baseurl升级为https
	if pool.url.Scheme == "http" {
		if pool.index.RedirectURL != "" {
			if err := pool.Upgrade(pool.index); err != nil {
				return err
			}
		} else if pool.random.RedirectURL != "" {
			if err := pool.Upgrade(pool.random); err != nil {
				return err
			}
		}
	}

	return nil
}

func (pool *BrutePool) Run(offset, limit int) {
	pool.Worder.Run()
	if pool.Active {
		pool.launchProducer(pool.doActive)
	}

	if pool.Bak {
		pool.launchProducer(pool.doBak)
	}

	if pool.Fuzzuli {
		pool.launchProducer(pool.doFuzzuli)
	}

	if pool.Common {
		pool.launchProducer(pool.doCommonFile)
	}

	// worderCh 指向 Worder 输出; 设为 nil 后 select 不再接受新词,
	// 随后 allDone 等待 in-flight 工作全部结束再退出循环.
	// 这比 atomic.Bool + 轮询 monitor goroutine 更安全: wg.Add 只发生在
	// worderCh 分支, nil 掉之后不会再有新 Add, 消除了 Add/Wait 竞态.
	worderCh := pool.Worder.Output
	var allDone <-chan struct{} // nil channel: select 永远不选中

	var drainOnce sync.Once
	startDrain := func() {
		drainOnce.Do(func() {
			worderCh = nil
			ch := make(chan struct{})
			go func() { pool.wg.Wait(); close(ch) }()
			allDone = ch
		})
	}

Loop:
	for {
		select {
		case w, ok := <-worderCh:
			if !ok {
				startDrain()
				continue
			}
			pool.Statistor.End++

			wordOffset := int(pool.wordOffset.Add(1))
			if wordOffset < offset {
				continue
			}

			if pool.Statistor.End > limit {
				startDrain()
				continue
			}

			if w == "" {
				pool.Statistor.Skipped++
				pool.Bar.Done()
				continue
			}

			pool.wg.Add(1)
			if pool.Mod == HostSpray {
				if err := pool.reqPool.Invoke(&Unit{word: w, host: w, source: parsers.WordSource, number: wordOffset}); err != nil {
					pool.wg.Done()
				}
			} else {
				if err := pool.reqPool.Invoke(&Unit{word: w, path: pool.safePath(w), source: parsers.WordSource, number: wordOffset}); err != nil {
					pool.wg.Done()
				}
			}
		case unit, ok := <-pool.additionCh:
			if !ok {
				continue
			}
			// addAddition 已经做过 wg.Add(1), 这里不再 Add
			if _, ok := pool.urls.Load(unit.path); ok {
				logs.Log.Debugf("[%s] duplicate path: %s, skipped", unit.source.Name(), pool.base+unit.path)
				pool.wg.Done()
			} else {
				pool.urls.Store(unit.path, nil)
				unit.path = pool.safePath(unit.path)
				unit.number = int(pool.wordOffset.Load())
				if err := pool.reqPool.Invoke(unit); err != nil {
					pool.wg.Done()
				}
			}
		case <-allDone:
			break Loop
		case <-pool.ctx.Done():
			break Loop
		}
	}
	pool.Close()
}

func (pool *BrutePool) invoke(v interface{}) {
	defer pool.wg.Done()
	unit := v.(*Unit)
	if pool.RateLimit != 0 {
		if err := pool.limiter.Wait(pool.ctx); err != nil {
			bl := &baseline.Baseline{
				SprayResult: &parsers.SprayResult{
					UrlString: unit.path,
					ErrString: err.Error(),
					Reason:    pkg.ErrRequestFailed.Error(),
				},
			}
			bl.Number = unit.number
			bl.Parent = unit.parent
			bl.Source = unit.source
			bl.From = unit.from
			bl.ReqDepth = unit.depth
			bl.Retry = unit.retry
			pool.sendProcess(bl)
			return
		}
	}

	// 使用RequestConfig.Build()构建请求
	req, err := pool.Request.Build(pool.ctx, pool.ClientType, pool.base, unit.path, unit.host, unit.word)
	if err != nil {
		logs.Log.Debug(err.Error())
		bl := &baseline.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				ErrString: err.Error(),
				Reason:    pkg.ErrUrlError.Error(),
			},
		}
		bl.Number = unit.number
		bl.Parent = unit.parent
		bl.Source = unit.source
		bl.From = unit.from
		bl.ReqDepth = unit.depth
		bl.Retry = unit.retry
		pool.sendProcess(bl)
		return
	}

	start := time.Now()
	resp, reqerr := pool.client.Do(req)
	if pool.ClientType == ihttp.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}

	// compare与各种错误处理
	var bl *baseline.Baseline
	if reqerr != nil && !errors.Is(reqerr, fasthttp.ErrBodyTooLarge) {
		bl = &baseline.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: req.URI(),
				ErrString: reqerr.Error(),
				Reason:    pkg.ErrRequestFailed.Error(),
			},
		}
	} else { // 特定场景优化
		bl = baseline.NewBaseline(req.URI(), req.Host(), resp)
	}

	if !ihttp.CheckBodySize(int64(bl.BodyLength)) {
		bl.ExceedLength = true
	}
	bl.Number = unit.number
	bl.Parent = unit.parent
	bl.Source = unit.source
	bl.From = unit.from
	bl.ReqDepth = unit.depth
	bl.Retry = unit.retry
	if unit.source == parsers.RedirectSource {
		bl.FrontURL = unit.frontUrl
	}
	bl.Spended = time.Since(start).Milliseconds()

	// doRedirect launches a goroutine that reads bl fields,
	// so all field writes must complete before this call.
	if bl.IsValid && unit.source != parsers.CheckSource && bl.RedirectURL != "" {
		bl.SameRedirectDomain = pool.checkHost(bl.RedirectURL)
		pool.doRedirect(bl, unit.depth)
	}

	pool.sendProcess(bl)
}

func (pool *BrutePool) invokeNoScope(v interface{}) {
	defer pool.wg.Done()
	unit := v.(*Unit)

	// 为NoScope请求创建一个简化的RequestConfig（固定使用GET方法）
	scopeReqConfig := &ihttp.RequestConfig{
		Method:          "GET",
		Headers:         pool.Request.Headers,
		Body:            nil,
		RandomUserAgent: pool.Request.RandomUserAgent,
	}

	req, err := scopeReqConfig.Build(pool.ctx, pool.ClientType, unit.path, "", "", "")
	if err != nil {
		logs.Log.Debug(err.Error())
		bl := &baseline.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				ErrString: err.Error(),
				Reason:    pkg.ErrUrlError.Error(),
			},
		}
		bl.Source = unit.source
		bl.From = unit.from
		bl.ReqDepth = unit.depth
		bl.Retry = unit.retry
		pool.sendProcess(bl)
		return
	}
	resp, reqerr := pool.client.Do(req)
	if pool.ClientType == ihttp.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}
	if reqerr != nil {
		logs.Log.Debug(reqerr.Error())
		bl := &baseline.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: unit.path,
				ErrString: reqerr.Error(),
				Reason:    pkg.ErrRequestFailed.Error(),
			},
		}
		bl.Source = unit.source
		bl.From = unit.from
		bl.ReqDepth = unit.depth
		bl.Retry = unit.retry
		pool.sendProcess(bl)
		return
	}
	if resp.StatusCode() == 200 {
		bl := baseline.NewBaseline(req.URI(), req.Host(), resp)
		bl.Source = unit.source
		bl.From = unit.from
		bl.ReqDepth = unit.depth
		bl.Retry = unit.retry
		bl.Collect()
		bl.CollectURL()
		pool.sendProcess(bl)
		return
	}
	bl := baseline.NewInvalidBaseline(req.URI(), req.Host(), resp, pkg.ErrBadStatus.Error())
	bl.Source = unit.source
	bl.From = unit.from
	bl.ReqDepth = unit.depth
	bl.Retry = unit.retry
	pool.sendProcess(bl)
}

func (pool *BrutePool) Handler() {
	defer close(pool.handlerDone)
	for bl := range pool.processCh {
		pool.handleBaseline(bl)
		pool.wg.Done()
	}
}

func (pool *BrutePool) handleBaseline(bl *baseline.Baseline) {
	pool.Statistor.ReqTotal++
	if bl.ErrString != "" {
		pool.failedCount++
		pool.Statistor.FailedNumber++
		pool.FailedBaselines = append(pool.FailedBaselines, bl)
		if bl.Source != parsers.InitIndexSource && bl.Source != parsers.InitRandomSource && bl.Source != parsers.CheckSource {
			pool.doRetry(bl)
		}
	}

	switch bl.Source {
	case parsers.InitRandomSource:
		pool.random = bl
		if bl.IsValid {
			bl.Collect()
			pool.addFuzzyBaseline(bl)
		}
		pool.initwg.Done()
		return
	case parsers.InitIndexSource:
		pool.index = bl
		if bl.IsValid {
			bl.Collect()
			pool.doCrawl(bl)
			pool.doAppend(bl)
			pool.putToOutput(bl)
		}
		pool.initwg.Done()
		return
	case parsers.CheckSource:
		pool.handleCheckBaseline(bl)
		return
	case parsers.CrawlSource:
		pool.handleCrawlBaseline(bl)
		return
	}

	if _, ok := pool.Statistor.Counts[bl.Status]; ok {
		pool.Statistor.Counts[bl.Status]++
	} else {
		pool.Statistor.Counts[bl.Status] = 1
	}

	if _, ok := pool.Statistor.Sources[bl.Source]; ok {
		pool.Statistor.Sources[bl.Source]++
	} else {
		pool.Statistor.Sources[bl.Source] = 1
	}

	params := pool.compareParams(bl)
	if bl.IsValid {
		if pool.addFuzzyBaseline(bl) {
			bl.IsValid = false
			bl.IsFuzzy = true
			bl.Reason = pkg.ErrFuzzyCompareFailed.Error()
		} else {
			ok := false
			if pool.MatchExpr != nil {
				ok = pkg.CompareWithExpr(pool.MatchExpr, params)
			} else if pool.shouldPreCompare(bl) {
				if err := pool.PreCompareBaseline(bl); err == nil {
					ok = pool.BaseCompare(bl)
				} else {
					bl.Reason = err.Error()
				}
			} else {
				ok = pool.BaseCompare(bl)
			}

			if ok {
				// unique判断
				if EnableAllUnique || iutils.IntsContains(pkg.UniqueStatus, bl.Status) {
					if _, ok := pool.uniques[bl.Unique]; ok {
						bl.IsValid = false
						bl.IsFuzzy = true
						bl.Reason = pkg.ErrFuzzyNotUnique.Error()
					} else {
						pool.uniques[bl.Unique] = struct{}{}
					}
				}

				// 对通过所有对比的有效数据进行再次filter
				if bl.IsValid && pool.FilterExpr != nil && pkg.CompareWithExpr(pool.FilterExpr, params) {
					pool.Statistor.FilteredNumber++
					bl.Reason = pkg.ErrCustomFilter.Error()
					bl.IsValid = false
				}
			} else {
				bl.IsValid = false
			}
		}
	} else {
		bl.IsValid = false
	}

	if bl.IsValid || (bl.IsFuzzy && pool.Fuzzy) {
		pool.doCrawl(bl)
		pool.doAppend(bl)
	}

	// 如果要进行递归判断, 要满足 bl有效, mod为path-spray, 当前深度小于最大递归深度
	if bl.IsValid {
		pool.Statistor.FoundNumber++
		if pool.RecuExpr != nil && bl.RecuDepth < pool.MaxRecursionDepth {
			if pkg.CompareWithExpr(pool.RecuExpr, params) {
				bl.Recu = true
			}
		}
	}

	if bl.Source == parsers.WordSource {
		pool.Bar.Done()
		pool.maybeScheduleCheck()
	}

	pool.putToOutput(bl)
}

func (pool *BrutePool) compareParams(bl *baseline.Baseline) map[string]interface{} {
	if pool.MatchExpr == nil && pool.FilterExpr == nil && pool.RecuExpr == nil {
		return nil
	}
	return map[string]interface{}{
		"index":   pool.index,
		"random":  pool.random,
		"current": bl,
	}
}

func (pool *BrutePool) handleCheckBaseline(bl *baseline.Baseline) {
	if bl.ErrString != "" {
		logs.Log.Warnf("[check.error] %s maybe ip had banned, break (%d/%d), error: %s", pool.BaseURL, pool.failedCount, pool.BreakThreshold, bl.ErrString)
		return
	}
	if pool.random == nil {
		return
	}
	if i := pool.random.Compare(bl); i < 1 {
		if i == 0 {
			if pool.Fuzzy {
				logs.Log.Debug("[check.fuzzy] maybe trigger risk control, " + bl.String())
			}
			return
		}
		pool.failedCount++
		logs.Log.Debug("[check.failed] maybe trigger risk control, " + bl.String())
		pool.FailedBaselines = append(pool.FailedBaselines, bl)
		return
	}
	pool.resetFailed()
	logs.Log.Debug("[check.pass] " + bl.String())
}

func (pool *BrutePool) handleCrawlBaseline(bl *baseline.Baseline) {
	if _, ok := pool.Statistor.Counts[bl.Status]; ok {
		pool.Statistor.Counts[bl.Status]++
	} else {
		pool.Statistor.Counts[bl.Status] = 1
	}
	if _, ok := pool.Statistor.Sources[bl.Source]; ok {
		pool.Statistor.Sources[bl.Source]++
	} else {
		pool.Statistor.Sources[bl.Source] = 1
	}

	if bl.IsValid {
		bl.Collect()
		pool.doCrawl(bl)
		pool.doAppend(bl)
		pool.Statistor.FoundNumber++
	}
	pool.putToOutput(bl)
}

func (pool *BrutePool) maybeScheduleCheck() {
	if pool.CheckPeriod > 0 && int(pool.Statistor.ReqTotal)%pool.CheckPeriod == 0 {
		pool.doCheck()
		return
	}
	if pool.ErrPeriod > 0 && pool.failedCount > 0 && pool.failedCount%pool.ErrPeriod == 0 {
		pool.failedCount++
		pool.doCheck()
	}
}

func (pool *BrutePool) checkRedirect(redirectURL string) bool {
	if pool.random == nil || pool.random.RedirectURL == "" {
		// 如果random的redirectURL为空, 忽略
		return true
	}

	if redirectURL == pool.random.RedirectURL {
		// 相同的RedirectURL将被认为是无效数据
		return false
	} else {
		// path为3xx, 且与baseline中的RedirectURL不同时, 为有效数据
		return true
	}
}

func (pool *BrutePool) Upgrade(bl *baseline.Baseline) error {
	rurl, err := url.Parse(bl.RedirectURL)
	if err == nil && rurl.Hostname() == bl.Url.Hostname() && bl.Url.Scheme == "http" && rurl.Scheme == "https" {
		logs.Log.Infof("baseurl %s upgrade http to https, reinit", pool.BaseURL)
		pool.base = strings.Replace(pool.BaseURL, "http", "https", 1)
		pool.url.Scheme = "https"
		// 重新初始化
		err = pool.Init()
		if err != nil {
			return err
		}
	}

	return nil
}

func (pool *BrutePool) PreCompare(resp *ihttp.Response) error {
	status := resp.StatusCode()
	if pkg.StatusContain(pkg.WhiteStatus, status) {
		// 如果为白名单状态码则直接返回
		return nil
	}
	//if pool.random.Status != 200 && pool.random.Status == status {
	//	return pkg.ErrSameStatus
	//}

	if pkg.StatusContain(pkg.BlackStatus, status) {
		return pkg.ErrBadStatus
	}

	if pkg.StatusContain(pkg.WAFStatus, status) {
		return pkg.ErrWaf
	}

	if !pool.checkRedirect(resp.GetHeader("Location")) {
		return pkg.ErrRedirect
	}

	return nil
}

func (pool *BrutePool) PreCompareBaseline(bl *baseline.Baseline) error {
	status := bl.Status
	if pkg.StatusContain(pkg.WhiteStatus, status) {
		return nil
	}
	if pkg.StatusContain(pkg.BlackStatus, status) {
		return pkg.ErrBadStatus
	}
	if pkg.StatusContain(pkg.WAFStatus, status) {
		return pkg.ErrWaf
	}
	if !pool.checkRedirect(bl.RedirectURL) {
		return pkg.ErrRedirect
	}
	return nil
}

func (pool *BrutePool) shouldPreCompare(bl *baseline.Baseline) bool {
	if pool.MatchExpr != nil {
		return false
	}
	switch bl.Source {
	case parsers.CheckSource, parsers.InitRandomSource, parsers.InitIndexSource, parsers.CrawlSource, parsers.CommonFileSource:
		return false
	default:
		return true
	}
}

// same host return true
// diff host return false
func (pool *BrutePool) checkHost(u string) bool {
	if v, err := url.Parse(u); err == nil {
		if v.Host == "" {
			return true
		}
		if v.Host == pool.url.Host {
			return true
		} else {
			return false
		}
	}
	return true
}

func (pool *BrutePool) BaseCompare(bl *baseline.Baseline) bool {
	if !bl.IsValid {
		return false
	}
	var status = -1

	// 30x状态码的特殊处理
	if bl.RedirectURL != "" {
		if bl.SameRedirectDomain && strings.HasSuffix(bl.RedirectURL, bl.Url.Path+"/") {
			bl.Reason = pkg.ErrFuzzyRedirect.Error()
			return false
		}
	}

	// 使用与baseline相同状态码, 需要在fuzzystatus中提前配置
	base, ok := pool.baselines[bl.Status] // 挑选对应状态码的baseline进行compare
	if bl.IsBaseline {
		ok = false
	}
	if !ok {
		if pool.random.Status == bl.Status {
			// 当other的状态码与base相同时, 会使用base
			ok = true
			base = pool.random
		} else if pool.index.Status == bl.Status {
			// 当other的状态码与index相同时, 会使用index
			ok = true
			base = pool.index
		}
	}

	if ok {
		if status = base.Compare(bl); status == 1 {
			bl.Reason = pkg.ErrCompareFailed.Error()
			return false
		}
	}

	bl.Hashes = parsers.NewHashes(bl.Raw)

	//if !pool.IgnoreWaf {
	//	// 部分情况下waf的特征可能是全局, 指定了--ignore-waf则不会进行waf的指纹检测
	//	for _, f := range bl.Frameworks {
	//		if f.HasTag("waf") {
	//			pool.Statistor.WafedNumber++
	//			bl.Reason = ErrWaf.Error()
	//			return false
	//		}
	//	}
	//}

	if ok && status == 0 && pool.sameDefaultResponse(base, bl) {
		pool.Statistor.FuzzyNumber++
		bl.Reason = pkg.ErrFuzzyCompareFailed.Error()
		pool.putToFuzzy(bl)
		return false
	}

	return true
}

func (pool *BrutePool) sameDefaultResponse(base, bl *baseline.Baseline) bool {
	if base.FuzzyCompare(bl) {
		return true
	}
	return pool.isAdaptiveFuzzyStatus(bl.Status)
}

func (pool *BrutePool) addFuzzyBaseline(bl *baseline.Baseline) bool {
	if !pool.shouldLearnFuzzyBaseline(bl) {
		return false
	}
	for _, base := range pool.fuzzyBaselines[bl.Status] {
		if pool.sameFuzzyBaseline(base, bl) {
			return true
		}
	}
	pool.learnFuzzyBaseline(bl)
	return true
}

func (pool *BrutePool) sameFuzzyBaseline(base, bl *baseline.Baseline) bool {
	switch base.Compare(bl) {
	case 1:
		return true
	case 0:
		return true
	default:
		return false
	}
}

func (pool *BrutePool) learnFuzzyBaseline(bl *baseline.Baseline) {
	if pool.baselines == nil {
		pool.baselines = make(map[int]*baseline.Baseline)
	}
	if pool.fuzzyBaselines == nil {
		pool.fuzzyBaselines = make(map[int][]*baseline.Baseline)
	}
	bl.IsBaseline = true
	bl.Collect()
	pool.doCrawl(bl) // 非有效页面也可能存在一些特殊的url可以用来爬取
	if _, ok := pool.baselines[bl.Status]; !ok {
		pool.baselines[bl.Status] = bl
	}
	pool.fuzzyBaselines[bl.Status] = append(pool.fuzzyBaselines[bl.Status], bl)
	logs.Log.Logf(pkg.LogVerbose, "[baseline.%dinit] %s", bl.Status, bl.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
}

func (pool *BrutePool) shouldLearnFuzzyBaseline(bl *baseline.Baseline) bool {
	if EnableAllFuzzy || iutils.IntsContains(pkg.FuzzyStatus, bl.Status) {
		return true
	}
	return pool.isAdaptiveFuzzyStatus(bl.Status)
}

func (pool *BrutePool) isAdaptiveFuzzyStatus(status int) bool {
	if status == 0 || (status >= 200 && status < 300) {
		return false
	}
	if len(pkg.WhiteStatus) > 0 && pkg.StatusContain(pkg.WhiteStatus, status) {
		return false
	}
	if len(pkg.BlackStatus) > 0 && pkg.StatusContain(pkg.BlackStatus, status) {
		return false
	}
	if len(pkg.WAFStatus) > 0 && pkg.StatusContain(pkg.WAFStatus, status) {
		return false
	}
	return true
}

func (pool *BrutePool) fallback() {
	logs.Log.Errorf("%s ,failed request exceeds the threshold , task will exit. Breakpoint %d", pool.BaseURL, pool.wordOffset.Load())
	for i, bl := range pool.FailedBaselines {
		if i > 5 {
			break
		}
		logs.Log.Errorf("[failed.%d] %s", i, bl.String())
	}
}

func (pool *BrutePool) Close() {
	pool.Cancel()
	// drain additionCh: Run 主循环退出后可能还有未消费的 addition item,
	// 每个都持有 wg.Add(1), 必须 Done 掉否则 wg.Wait 永远阻塞.
	go func() {
		for range pool.additionCh {
			pool.wg.Done()
		}
	}()
	pool.wg.Wait()
	close(pool.additionCh)
	pool.reqPool.Release()
	pool.scopePool.Release()
	close(pool.processCh)
	<-pool.handlerDone
	pool.Statistor.EndTime = time.Now().Unix()
}

func (pool *BrutePool) safePath(u string) string {
	// 自动生成的目录将采用safepath的方式拼接到相对目录中, 避免出现//的情况. 例如init, check, common
	if pool.isDir {
		return pkg.SafePath(pool.dir, u)
	} else {
		return pkg.SafePath(pool.url.Path+"/", u)
	}
}

func (pool *BrutePool) resetFailed() {
	pool.failedCount = 1
	pool.FailedBaselines = nil
}

func (pool *BrutePool) doCheck() {
	if pool.failedCount > pool.BreakThreshold {
		// 当报错次数超过上限是, 结束任务
		if pool.isFallback.Load() {
			return
		}
		pool.isFallback.Store(true)
		pool.fallback()
		pool.IsFailed = true
		pool.Cancel()
		return
	}

	var unit *Unit
	wordOffset := int(pool.wordOffset.Load())
	if pool.Mod == HostSpray {
		pool.Statistor.CheckNumber++
		unit = &Unit{host: pkg.RandHost(), source: parsers.CheckSource, number: wordOffset}
	} else if pool.Mod == PathSpray {
		pool.Statistor.CheckNumber++
		unit = &Unit{path: pool.safePath(pkg.RandPath()), source: parsers.CheckSource, number: wordOffset}
	} else {
		return
	}
	pool.addAddition(unit)
}

func (pool *BrutePool) doRedirect(bl *baseline.Baseline, depth int) {
	if depth >= pool.MaxRedirect {
		return
	}

	//if !bl.SameRedirectDomain {
	//	return // 不同域名的重定向不处理
	//}
	reURL := pkg.FormatURL(bl.Url.Path, bl.RedirectURL)
	pool.launchProducer(func() {
		pool.addAddition(&Unit{
			path:     reURL,
			parent:   bl.Number,
			host:     bl.Host,
			source:   parsers.RedirectSource,
			from:     bl.Source,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		})
	})
}

func (pool *BrutePool) doCrawl(bl *baseline.Baseline) {
	if !pool.Crawl || bl.ReqDepth >= pool.MaxCrawlDepth {
		return
	}

	bl.CollectURL()
	if bl.URLs == nil {
		return
	}

	pool.doScopeCrawl(bl)

	pool.launchProducer(func() {
		for _, u := range bl.URLs {
			if u = pkg.FormatURL(bl.Url.Path, u); u == "" {
				continue
			}
			pool.addAddition(&Unit{
				path:   u,
				parent: bl.Number,
				host:   bl.Host,
				source: parsers.CrawlSource,
				from:   bl.Source,
				depth:  bl.ReqDepth + 1,
			})
		}
	})

}

func (pool *BrutePool) doScopeCrawl(bl *baseline.Baseline) {
	if bl.ReqDepth >= pool.MaxCrawlDepth {
		return
	}

	pool.launchProducer(func() {
		for _, u := range bl.URLs {
			if strings.HasPrefix(u, "http") {
				if v, _ := url.Parse(u); v == nil || !pkg.MatchWithGlobs(v.Host, pool.Scope) {
					continue
				}
				submit := func() bool {
					pool.scopeLocker.Lock()
					defer pool.scopeLocker.Unlock()
					if _, ok := pool.scopeurls[u]; !ok {
						pool.scopeurls[u] = struct{}{}
						pool.urls.Store(u, nil)
						return true
					}
					return false
				}()
				if submit {
					pool.wg.Add(1)
					if err := pool.scopePool.Invoke(&Unit{
						path:   u,
						parent: bl.Number,
						source: parsers.CrawlSource,
						from:   bl.Source,
						depth:  bl.ReqDepth + 1,
					}); err != nil {
						pool.wg.Done()
					}
				}
			}
		}
	})
}

func (pool *BrutePool) doFuzzuli() {
	if pool.Mod == HostSpray {
		return
	}
	for w := range NewBruteDSL(pool.Config, "{?0}.{?@bak_ext}", [][]string{pkg.BakGenerator(pool.url.Host)}).Output {
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: parsers.BakSource,
		})
	}
}

func (pool *BrutePool) doBak() {
	if pool.Mod == HostSpray {
		return
	}

	for w := range NewBruteDSL(pool.Config, "{?@bak_name}.{?@bak_ext}", nil).Output {
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: parsers.BakSource,
		})
	}
}

func (pool *BrutePool) doAppend(bl *baseline.Baseline) {
	pool.doAppendWords(bl)
	pool.doAppendRule(bl)
}

func (pool *BrutePool) doAppendRule(bl *baseline.Baseline) {
	if pool.AppendRule == nil || !canDeriveAppendFromSource(bl.Source) || bl.ReqDepth >= pool.MaxAppendDepth {
		return
	}

	pool.launchProducer(func() {
		for u := range rule.RunAsStream(pool.AppendRule.Expressions, path.Base(bl.Path)) {
			pool.addAddition(&Unit{
				path:   pkg.Dir(bl.Url.Path) + u,
				parent: bl.Number,
				host:   bl.Host,
				source: parsers.AppendRuleSource,
				from:   bl.Source,
				depth:  bl.ReqDepth + 1,
			})
		}
	})
}

func (pool *BrutePool) doAppendWords(bl *baseline.Baseline) {
	if pool.AppendWords == nil || !canDeriveAppendFromSource(bl.Source) || bl.ReqDepth >= pool.MaxAppendDepth {
		// 防止自身递归
		return
	}

	pool.launchProducer(func() {
		for u := range NewBruteWords(pool.Config, pool.AppendWords).Output {
			pool.addAddition(&Unit{
				path:   pkg.SafePath(appendBasePath(bl.Path), u),
				parent: bl.Number,
				host:   bl.Host,
				source: parsers.AppendSource,
				from:   bl.Source,
				depth:  bl.ReqDepth + 1,
			})
		}
	})
}

func canDeriveAppendFromSource(source parsers.SpraySource) bool {
	switch source {
	case parsers.InitIndexSource, parsers.WordSource, parsers.RedirectSource, parsers.CrawlSource:
		return true
	default:
		return false
	}
}

func appendBasePath(current string) string {
	if current == "" {
		return "/"
	}
	if strings.HasSuffix(current, "/") {
		return current
	}
	return current + "/"
}

func (pool *BrutePool) doActive() {
	if pool.Mod == HostSpray {
		return
	}
	for _, u := range pkg.ActivePath {
		pool.addAddition(&Unit{
			path:   pool.dir + u[1:],
			source: parsers.FingerSource,
		})
	}
}

func (pool *BrutePool) doCommonFile() {
	if pool.Mod == HostSpray {
		return
	}
	for u := range NewBruteWords(pool.Config, append(pkg.Dicts["common"], pkg.Dicts["log"]...)).Output {
		pool.addAddition(&Unit{
			path:   pool.dir + u,
			source: parsers.CommonFileSource,
		})
	}
}
