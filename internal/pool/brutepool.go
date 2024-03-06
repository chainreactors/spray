package pool

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words"
	"github.com/panjf2000/ants/v2"
	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	MaxRedirect     = 3
	MaxCrawl        = 3
	MaxRecursion    = 0
	EnableAllFuzzy  = false
	EnableAllUnique = false
)

func NewBrutePool(ctx context.Context, config *Config) (*BrutePool, error) {
	var u *url.URL
	var err error
	if u, err = url.Parse(config.BaseURL); err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(ctx)
	pool := &BrutePool{
		Baselines: NewBaselines(),
		This: &This{
			Config: config,
			ctx:    pctx,
			Cancel: cancel,
			client: ihttp.NewClient(&ihttp.ClientConfig{
				Thread:    config.Thread,
				Type:      config.ClientType,
				Timeout:   time.Duration(config.Timeout) * time.Second,
				ProxyAddr: config.ProxyAddr,
			}),
			additionCh: make(chan *Unit, config.Thread),
			closeCh:    make(chan struct{}),
			wg:         sync.WaitGroup{},
		},
		base:  u.Scheme + "://" + u.Host,
		isDir: strings.HasSuffix(u.Path, "/"),
		url:   u,

		scopeurls:   make(map[string]struct{}),
		uniques:     make(map[uint16]struct{}),
		handlerCh:   make(chan *pkg.Baseline, config.Thread),
		checkCh:     make(chan struct{}, config.Thread),
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

	pool.reqPool, _ = ants.NewPoolWithFunc(config.Thread, pool.Invoke)
	pool.scopePool, _ = ants.NewPoolWithFunc(config.Thread, pool.NoScopeInvoke)

	// 挂起一个异步的处理结果线程, 不干扰主线程的请求并发
	go pool.Handler()
	return pool, nil
}

type BrutePool struct {
	*Baselines
	*This
	base  string // url的根目录, 在爬虫或者redirect时, 会需要用到根目录进行拼接
	isDir bool
	url   *url.URL

	reqPool     *ants.PoolWithFunc
	scopePool   *ants.PoolWithFunc
	handlerCh   chan *pkg.Baseline // 待处理的baseline
	checkCh     chan struct{}      // 独立的check管道， 防止与redirect/crawl冲突
	closed      bool
	wordOffset  int
	failedCount int32
	IsFailed    bool
	urls        sync.Map
	scopeurls   map[string]struct{}
	uniques     map[uint16]struct{}
	analyzeDone bool
	limiter     *rate.Limiter
	locker      sync.Mutex
	scopeLocker sync.Mutex
	initwg      sync.WaitGroup // 初始化用, 之后改成锁
}

func (pool *BrutePool) checkRedirect(redirectURL string) bool {
	if pool.random.RedirectURL == "" {
		// 如果random的redirectURL为空, 此时该项
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

func (pool *BrutePool) genReq(mod SprayMod, s string) (*ihttp.Request, error) {
	if mod == HostSpray {
		return ihttp.BuildHostRequest(pool.ClientType, pool.BaseURL, s)
	} else if mod == PathSpray {
		return ihttp.BuildPathRequest(pool.ClientType, pool.base, s)
	}
	return nil, fmt.Errorf("unknown mod")
}

func (pool *BrutePool) Init() error {
	pool.initwg.Add(2)
	if pool.Index != "/" {
		logs.Log.Logf(pkg.LogVerbose, "custom index url: %s", pkg.BaseURL(pool.url)+pkg.FormatURL(pkg.BaseURL(pool.url), pool.Index))
		pool.reqPool.Invoke(newUnit(pool.Index, parsers.InitIndexSource))
		//pool.urls[dir(pool.Index)] = struct{}{}
	} else {
		pool.reqPool.Invoke(newUnit(pool.url.Path, parsers.InitIndexSource))
		//pool.urls[dir(pool.url.Path)] = struct{}{}
	}

	if pool.Random != "" {
		logs.Log.Logf(pkg.LogVerbose, "custom random url: %s", pkg.BaseURL(pool.url)+pkg.FormatURL(pkg.BaseURL(pool.url), pool.Random))
		pool.reqPool.Invoke(newUnit(pool.Random, parsers.InitRandomSource))
	} else {
		pool.reqPool.Invoke(newUnit(pool.safePath(pkg.RandPath()), parsers.InitRandomSource))
	}

	pool.initwg.Wait()
	if pool.index.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf(pool.index.ErrString)
	}
	if pool.index.Chunked && pool.ClientType == ihttp.FAST {
		logs.Log.Warn("chunk encoding! buf current client FASTHTTP not support chunk decode")
	}
	logs.Log.Logf(pkg.LogVerbose, "[baseline.index] "+pool.index.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
	// 检测基本访问能力
	if pool.random.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf(pool.index.ErrString)
	}
	logs.Log.Logf(pkg.LogVerbose, "[baseline.random] "+pool.random.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))

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

func (pool *BrutePool) Upgrade(bl *pkg.Baseline) error {
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

func (pool *BrutePool) Run(offset, limit int) {
	pool.Worder.Run()
	if pool.Active {
		pool.wg.Add(1)
		go pool.doActive()
	}

	if pool.Bak {
		pool.wg.Add(1)
		go pool.doBak()
	}

	if pool.Common {
		pool.wg.Add(1)
		go pool.doCommonFile()
	}

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
		case w, ok := <-pool.Worder.C:
			if !ok {
				done = true
				continue
			}
			pool.Statistor.End++
			if w == "" {
				pool.Statistor.Skipped++
				continue
			}

			pool.wordOffset++
			if pool.wordOffset < offset {
				continue
			}

			if pool.Statistor.End > limit {
				done = true
				continue
			}

			pool.wg.Add(1)
			if pool.Mod == HostSpray {
				pool.reqPool.Invoke(newUnitWithNumber(w, parsers.WordSource, pool.wordOffset))
			} else {
				// 原样的目录拼接, 输入了几个"/"就是几个, 适配/有语义的中间件
				pool.reqPool.Invoke(newUnitWithNumber(pool.safePath(w), parsers.WordSource, pool.wordOffset))
			}

		case <-pool.checkCh:
			pool.Statistor.CheckNumber++
			if pool.Mod == HostSpray {
				pool.reqPool.Invoke(newUnitWithNumber(pkg.RandHost(), parsers.CheckSource, pool.wordOffset))
			} else if pool.Mod == PathSpray {
				pool.reqPool.Invoke(newUnitWithNumber(pool.safePath(pkg.RandPath()), parsers.CheckSource, pool.wordOffset))
			}
		case unit, ok := <-pool.additionCh:
			if !ok || pool.closed {
				continue
			}
			if _, ok := pool.urls.Load(unit.path); ok {
				logs.Log.Debugf("[%s] duplicate path: %s, skipped", unit.source.Name(), pool.base+unit.path)
				pool.wg.Done()
			} else {
				pool.urls.Store(unit.path, nil)
				unit.number = pool.wordOffset
				pool.reqPool.Invoke(unit)
			}
		case <-pool.closeCh:
			break Loop
		case <-pool.ctx.Done():
			break Loop
		case <-pool.ctx.Done():
			break Loop
		}
	}
	pool.closed = true
	pool.Close()
}

func (pool *BrutePool) Invoke(v interface{}) {
	if pool.RateLimit != 0 {
		pool.limiter.Wait(pool.ctx)
	}

	atomic.AddInt32(&pool.Statistor.ReqTotal, 1)
	unit := v.(*Unit)

	var req *ihttp.Request
	var err error
	if unit.source == parsers.WordSource {
		req, err = pool.genReq(pool.Mod, unit.path)
	} else {
		req, err = pool.genReq(PathSpray, unit.path)
	}

	if err != nil {
		logs.Log.Error(err.Error())
		return
	}

	req.SetHeaders(pool.Headers)
	req.SetHeader("User-Agent", pkg.RandomUA())

	start := time.Now()
	resp, reqerr := pool.client.Do(pool.ctx, req)
	if pool.ClientType == ihttp.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}

	// compare与各种错误处理
	var bl *pkg.Baseline
	if reqerr != nil && reqerr != fasthttp.ErrBodyTooLarge {
		atomic.AddInt32(&pool.failedCount, 1)
		atomic.AddInt32(&pool.Statistor.FailedNumber, 1)
		bl = &pkg.Baseline{
			SprayResult: &parsers.SprayResult{
				UrlString: pool.base + unit.path,
				ErrString: reqerr.Error(),
				Reason:    pkg.ErrRequestFailed.Error(),
			},
		}
		pool.FailedBaselines = append(pool.FailedBaselines, bl)
		// 自动重放失败请求
		pool.doRetry(bl)
	} else { // 特定场景优化
		if unit.source <= 3 || unit.source == parsers.CrawlSource || unit.source == parsers.CommonFileSource {
			// 一些高优先级的source, 将跳过PreCompare
			bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
		} else if pool.MatchExpr != nil {
			// 如果自定义了match函数, 则所有数据送入tempch中
			bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
		} else if err = pool.PreCompare(resp); err == nil {
			// 通过预对比跳过一些无用数据, 减少性能消耗
			bl = pkg.NewBaseline(req.URI(), req.Host(), resp)
		} else {
			bl = pkg.NewInvalidBaseline(req.URI(), req.Host(), resp, err.Error())
		}
	}

	// 手动处理重定向
	if bl.IsValid && unit.source != parsers.CheckSource && bl.RedirectURL != "" {
		//pool.wg.Add(1)
		pool.doRedirect(bl, unit.depth)
	}

	if !ihttp.CheckBodySize(int64(bl.BodyLength)) {
		bl.ExceedLength = true
	}
	bl.Source = unit.source
	bl.ReqDepth = unit.depth
	bl.Number = unit.number
	bl.Spended = time.Since(start).Milliseconds()
	switch unit.source {
	case parsers.InitRandomSource:
		bl.Collect()
		pool.locker.Lock()
		pool.random = bl
		pool.addFuzzyBaseline(bl)
		pool.locker.Unlock()
		pool.initwg.Done()
	case parsers.InitIndexSource:
		bl.Collect()
		pool.locker.Lock()
		pool.index = bl
		pool.locker.Unlock()
		if bl.Status == 200 || (bl.Status/100) == 3 {
			// 保留index输出结果
			pool.wg.Add(1)
			pool.doCrawl(bl)
			pool.putToOutput(bl)
		}
		pool.initwg.Done()
	case parsers.CheckSource:
		if bl.ErrString != "" {
			logs.Log.Warnf("[check.error] %s maybe ip had banned, break (%d/%d), error: %s", pool.BaseURL, pool.failedCount, pool.BreakThreshold, bl.ErrString)
		} else if i := pool.random.Compare(bl); i < 1 {
			if i == 0 {
				if pool.Fuzzy {
					logs.Log.Debug("[check.fuzzy] maybe trigger risk control, " + bl.String())
				}
			} else {
				atomic.AddInt32(&pool.failedCount, 1) //
				logs.Log.Debug("[check.failed] maybe trigger risk control, " + bl.String())
				pool.FailedBaselines = append(pool.FailedBaselines, bl)
			}
		} else {
			pool.resetFailed() // 如果后续访问正常, 重置错误次数
			logs.Log.Debug("[check.pass] " + bl.String())
		}

	case parsers.WordSource:
		// 异步进行性能消耗较大的深度对比
		pool.handlerCh <- bl
		if int(pool.Statistor.ReqTotal)%pool.CheckPeriod == 0 {
			pool.doCheck()
		} else if pool.failedCount%pool.ErrPeriod == 0 {
			atomic.AddInt32(&pool.failedCount, 1)
			pool.doCheck()
		}
		pool.Bar.Done()
	case parsers.RedirectSource:
		bl.FrontURL = unit.frontUrl
		pool.handlerCh <- bl
	default:
		pool.handlerCh <- bl
	}
}

func (pool *BrutePool) NoScopeInvoke(v interface{}) {
	defer pool.wg.Done()
	unit := v.(*Unit)
	req, err := ihttp.BuildPathRequest(pool.ClientType, unit.path, "")
	if err != nil {
		logs.Log.Error(err.Error())
		return
	}
	req.SetHeaders(pool.Headers)
	req.SetHeader("User-Agent", pkg.RandomUA())
	resp, reqerr := pool.client.Do(pool.ctx, req)
	if pool.ClientType == ihttp.FAST {
		defer fasthttp.ReleaseResponse(resp.FastResponse)
		defer fasthttp.ReleaseRequest(req.FastRequest)
	}
	if reqerr != nil {
		logs.Log.Error(reqerr.Error())
		return
	}
	if resp.StatusCode() == 200 {
		bl := pkg.NewBaseline(req.URI(), req.Host(), resp)
		bl.Source = unit.source
		bl.ReqDepth = unit.depth
		bl.Collect()
		bl.CollectURL()
		pool.wg.Add(1)
		pool.doScopeCrawl(bl)
		pool.putToOutput(bl)
	}
}

func (pool *BrutePool) Handler() {
	for bl := range pool.handlerCh {
		if bl.IsValid {
			pool.addFuzzyBaseline(bl)
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

		var params map[string]interface{}
		if pool.MatchExpr != nil || pool.FilterExpr != nil || pool.RecuExpr != nil {
			params = map[string]interface{}{
				"index":   pool.index,
				"random":  pool.random,
				"current": bl,
			}
			//for _, ok := range FuzzyStatus {
			//	if bl, ok := pool.baselines[ok]; ok {
			//		params["bl"+strconv.Itoa(ok)] = bl
			//	} else {
			//		params["bl"+strconv.Itoa(ok)] = nilBaseline
			//	}
			//}
		}

		var ok bool
		if pool.MatchExpr != nil {
			if pkg.CompareWithExpr(pool.MatchExpr, params) {
				ok = true
			}
		} else {
			ok = pool.BaseCompare(bl)
		}

		if ok {
			pool.Statistor.FoundNumber++

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

		if bl.IsValid || bl.IsFuzzy {
			pool.wg.Add(2)
			pool.doCrawl(bl)
			pool.doRule(bl)
			if iutils.IntsContains(pkg.WhiteStatus, bl.Status) || iutils.IntsContains(pkg.UniqueStatus, bl.Status) {
				pool.wg.Add(1)
				pool.doAppendWords(bl)
			}
		}

		// 如果要进行递归判断, 要满足 bl有效, mod为path-spray, 当前深度小于最大递归深度
		if bl.IsValid {
			if bl.RecuDepth < MaxRecursion {
				if pkg.CompareWithExpr(pool.RecuExpr, params) {
					bl.Recu = true
				}
			}
		}

		if !pool.closed {
			// 如果任务被取消, 所有还没处理的请求结果都会被丢弃
			pool.putToOutput(bl)
		}
		pool.wg.Done()
	}

	pool.analyzeDone = true
}

func (pool *BrutePool) PreCompare(resp *ihttp.Response) error {
	status := resp.StatusCode()
	if iutils.IntsContains(pkg.WhiteStatus, status) {
		// 如果为白名单状态码则直接返回
		return nil
	}
	if pool.random.Status != 200 && pool.random.Status == status {
		return pkg.ErrSameStatus
	}

	if iutils.IntsContains(pkg.BlackStatus, status) {
		return pkg.ErrBadStatus
	}

	if iutils.IntsContains(pkg.WAFStatus, status) {
		return pkg.ErrWaf
	}

	if !pool.checkRedirect(resp.GetHeader("Location")) {
		return pkg.ErrRedirect
	}

	return nil
}

func (pool *BrutePool) BaseCompare(bl *pkg.Baseline) bool {
	if !bl.IsValid {
		return false
	}
	var status = -1
	// 30x状态码的特殊处理
	if bl.RedirectURL != "" && strings.HasSuffix(bl.RedirectURL, bl.Url.Path+"/") {
		bl.Reason = pkg.ErrFuzzyRedirect.Error()
		pool.putToFuzzy(bl)
		return false
	}
	// 使用与baseline相同状态码, 需要在fuzzystatus中提前配置
	base, ok := pool.baselines[bl.Status] // 挑选对应状态码的baseline进行compare
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

	bl.Collect()

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

	if ok && status == 0 && base.FuzzyCompare(bl) {
		pool.Statistor.FuzzyNumber++
		bl.Reason = pkg.ErrFuzzyCompareFailed.Error()
		pool.putToFuzzy(bl)
		return false
	}

	return true
}

func (pool *BrutePool) doCheck() {
	if pool.failedCount > pool.BreakThreshold {
		// 当报错次数超过上限是, 结束任务
		pool.recover()
		pool.Cancel()
		pool.IsFailed = true
		return
	}

	if pool.Mod == HostSpray {
		pool.checkCh <- struct{}{}
	} else if pool.Mod == PathSpray {
		pool.checkCh <- struct{}{}
	}
}

func (pool *BrutePool) doCrawl(bl *pkg.Baseline) {
	if !pool.Crawl || bl.ReqDepth >= MaxCrawl {
		pool.wg.Done()
		return
	}
	bl.CollectURL()
	if bl.URLs == nil {
		pool.wg.Done()
		return
	}

	pool.wg.Add(1)
	pool.doScopeCrawl(bl)

	go func() {
		defer pool.wg.Done()
		for _, u := range bl.URLs {
			if u = pkg.FormatURL(bl.Url.Path, u); u == "" {
				continue
			}
			pool.addAddition(&Unit{
				path:   u,
				source: parsers.CrawlSource,
				depth:  bl.ReqDepth + 1,
			})
		}
	}()

}

func (pool *BrutePool) doScopeCrawl(bl *pkg.Baseline) {
	if bl.ReqDepth >= MaxCrawl {
		pool.wg.Done()
		return
	}

	go func() {
		defer pool.wg.Done()
		for _, u := range bl.URLs {
			if strings.HasPrefix(u, "http") {
				if v, _ := url.Parse(u); v == nil || !pkg.MatchWithGlobs(v.Host, pool.Scope) {
					continue
				}
				pool.scopeLocker.Lock()
				if _, ok := pool.scopeurls[u]; !ok {
					pool.urls.Store(u, nil)
					pool.wg.Add(1)
					pool.scopePool.Invoke(&Unit{path: u, source: parsers.CrawlSource, depth: bl.ReqDepth + 1})
				}
				pool.scopeLocker.Unlock()
			}
		}
	}()
}

func (pool *BrutePool) addFuzzyBaseline(bl *pkg.Baseline) {
	if _, ok := pool.baselines[bl.Status]; !ok && (EnableAllFuzzy || iutils.IntsContains(pkg.FuzzyStatus, bl.Status)) {
		bl.Collect()
		pool.wg.Add(1)
		pool.doCrawl(bl) // 非有效页面也可能存在一些特殊的url可以用来爬取
		pool.baselines[bl.Status] = bl
		logs.Log.Logf(pkg.LogVerbose, "[baseline.%dinit] %s", bl.Status, bl.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
	}
}

func (pool *BrutePool) doBak() {
	defer pool.wg.Done()
	worder, err := words.NewWorderWithDsl("{?0}.{@bak_ext}", [][]string{pkg.BakGenerator(pool.url.Host)}, nil)
	if err != nil {
		return
	}
	worder.Run()
	for w := range worder.C {
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: parsers.BakSource,
		})
	}

	worder, err = words.NewWorderWithDsl("{@bak_name}.{@bak_ext}", nil, nil)
	if err != nil {
		return
	}
	worder.Run()
	for w := range worder.C {
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: parsers.BakSource,
		})
	}
}

func (pool *BrutePool) recover() {
	logs.Log.Errorf("%s ,failed request exceeds the threshold , task will exit. Breakpoint %d", pool.BaseURL, pool.wordOffset)
	for i, bl := range pool.FailedBaselines {
		logs.Log.Errorf("[failed.%d] %s", i, bl.String())
	}
}

func (pool *BrutePool) Close() {
	for pool.analyzeDone {
		// 等待缓存的待处理任务完成
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	close(pool.additionCh) // 关闭addition管道
	close(pool.checkCh)    // 关闭check管道
	pool.Statistor.EndTime = time.Now().Unix()
	pool.Bar.Close()
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

func NewBaselines() *Baselines {
	return &Baselines{
		baselines: map[int]*pkg.Baseline{},
	}
}

type Baselines struct {
	FailedBaselines []*pkg.Baseline
	random          *pkg.Baseline
	index           *pkg.Baseline
	baselines       map[int]*pkg.Baseline
}
