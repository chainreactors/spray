package internal

import (
	"context"
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/mask"
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
	max             = 2147483647
	MaxRedirect     = 3
	MaxCrawl        = 3
	MaxRecursion    = 0
	enableAllFuzzy  = false
	enableAllUnique = false
	nilBaseline     = &pkg.Baseline{}
)

func NewPool(ctx context.Context, config *pkg.Config) (*Pool, error) {
	var u *url.URL
	var err error
	if u, err = url.Parse(config.BaseURL); err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(ctx)
	pool := &Pool{
		Config:      config,
		base:        u.Scheme + "://" + u.Host,
		isDir:       strings.HasSuffix(u.Path, "/"),
		url:         u,
		ctx:         pctx,
		cancel:      cancel,
		client:      ihttp.NewClient(config.Thread, 2, config.ClientType),
		baselines:   make(map[int]*pkg.Baseline),
		urls:        make(map[string]struct{}),
		scopeurls:   make(map[string]struct{}),
		uniques:     make(map[uint16]struct{}),
		tempCh:      make(chan *pkg.Baseline, 100),
		checkCh:     make(chan int, 100),
		additionCh:  make(chan *Unit, 100),
		closeCh:     make(chan struct{}),
		waiter:      sync.WaitGroup{},
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
		pool.dir = Dir(pool.url.Path)
	}

	pool.reqPool, _ = ants.NewPoolWithFunc(config.Thread, pool.Invoke)
	pool.scopePool, _ = ants.NewPoolWithFunc(config.Thread, pool.NoScopeInvoke)

	// 挂起一个异步的处理结果线程, 不干扰主线程的请求并发
	go pool.Handler()
	return pool, nil
}

type Pool struct {
	*pkg.Config            // read only
	base            string // url的根目录, 在爬虫或者redirect时, 会需要用到根目录进行拼接
	dir             string
	isDir           bool
	url             *url.URL
	Statistor       *pkg.Statistor
	client          *ihttp.Client
	reqPool         *ants.PoolWithFunc
	scopePool       *ants.PoolWithFunc
	bar             *pkg.Bar
	ctx             context.Context
	cancel          context.CancelFunc
	tempCh          chan *pkg.Baseline // 待处理的baseline
	checkCh         chan int           // 独立的check管道， 防止与redirect/crawl冲突
	additionCh      chan *Unit         // 插件添加的任务, 待处理管道
	closeCh         chan struct{}
	closed          bool
	wordOffset      int
	failedCount     int32
	isFailed        bool
	failedBaselines []*pkg.Baseline
	random          *pkg.Baseline
	index           *pkg.Baseline
	baselines       map[int]*pkg.Baseline
	urls            map[string]struct{}
	scopeurls       map[string]struct{}
	uniques         map[uint16]struct{}
	analyzeDone     bool
	worder          *words.Worder
	limiter         *rate.Limiter
	locker          sync.Mutex
	scopeLocker     sync.Mutex
	waiter          sync.WaitGroup
	initwg          sync.WaitGroup // 初始化用, 之后改成锁
}

func (pool *Pool) checkRedirect(redirectURL string) bool {
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

func (pool *Pool) genReq(mod pkg.SprayMod, s string) (*ihttp.Request, error) {
	if mod == pkg.HostSpray {
		return ihttp.BuildHostRequest(pool.ClientType, pool.BaseURL, s)
	} else if mod == pkg.PathSpray {
		return ihttp.BuildPathRequest(pool.ClientType, pool.base, s)
	}
	return nil, fmt.Errorf("unknown mod")
}

func (pool *Pool) Init() error {
	// 分成两步是为了避免闭包的线程安全问题
	pool.initwg.Add(2)
	pool.reqPool.Invoke(newUnit(pool.url.Path, InitIndexSource))
	pool.reqPool.Invoke(newUnit(pool.safePath(pkg.RandPath()), InitRandomSource))
	pool.initwg.Wait()
	if pool.index.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf(pool.index.ErrString)
	}
	if pool.index.Chunked && pool.ClientType == ihttp.FAST {
		logs.Log.Warn("chunk encoding! buf current client FASTHTTP not support chunk decode")
	}
	logs.Log.Info("[baseline.index] " + pool.index.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
	// 检测基本访问能力
	if pool.random.ErrString != "" {
		logs.Log.Error(pool.index.String())
		return fmt.Errorf(pool.index.ErrString)
	}
	logs.Log.Info("[baseline.random] " + pool.random.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))

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

func (pool *Pool) Run(offset, limit int) {
	pool.worder.RunWithRules()
	if pool.Active {
		pool.waiter.Add(1)
		go pool.doActive()
	}

	if pool.Bak {
		pool.waiter.Add(1)
		go pool.doBak()
	}

	if pool.Common {
		pool.waiter.Add(1)
		go pool.doCommonFile()
	}

	var done bool
	// 挂起一个监控goroutine, 每100ms判断一次done, 如果已经done, 则关闭closeCh, 然后通过Loop中的select case closeCh去break, 实现退出
	go func() {
		for {
			if done {
				pool.waiter.Wait()
				close(pool.closeCh)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

Loop:
	for {
		select {
		case w, ok := <-pool.worder.C:
			if !ok {
				done = true
				continue
			}
			pool.Statistor.End++
			pool.wordOffset++
			if pool.wordOffset < offset {
				continue
			}

			if pool.Statistor.End > limit {
				done = true
				continue
			}

			pool.waiter.Add(1)
			if pool.Mod == pkg.HostSpray {
				pool.reqPool.Invoke(newUnitWithNumber(w, WordSource, pool.wordOffset))
			} else {
				// 原样的目录拼接, 输入了几个"/"就是几个, 适配/有语义的中间件
				pool.reqPool.Invoke(newUnitWithNumber(pool.safePath(w), WordSource, pool.wordOffset))
			}

		case source := <-pool.checkCh:
			pool.Statistor.CheckNumber++
			if pool.Mod == pkg.HostSpray {
				pool.reqPool.Invoke(newUnitWithNumber(pkg.RandHost(), source, pool.wordOffset))
			} else if pool.Mod == pkg.PathSpray {
				pool.reqPool.Invoke(newUnitWithNumber(pool.safePath(pkg.RandPath()), source, pool.wordOffset))
			}
		case unit, ok := <-pool.additionCh:
			if !ok || pool.closed {
				continue
			}
			if _, ok := pool.urls[unit.path]; ok {
				logs.Log.Debugf("[%s] duplicate path: %s, skipped", parsers.GetSpraySourceName(unit.source), pool.base+unit.path)
				pool.waiter.Done()
			} else {
				pool.urls[unit.path] = struct{}{}
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

func (pool *Pool) Invoke(v interface{}) {
	if pool.RateLimit != 0 {
		pool.limiter.Wait(pool.ctx)
	}

	atomic.AddInt32(&pool.Statistor.ReqTotal, 1)
	unit := v.(*Unit)

	var req *ihttp.Request
	var err error
	if unit.source == WordSource {
		req, err = pool.genReq(pool.Mod, unit.path)
	} else {
		req, err = pool.genReq(pkg.PathSpray, unit.path)
	}

	if err != nil {
		logs.Log.Error(err.Error())
		return
	}

	req.SetHeaders(pool.Headers)
	req.SetHeader("User-Agent", RandomUA())

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
				IsValid:   false,
				ErrString: reqerr.Error(),
				Reason:    ErrRequestFailed.Error(),
			},
		}
		pool.failedBaselines = append(pool.failedBaselines, bl)
	} else {
		if unit.source <= 3 || unit.source == CrawlSource || unit.source == CommonFileSource {
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
	if bl.IsValid && unit.source != CheckSource && bl.RedirectURL != "" {
		//pool.waiter.Add(1)
		pool.doRedirect(bl, unit.depth)
	}

	if ihttp.DefaultMaxBodySize != 0 && bl.BodyLength > ihttp.DefaultMaxBodySize {
		bl.ExceedLength = true
	}
	bl.Source = unit.source
	bl.ReqDepth = unit.depth
	bl.Number = unit.number
	bl.Spended = time.Since(start).Milliseconds()
	switch unit.source {
	case InitRandomSource:
		bl.Collect()
		pool.locker.Lock()
		pool.random = bl
		pool.addFuzzyBaseline(bl)
		pool.locker.Unlock()
		pool.initwg.Done()
	case InitIndexSource:
		bl.Collect()
		pool.locker.Lock()
		pool.index = bl
		pool.locker.Unlock()
		if bl.Status == 200 || (bl.Status/100) == 3 {
			// 保留index输出结果
			pool.waiter.Add(1)
			pool.doCrawl(bl)
			pool.OutputCh <- bl
		}
		pool.initwg.Done()
	case CheckSource:
		if bl.ErrString != "" {
			logs.Log.Warnf("[check.error] %s maybe ip had banned, break (%d/%d), error: %s", pool.BaseURL, pool.failedCount, pool.BreakThreshold, bl.ErrString)
		} else if i := pool.random.Compare(bl); i < 1 {
			if i == 0 {
				if pool.Fuzzy {
					logs.Log.Warn("[check.fuzzy] maybe trigger risk control, " + bl.String())
				}
			} else {
				atomic.AddInt32(&pool.failedCount, 1) //
				logs.Log.Warn("[check.failed] maybe trigger risk control, " + bl.String())
				pool.failedBaselines = append(pool.failedBaselines, bl)
			}
		} else {
			pool.resetFailed() // 如果后续访问正常, 重置错误次数
			logs.Log.Debug("[check.pass] " + bl.String())
		}

	case WordSource:
		// 异步进行性能消耗较大的深度对比
		pool.tempCh <- bl
		if int(pool.Statistor.ReqTotal)%pool.CheckPeriod == 0 {
			pool.doCheck()
		} else if pool.failedCount%pool.ErrPeriod == 0 {
			atomic.AddInt32(&pool.failedCount, 1)
			pool.doCheck()
		}
		pool.bar.Done()
	case RedirectSource:
		bl.FrontURL = unit.frontUrl
		pool.tempCh <- bl
	default:
		pool.tempCh <- bl
	}
}

func (pool *Pool) NoScopeInvoke(v interface{}) {
	defer pool.waiter.Done()
	unit := v.(*Unit)
	req, err := ihttp.BuildPathRequest(pool.ClientType, unit.path, "")
	if err != nil {
		logs.Log.Error(err.Error())
		return
	}
	req.SetHeaders(pool.Headers)
	req.SetHeader("User-Agent", RandomUA())
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
		pool.waiter.Add(1)
		pool.doScopeCrawl(bl)
		pool.OutputCh <- bl
	}
}

func (pool *Pool) Handler() {
	for bl := range pool.tempCh {
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
			//for _, status := range FuzzyStatus {
			//	if bl, ok := pool.baselines[status]; ok {
			//		params["bl"+strconv.Itoa(status)] = bl
			//	} else {
			//		params["bl"+strconv.Itoa(status)] = nilBaseline
			//	}
			//}
		}

		var status bool
		if pool.MatchExpr != nil {
			if CompareWithExpr(pool.MatchExpr, params) {
				status = true
			}
		} else {
			status = pool.BaseCompare(bl)
		}

		if status {
			pool.Statistor.FoundNumber++

			// unique判断
			if enableAllUnique || iutils.IntsContains(UniqueStatus, bl.Status) {
				if _, ok := pool.uniques[bl.Unique]; ok {
					bl.IsValid = false
					bl.IsFuzzy = true
					bl.Reason = ErrFuzzyNotUnique.Error()
				} else {
					pool.uniques[bl.Unique] = struct{}{}
				}
			}

			// 对通过所有对比的有效数据进行再次filter
			if bl.IsValid && pool.FilterExpr != nil && CompareWithExpr(pool.FilterExpr, params) {
				pool.Statistor.FilteredNumber++
				bl.Reason = ErrCustomFilter.Error()
				bl.IsValid = false
			}
		} else {
			bl.IsValid = false
		}

		if bl.IsValid || bl.IsFuzzy {
			pool.waiter.Add(2)
			pool.doCrawl(bl)
			pool.doRule(bl)
		}
		// 如果要进行递归判断, 要满足 bl有效, mod为path-spray, 当前深度小于最大递归深度
		if bl.IsValid {
			if bl.RecuDepth < MaxRecursion {
				if CompareWithExpr(pool.RecuExpr, params) {
					bl.Recu = true
				}
			}
		}

		if !pool.closed {
			// 如果任务被取消, 所有还没处理的请求结果都会被丢弃
			pool.OutputCh <- bl
		}
		pool.waiter.Done()
	}

	pool.analyzeDone = true
}

func (pool *Pool) PreCompare(resp *ihttp.Response) error {
	status := resp.StatusCode()
	if iutils.IntsContains(WhiteStatus, status) {
		// 如果为白名单状态码则直接返回
		return nil
	}
	if pool.random.Status != 200 && pool.random.Status == status {
		return ErrSameStatus
	}

	if iutils.IntsContains(BlackStatus, status) {
		return ErrBadStatus
	}

	if iutils.IntsContains(WAFStatus, status) {
		return ErrWaf
	}

	if !pool.checkRedirect(resp.GetHeader("Location")) {
		return ErrRedirect
	}

	return nil
}

func (pool *Pool) BaseCompare(bl *pkg.Baseline) bool {
	if !bl.IsValid {
		return false
	}
	var status = -1
	// 30x状态码的特殊处理
	if bl.RedirectURL != "" && strings.HasSuffix(bl.RedirectURL, bl.Url.Path+"/") {
		bl.Reason = ErrFuzzyRedirect.Error()
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
			bl.Reason = ErrCompareFailed.Error()
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
		bl.Reason = ErrFuzzyCompareFailed.Error()
		pool.putToFuzzy(bl)
		return false
	}

	return true
}

func (pool *Pool) Upgrade(bl *pkg.Baseline) error {
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

func (pool *Pool) doRedirect(bl *pkg.Baseline, depth int) {
	if depth >= MaxRedirect {
		return
	}
	reURL := FormatURL(bl.Url.Path, bl.RedirectURL)

	pool.waiter.Add(1)
	go func() {
		pool.addAddition(&Unit{
			path:     reURL,
			source:   RedirectSource,
			frontUrl: bl.UrlString,
			depth:    depth + 1,
		})
	}()
}

func (pool *Pool) doCrawl(bl *pkg.Baseline) {
	if !pool.Crawl || bl.ReqDepth >= MaxCrawl {
		pool.waiter.Done()
		return
	}
	bl.CollectURL()
	if bl.URLs == nil {
		pool.waiter.Done()
		return
	}

	pool.waiter.Add(1)
	pool.doScopeCrawl(bl)

	go func() {
		defer pool.waiter.Done()
		for _, u := range bl.URLs {
			if u = FormatURL(bl.Url.Path, u); u == "" {
				continue
			}
			pool.waiter.Add(1)
			pool.addAddition(&Unit{
				path:   u,
				source: CrawlSource,
				depth:  bl.ReqDepth + 1,
			})
		}
	}()

}

func (pool *Pool) doScopeCrawl(bl *pkg.Baseline) {
	if bl.ReqDepth >= MaxCrawl {
		pool.waiter.Done()
		return
	}

	go func() {
		defer pool.waiter.Done()
		for _, u := range bl.URLs {
			if strings.HasPrefix(u, "http") {
				if v, _ := url.Parse(u); v == nil || !MatchWithGlobs(v.Host, pool.Scope) {
					continue
				}
				pool.scopeLocker.Lock()
				if _, ok := pool.scopeurls[u]; !ok {
					pool.urls[u] = struct{}{}
					pool.waiter.Add(1)
					pool.scopePool.Invoke(&Unit{path: u, source: CrawlSource, depth: bl.ReqDepth + 1})
				}
				pool.scopeLocker.Unlock()
			}
		}
	}()
}

func (pool *Pool) doRule(bl *pkg.Baseline) {
	if pool.AppendRule == nil {
		pool.waiter.Done()
		return
	}
	if bl.Source == RuleSource {
		pool.waiter.Done()
		return
	}

	go func() {
		defer pool.waiter.Done()
		for u := range rule.RunAsStream(pool.AppendRule.Expressions, path.Base(bl.Path)) {
			pool.waiter.Add(1)
			pool.addAddition(&Unit{
				path:   Dir(bl.Url.Path) + u,
				source: RuleSource,
			})
		}
	}()
}

func (pool *Pool) doActive() {
	defer pool.waiter.Done()
	for _, u := range pkg.ActivePath {
		pool.waiter.Add(1)
		pool.addAddition(&Unit{
			path:   pool.dir + u[1:],
			source: ActiveSource,
		})
	}
}

func (pool *Pool) doBak() {
	defer pool.waiter.Done()
	worder, err := words.NewWorderWithDsl("{?0}.{@bak_ext}", [][]string{pkg.BakGenerator(pool.url.Host)}, nil)
	if err != nil {
		return
	}
	worder.Run()
	for w := range worder.C {
		pool.waiter.Add(1)
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: BakSource,
		})
	}

	worder, err = words.NewWorderWithDsl("{@bak_name}.{@bak_ext}", nil, nil)
	if err != nil {
		return
	}
	worder.Run()
	for w := range worder.C {
		pool.waiter.Add(1)
		pool.addAddition(&Unit{
			path:   pool.dir + w,
			source: BakSource,
		})
	}
}

func (pool *Pool) doCommonFile() {
	defer pool.waiter.Done()
	for _, u := range mask.SpecialWords["common_file"] {
		pool.waiter.Add(1)
		pool.addAddition(&Unit{
			path:   pool.dir + u,
			source: CommonFileSource,
		})
	}
}

func (pool *Pool) doCheck() {
	if pool.failedCount > pool.BreakThreshold {
		// 当报错次数超过上限是, 结束任务
		pool.recover()
		pool.cancel()
		pool.isFailed = true
		return
	}

	if pool.Mod == pkg.HostSpray {
		pool.checkCh <- CheckSource
	} else if pool.Mod == pkg.PathSpray {
		pool.checkCh <- CheckSource
	}
}

func (pool *Pool) addAddition(u *Unit) {
	// 强行屏蔽报错, 防止goroutine泄露
	defer func() {
		if err := recover(); err != nil {
		}
	}()
	pool.additionCh <- u
}

func (pool *Pool) addFuzzyBaseline(bl *pkg.Baseline) {
	if _, ok := pool.baselines[bl.Status]; !ok && (enableAllFuzzy || iutils.IntsContains(FuzzyStatus, bl.Status)) {
		bl.Collect()
		pool.waiter.Add(1)
		pool.doCrawl(bl) // 非有效页面也可能存在一些特殊的url可以用来爬取
		pool.baselines[bl.Status] = bl
		logs.Log.Infof("[baseline.%dinit] %s", bl.Status, bl.Format([]string{"status", "length", "spend", "title", "frame", "redirect"}))
	}
}

func (pool *Pool) putToInvalid(bl *pkg.Baseline, reason string) {
	bl.IsValid = false
	pool.OutputCh <- bl
}

func (pool *Pool) putToFuzzy(bl *pkg.Baseline) {
	bl.IsFuzzy = true
	pool.FuzzyCh <- bl
}

func (pool *Pool) resetFailed() {
	pool.failedCount = 1
	pool.failedBaselines = nil
}

func (pool *Pool) recover() {
	logs.Log.Errorf("%s ,failed request exceeds the threshold , task will exit. Breakpoint %d", pool.BaseURL, pool.wordOffset)
	for i, bl := range pool.failedBaselines {
		logs.Log.Errorf("[failed.%d] %s", i, bl.String())
	}
}

func (pool *Pool) Close() {
	for pool.analyzeDone {
		// 等待缓存的待处理任务完成
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	close(pool.additionCh) // 关闭addition管道
	close(pool.checkCh)    // 关闭check管道
	pool.Statistor.EndTime = time.Now().Unix()
	pool.bar.Close()
}

func (pool *Pool) safePath(u string) string {
	// 自动生成的目录将采用safepath的方式拼接到相对目录中, 避免出现//的情况. 例如init, check, common
	hasSlash := strings.HasPrefix(u, "/")
	if hasSlash {
		if pool.isDir {
			return pool.dir + u[1:]
		} else {
			return pool.url.Path + u
		}
	} else {
		if pool.isDir {
			return pool.url.Path + u
		} else {
			return pool.url.Path + "/" + u
		}
	}
}
