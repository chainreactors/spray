package core

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/proxyclient"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/core/pool"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr/vm"
	"github.com/panjf2000/ants/v2"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var (
	MAX = 2147483647
)

type RunnerStats struct {
	Targets  int64
	Tasks    int64
	Requests int64
	Results  int64
	Errors   int64
}

type Runner struct {
	*Option

	taskCh   chan *Task
	poolwg   *sync.WaitGroup
	OutWg    *sync.WaitGroup
	OutputCh chan *baseline.Baseline
	FuzzyCh  chan *baseline.Baseline
	bar      *mpb.Bar
	bruteMod bool

	ProxyClient   proxyclient.Dial
	IsCheck       bool
	Pools         *ants.PoolWithFunc
	PoolName      map[string]bool
	Tasks         *TaskGenerator
	Rules         *rule.Program
	AppendRules   *rule.Program
	Headers       map[string]string
	Body          []byte
	FilterExpr    *vm.Program
	MatchExpr     *vm.Program
	RecursiveExpr *vm.Program
	OutputFile    *files.File
	//FuzzyFile     *files.File
	DumpFile    *files.File
	StatFile    *files.File
	Progress    *mpb.Progress
	Fns         []words.WordFunc
	Count       int // tasks total number
	Wordlist    []string
	AppendWords []string
	ClientType  int
	Probes      []string
	Total       int // wordlist total number
	Color       bool
	Jsonify     bool
	statsMu     sync.Mutex
	stats       RunnerStats
	outputMu    sync.Mutex
}

func (r *Runner) Stats() RunnerStats {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.stats
}

func (r *Runner) recordStat(stat *pkg.Statistor) {
	if stat == nil {
		return
	}

	targets := int64(1)
	if r.IsCheck {
		targets = int64(stat.Total)
	}

	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats.Targets += targets
	r.stats.Tasks += int64(stat.Total)
	r.stats.Requests += int64(stat.ReqTotal)
	r.stats.Results += int64(stat.FoundNumber)
	r.stats.Errors += int64(stat.FailedNumber)
}

func (r *Runner) PrepareConfig() *pool.Config {
	// 准备HTTP请求配置
	headers := make(http.Header)
	for k, v := range r.Headers {
		headers.Set(k, v)
	}

	if r.ClientType != ihttp.REQ && headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", pkg.DefaultUserAgent)
	}

	if r.ClientType != ihttp.REQ && headers.Get("Accept") == "" {
		headers.Set("Accept", "*/*")
	}

	requestConfig := &ihttp.RequestConfig{
		Method:          r.Method,
		Headers:         headers,
		Host:            r.Host,
		Path:            r.Path,
		Body:            r.Body,
		RandomUserAgent: r.RandomUserAgent,
	}

	config := &pool.Config{
		Thread:         r.Threads,
		Timeout:        time.Duration(r.Timeout) * time.Second,
		RateLimit:      r.RateLimit,
		Mod:            pool.ModMap[r.Mod],
		Request:        requestConfig,
		OutputCh:       r.OutputCh,
		FuzzyCh:        r.FuzzyCh,
		Outwg:          r.OutWg,
		Fuzzy:          r.Fuzzy,
		CheckPeriod:    r.CheckPeriod,
		ErrPeriod:      int32(r.ErrPeriod),
		BreakThreshold: int32(r.BreakThreshold),
		MatchExpr:      r.MatchExpr,
		FilterExpr:     r.FilterExpr,
		RecuExpr:       r.RecursiveExpr,
		AppendRule:     r.AppendRules, // 对有效目录追加规则, 根据rule生成
		AppendWords:    r.AppendWords, // 对有效目录追加字典
		Fns:            r.Fns,
		//IgnoreWaf:       r.IgnoreWaf,
		Crawl:             r.CrawlPlugin,
		Scope:             r.Scope,
		Active:            r.Finger,
		Bak:               r.BakPlugin,
		Fuzzuli:           r.FuzzuliPlugin,
		Common:            r.CommonPlugin,
		Poc:               r.PocPlugin,
		RetryLimit:        r.RetryCount,
		ClientType:        r.ClientType,
		ClientFingerprint: r.ClientFingerprint,
		Random:            r.Random,
		Index:             r.Index,
		MaxRecursionDepth: r.Depth,
		MaxRedirect:       3,
		MaxAppendDepth:    r.AppendDepth,
		MaxCrawlDepth:     r.CrawlDepth,
		ProxyClient:       r.ProxyClient,
	}

	if config.ClientType == ihttp.Auto {
		if config.Mod == pool.PathSpray {
			config.ClientType = ihttp.FAST
		} else if config.Mod == pool.HostSpray {
			config.ClientType = ihttp.STANDARD
		}
	}

	return config
}

func (r *Runner) AppendFunction(fn func(string) []string) {
	r.Fns = append(r.Fns, fn)
}

func (r *Runner) Prepare(ctx context.Context) error {
	if r.bruteMod {
		r.IsCheck = false
	}
	r.OutputHandler()
	return nil
}

func (r *Runner) CloseFiles() {
	if r.OutputFile != nil {
		r.OutputFile.Close()
		r.OutputFile = nil
	}
	if r.DumpFile != nil {
		r.DumpFile.Close()
		r.DumpFile = nil
	}
	if r.StatFile != nil {
		r.StatFile.Close()
		r.StatFile = nil
	}
}

func (r *Runner) RunWithBrute(ctx context.Context) {
	go func() {
		defer close(r.taskCh)
		for t := range r.Tasks.tasks {
			select {
			case r.taskCh <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	if r.Count > 0 {
		r.newBar(r.Count)
	}
	var err error
	poolSize := r.PoolSize
	if poolSize <= 0 {
		poolSize = 1
	}

	r.Pools, err = ants.NewPoolWithFunc(poolSize, func(i interface{}) {
		t := i.(*Task)
		if t.origin != nil && t.origin.End == t.origin.Total {
			r.saveStat(t.origin.Json())
			r.Done()
			return
		}
		config := r.PrepareConfig()
		config.BaseURL = t.baseUrl

		brutePool, err := pool.NewBrutePool(ctx, config)
		if err != nil {
			logs.Log.Error(err.Error())
			r.Done()
			return
		}
		if t.origin != nil && len(r.Wordlist) == 0 {
			// 如果是从断点续传中恢复的任务, 则自动设置word,dict与rule, 不过优先级低于命令行参数
			brutePool.Statistor = pkg.NewStatistorFromStat(t.origin.Statistor)
			brutePool.Worder, err = t.origin.InitWorder(r.Fns)
			if err != nil {
				logs.Log.Error(err.Error())
				r.Done()
				return
			}
			brutePool.Statistor.Total = t.origin.sum
		} else {
			brutePool.Statistor = r.Option.NewStatistor(t.baseUrl, r.Total)
			brutePool.Worder = words.NewWorderWithList(r.Wordlist)
			brutePool.Worder.Fns = r.Fns
			brutePool.Worder.Rules = r.Rules.Expressions
		}

		var limit int
		if brutePool.Statistor.Total > r.Limit && r.Limit != 0 {
			limit = r.Limit
		} else {
			limit = brutePool.Statistor.Total
		}
		brutePool.Bar = pkg.NewBar(config.BaseURL, limit-brutePool.Statistor.Offset, brutePool.Statistor, r.Progress)
		logs.Log.Importantf("[pool] task: %s, total %d words, %d threads, proxy: %v",
			brutePool.BaseURL, limit-brutePool.Statistor.Offset, brutePool.Thread, r.Proxies)
		err = brutePool.Init()
		if err != nil {
			brutePool.Statistor.Error = err.Error()
			// Init 失败说明对比所需的基线不可用.
			// --force 只关闭运行期错误阈值, 不能继续运行半初始化的 pool.
			brutePool.Bar.Close()
			brutePool.Close()
			r.PrintStat(brutePool)
			r.Done()
			return
		}

		brutePool.Run(brutePool.Statistor.Offset, limit)

		if brutePool.IsFailed && len(brutePool.FailedBaselines) > 0 {
			// 如果因为错误积累退出, end将指向第一个错误发生时, 防止resume时跳过大量目标
			brutePool.Statistor.End = brutePool.FailedBaselines[0].Number
		}
		r.PrintStat(brutePool)
		r.Done()
	})

	if err != nil {
		logs.Log.Error(err.Error())
		return
	}
	// r.Pools 内部有 ticktock / purgeStaleWorkers 后台 goroutine,
	// 必须 Release 才能回收, 否则 SDK 多次 Execute 会泄露.
	defer func() {
		r.Pools.Release()
		r.Pools = nil
	}()

Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case t, ok := <-r.taskCh:
			if !ok {
				break Loop
			}
			r.AddPool(t)
		}
	}

	if r.bar != nil {
		r.bar.Wait()
	}
	r.poolwg.Wait()
	r.OutWg.Wait()

	close(r.OutputCh)
	close(r.FuzzyCh)
}

func (r *Runner) RunWithCheck(ctx context.Context) {
	// 仅check, 类似httpx
	var err error
	r.Pools, err = ants.NewPoolWithFunc(1, func(i interface{}) {
		config := r.PrepareConfig()

		checkPool, err := pool.NewCheckPool(ctx, config)
		if err != nil {
			logs.Log.Error(err.Error())
			checkPool.Cancel()
			r.poolwg.Done()
			return
		}

		ch := make(chan string)
		var tasks []*Task
		go func() {
			for t := range r.Tasks.tasks {
				ch <- t.baseUrl
				tasks = append(tasks, t)
			}
			close(ch)
		}()
		checkPool.Worder = words.NewWorderWithChan(ch)
		checkPool.Worder.Fns = r.Fns
		checkPool.Bar = pkg.NewBar("check", r.Count-r.Offset, checkPool.Statistor, r.Progress)
		checkPool.Run(ctx, r.Offset, r.Count)

		// 保存 check 模式的统计信息
		checkPool.Statistor.EndTime = time.Now().Unix()
		checkPool.Statistor.End = r.Count
		checkPool.Statistor.Total = r.Count
		checkPool.Statistor.BaseUrl = r.Tasks.Name
		checkPool.Statistor.ReqTotal = int32(checkPool.RequestCount())
		checkPool.Statistor.FailedNumber = int32(checkPool.FailedCount())
		if r.Color {
			logs.Log.Important(checkPool.Statistor.ColorString())
		} else {
			logs.Log.Important(checkPool.Statistor.String())
		}
		r.saveStat(checkPool.Statistor.Json())
		r.recordStat(checkPool.Statistor)

		r.poolwg.Done()
	})

	// r.Pools 内部有 ticktock / purgeStaleWorkers 后台 goroutine,
	// 必须 Release 才能回收, 否则 SDK 多次 Execute 会泄露.
	defer func() {
		r.Pools.Release()
		r.Pools = nil
	}()

	// 缓冲 1: ctx 先取消时主循环走 ctx.Done 分支退出, 这个 goroutine 不能阻塞在 send.
	stopCh := make(chan struct{}, 1)
	r.poolwg.Add(1)
	err = r.Pools.Invoke(struct{}{})
	if err != nil {
		return
	}
	go func() {
		r.poolwg.Wait()
		stopCh <- struct{}{}
	}()

Loop:
	for {
		select {
		case <-ctx.Done():
			logs.Log.Error("cancel with deadline")
			break Loop
		case <-stopCh:
			break Loop
		}
	}

	r.poolwg.Wait()
	r.OutWg.Wait()

	// 关闭 OutputCh，通知所有监听者没有更多结果了
	close(r.OutputCh)
	close(r.FuzzyCh)
}

func (r *Runner) AddRecursive(bl *baseline.Baseline) {
	// 递归新任务
	task := &Task{
		baseUrl: bl.UrlString,
		depth:   bl.RecuDepth + 1,
		origin:  NewOrigin(r.Option.NewStatistor(bl.UrlString, 0)),
	}

	r.AddPool(task)
}

func (r *Runner) AddPool(task *Task) {
	if _, ok := r.PoolName[task.baseUrl]; ok {
		logs.Log.Importantf("already added pool, skip %s", task.baseUrl)
		return
	}
	task.depth++
	r.poolwg.Add(1)
	if err := r.Pools.Invoke(task); err != nil {
		r.poolwg.Done()
		logs.Log.Errorf("submit pool task: %v", err)
	}
}

func (r *Runner) newBar(total int) {
	if r.Progress == nil {
		return
	}

	prompt := "total progressive:"
	r.bar = r.Progress.AddBar(int64(total),
		mpb.BarFillerClearOnComplete(), // 可选：当进度条完成时清除
		mpb.PrependDecorators(
			// 显示自定义的信息，比如下载速度和进度
			decor.Name(prompt, decor.WC{W: len(prompt) + 1, C: decor.DindentRight}), // 这里调整了装饰器的参数
			decor.OnComplete( // 当进度完成时显示的文本
				decor.Counters(0, "% d/% d"), " done!",
			),
		),
		mpb.AppendDecorators(
			// 显示经过的时间
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 4}),
		),
	)
}

func (r *Runner) Done() {
	if r.bar != nil {
		r.bar.Increment()
	}
	r.poolwg.Done()
}

func (r *Runner) PrintStat(pool *pool.BrutePool) {
	if r.Color {
		logs.Log.Important(pool.Statistor.ColorString())
		if pool.Statistor.Error == "" {
			logs.Log.Log(pkg.LogVerbose, pool.Statistor.ColorCountString())
			logs.Log.Log(pkg.LogVerbose, pool.Statistor.ColorSourceString())
		}
	} else {
		logs.Log.Important(pool.Statistor.String())
		if pool.Statistor.Error == "" {
			logs.Log.Log(pkg.LogVerbose, pool.Statistor.CountString())
			logs.Log.Log(pkg.LogVerbose, pool.Statistor.SourceString())
		}
	}

	r.saveStat(pool.Statistor.Json())
	r.recordStat(pool.Statistor)
}

func (r *Runner) saveStat(content string) {
	if r.StatFile != nil {
		r.StatFile.SafeWrite(content)
		r.StatFile.SafeSync()
	}
}

func (r *Runner) Output(bl *baseline.Baseline) {
	r.outputMu.Lock()
	defer r.outputMu.Unlock()

	var out string
	if r.Option.Json {
		out = bl.ToJson()
	} else if len(r.Probes) > 0 {
		out = bl.ProbeOutput(r.Probes)
	} else if r.Color {
		out = bl.ColorString()
	} else {
		out = bl.String()
	}

	quiet := r.Option != nil && r.Option.Quiet
	if !quiet {
		if bl.IsValid {
			logs.Log.Console(out + "\n")
		} else if r.Fuzzy && bl.IsFuzzy {
			logs.Log.Console("[fuzzy] " + out + "\n")
		}
	}

	if r.OutputFile != nil {
		if r.FileOutput == "json" {
			r.OutputFile.SafeWrite(bl.ToJson() + "\n")
		} else if r.FileOutput == "csv" {
			r.OutputFile.SafeWrite(bl.ToCSV())
		} else if r.FileOutput == "full" {
			r.OutputFile.SafeWrite(bl.String() + "\n")
		} else {
			r.OutputFile.SafeWrite(bl.ProbeOutput(strings.Split(r.FileOutput, ",")) + "\n")
		}

		r.OutputFile.SafeSync()
	}
}

func (r *Runner) OutputHandler() {
	go func() {
		for {
			select {
			case bl, ok := <-r.OutputCh:
				if !ok {
					return
				}
				if r.DumpFile != nil {
					r.DumpFile.SafeWrite(bl.ToJson() + "\n")
					r.DumpFile.SafeSync()
				}
				if bl.IsValid {
					r.Output(bl)
					if bl.Recu {
						r.AddRecursive(bl)
					}
				} else {
					if r.Color {
						logs.Log.Debug(bl.ColorString())
					} else {
						logs.Log.Debug(bl.String())
					}
				}
				r.OutWg.Done()
			}
		}
	}()

	go func() {
		for {
			select {
			case bl, ok := <-r.FuzzyCh:
				if !ok {
					return
				}
				if r.Fuzzy {
					r.Output(bl)
				}
				r.OutWg.Done()
			}
		}
	}()
}
