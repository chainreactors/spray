package internal

import (
	"context"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/internal/ihttp"
	"github.com/chainreactors/spray/internal/pool"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
	"github.com/expr-lang/expr/vm"
	"github.com/panjf2000/ants/v2"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"sync"
	"time"
)

var (
	MAX = 2147483647
)

var (
	dictCache     = make(map[string][]string)
	wordlistCache = make(map[string][]string)
	ruleCache     = make(map[string][]rule.Expression)
)

type Runner struct {
	*Option

	taskCh        chan *Task
	poolwg        sync.WaitGroup
	outwg         *sync.WaitGroup
	outputCh      chan *pkg.Baseline
	fuzzyCh       chan *pkg.Baseline
	bar           *mpb.Bar
	finished      int
	Pools         *ants.PoolWithFunc
	PoolName      map[string]bool
	Tasks         chan *Task
	Rules         *rule.Program
	AppendRules   *rule.Program
	Headers       map[string]string
	FilterExpr    *vm.Program
	MatchExpr     *vm.Program
	RecursiveExpr *vm.Program
	OutputFile    *files.File
	FuzzyFile     *files.File
	DumpFile      *files.File
	StatFile      *files.File
	Progress      *mpb.Progress
	Fns           []func(string) []string
	Count         int // tasks total number
	Wordlist      []string
	AppendWords   []string
	RecuDepth     int
	ClientType    int
	Probes        []string
	Total         int // wordlist total number
	Color         bool
	Jsonify       bool
}

func (r *Runner) PrepareConfig() *pool.Config {
	config := &pool.Config{
		Thread:         r.Threads,
		Timeout:        r.Timeout,
		RateLimit:      r.RateLimit,
		Headers:        r.Headers,
		Method:         r.Method,
		Mod:            pool.ModMap[r.Mod],
		OutputCh:       r.outputCh,
		FuzzyCh:        r.fuzzyCh,
		OutLocker:      r.outwg,
		Fuzzy:          r.Fuzzy,
		CheckPeriod:    r.CheckPeriod,
		ErrPeriod:      int32(r.ErrPeriod),
		BreakThreshold: int32(r.BreakThreshold),
		MatchExpr:      r.MatchExpr,
		FilterExpr:     r.FilterExpr,
		RecuExpr:       r.RecursiveExpr,
		AppendRule:     r.AppendRules,
		AppendWords:    r.AppendWords,
		//IgnoreWaf:       r.IgnoreWaf,
		Crawl:           r.Crawl,
		Scope:           r.Scope,
		Active:          r.Finger,
		Bak:             r.Bak,
		Common:          r.Common,
		Retry:           r.RetryCount,
		ClientType:      r.ClientType,
		RandomUserAgent: r.RandomUserAgent,
		Random:          r.Random,
		Index:           r.Index,
		ProxyAddr:       r.Proxy,
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
	var err error
	if r.CheckOnly {
		// 仅check, 类似httpx
		r.Pools, err = ants.NewPoolWithFunc(1, func(i interface{}) {
			config := r.PrepareConfig()

			pool, err := pool.NewCheckPool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.Cancel()
				r.poolwg.Done()
				return
			}

			ch := make(chan string)
			go func() {
				for t := range r.Tasks {
					ch <- t.baseUrl
				}
				close(ch)
			}()
			pool.Worder = words.NewWorderWithChan(ch)
			pool.Worder.Fns = r.Fns
			pool.Bar = pkg.NewBar("check", r.Count-r.Offset, pool.Statistor, r.Progress)
			pool.Run(ctx, r.Offset, r.Count)
			r.poolwg.Done()
		})
	} else {
		// 完整探测模式
		go func() {
			for t := range r.Tasks {
				r.taskCh <- t
			}
			close(r.taskCh)
		}()

		if r.Count > 0 {
			r.addBar(r.Count)
		}

		r.Pools, err = ants.NewPoolWithFunc(r.PoolSize, func(i interface{}) {
			t := i.(*Task)
			if t.origin != nil && t.origin.End == t.origin.Total {
				r.StatFile.SafeWrite(t.origin.Json())
				r.Done()
				return
			}
			config := r.PrepareConfig()
			config.BaseURL = t.baseUrl

			pool, err := pool.NewBrutePool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.Cancel()
				r.Done()
				return
			}
			if t.origin != nil && len(r.Wordlist) == 0 {
				// 如果是从断点续传中恢复的任务, 则自动设置word,dict与rule, 不过优先级低于命令行参数
				pool.Statistor = pkg.NewStatistorFromStat(t.origin.Statistor)
				pool.Worder, err = t.origin.InitWorder(r.Fns)
				if err != nil {
					logs.Log.Error(err.Error())
					r.Done()
					return
				}
				pool.Statistor.Total = t.origin.sum
			} else {
				pool.Statistor = pkg.NewStatistor(t.baseUrl)
				pool.Worder = words.NewWorder(r.Wordlist)
				pool.Worder.Fns = r.Fns
				pool.Worder.Rules = r.Rules.Expressions
			}

			var limit int
			if pool.Statistor.Total > r.Limit && r.Limit != 0 {
				limit = r.Limit
			} else {
				limit = pool.Statistor.Total
			}
			pool.Bar = pkg.NewBar(config.BaseURL, limit-pool.Statistor.Offset, pool.Statistor, r.Progress)
			logs.Log.Importantf("[pool] task: %s, total %d words, %d threads, proxy: %s", pool.BaseURL, limit-pool.Statistor.Offset, pool.Thread, pool.ProxyAddr)
			err = pool.Init()
			if err != nil {
				pool.Statistor.Error = err.Error()
				if !r.Force {
					// 如果没开启force, init失败将会关闭pool
					pool.Close()
					r.PrintStat(pool)
					r.Done()
					return
				}
			}

			pool.Run(pool.Statistor.Offset, limit)

			if pool.IsFailed && len(pool.FailedBaselines) > 0 {
				// 如果因为错误积累退出, end将指向第一个错误发生时, 防止resume时跳过大量目标
				pool.Statistor.End = pool.FailedBaselines[0].Number
			}
			r.PrintStat(pool)
			r.Done()
		})
	}

	if err != nil {
		return err
	}
	r.OutputHandler()
	return nil
}

func (r *Runner) AddRecursive(bl *pkg.Baseline) {
	// 递归新任务
	task := &Task{
		baseUrl: bl.UrlString,
		depth:   bl.RecuDepth + 1,
		origin:  NewOrigin(pkg.NewStatistor(bl.UrlString)),
	}

	r.AddPool(task)
}

func (r *Runner) AddPool(task *Task) {
	// 递归新任务
	if _, ok := r.PoolName[task.baseUrl]; ok {
		logs.Log.Importantf("already added pool, skip %s", task.baseUrl)
		return
	}
	task.depth++
	r.poolwg.Add(1)
	r.Pools.Invoke(task)
}

func (r *Runner) Run(ctx context.Context) {
Loop:
	for {
		select {
		case <-ctx.Done():
			if len(r.taskCh) > 0 {
				for t := range r.taskCh {
					stat := pkg.NewStatistor(t.baseUrl)
					r.StatFile.SafeWrite(stat.Json())
				}
			}
			logs.Log.Importantf("already save all stat to %s", r.StatFile.Filename)
			break Loop
		case t, ok := <-r.taskCh:
			if !ok {
				break Loop
			}
			r.AddPool(t)
		}
	}

	r.poolwg.Wait()
	r.outwg.Wait()
}

func (r *Runner) RunWithCheck(ctx context.Context) {
	stopCh := make(chan struct{})
	r.poolwg.Add(1)
	err := r.Pools.Invoke(struct{}{})
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

	for {
		if len(r.outputCh) == 0 {
			break
		}
	}

	time.Sleep(100 * time.Millisecond) // 延迟100ms, 等所有数据处理完毕
}

func (r *Runner) addBar(total int) {
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
	r.finished++
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

	if r.StatFile != nil {
		r.StatFile.SafeWrite(pool.Statistor.Json())
		r.StatFile.SafeSync()
	}
}

func (r *Runner) OutputHandler() {
	debugPrint := func(bl *pkg.Baseline) {
		if r.Color {
			logs.Log.Debug(bl.ColorString())
		} else {
			logs.Log.Debug(bl.String())
		}
	}

	var saveFunc func(string)
	if r.OutputFile != nil {
		saveFunc = func(line string) {
			r.OutputFile.SafeWrite(line + "\n")
			r.OutputFile.SafeSync()
		}
	} else {
		saveFunc = func(line string) {
			logs.Log.Console(line + "\n")
		}
	}

	var fuzzySaveFunc func(string)
	if r.FuzzyFile != nil {
		fuzzySaveFunc = func(line string) {
			r.FuzzyFile.SafeWrite(line + "\n")
			r.FuzzyFile.SafeSync()
		}
	} else {
		fuzzySaveFunc = func(line string) {
			logs.Log.Console("[fuzzy] " + line + "\n")
		}
	}
	outputPrint := func(bl *pkg.Baseline) {
		var outFunc func(string)
		if bl.IsFuzzy {
			outFunc = fuzzySaveFunc
		} else {
			outFunc = saveFunc
		}
		if r.Option.Json {
			outFunc(bl.Jsonify())
		} else if r.Color {
			if len(r.Probes) > 0 {
				outFunc(logs.GreenBold(bl.Format(r.Probes)))
			} else {
				outFunc(logs.GreenBold(bl.ColorString()))
			}
		} else {
			if len(r.Probes) > 0 {
				outFunc(bl.Format(r.Probes))
			} else {
				outFunc(bl.String())
			}
		}
	}

	go func() {
		for {
			select {
			case bl, ok := <-r.outputCh:
				if !ok {
					return
				}
				if r.DumpFile != nil {
					r.DumpFile.SafeWrite(bl.Jsonify() + "\n")
					r.DumpFile.SafeSync()
				}
				if bl.IsValid {
					outputPrint(bl)
					if bl.Recu {
						r.AddRecursive(bl)
					}
				} else {
					debugPrint(bl)
				}
				r.outwg.Done()
			}
		}
	}()

	go func() {
		for {
			select {
			case bl, ok := <-r.fuzzyCh:
				if !ok {
					return
				}
				if r.Fuzzy {
					outputPrint(bl)
				}
				r.outwg.Done()
			}
		}
	}()
}
