package core

import (
	"context"
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
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	MAX = 2147483647
)

type Runner struct {
	*Option

	taskCh   chan *Task
	poolwg   *sync.WaitGroup
	OutWg    *sync.WaitGroup
	OutputCh chan *baseline.Baseline
	fuzzyCh  chan *baseline.Baseline
	bar      *mpb.Bar
	bruteMod bool

	ProxyClient          proxyclient.Dial
	IsCheck              bool
	DisableOutputHandler bool // 禁用内置的 OutputHandler，用于 SDK 等外部控制
	Pools                *ants.PoolWithFunc
	PoolName             map[string]bool
	Tasks                *TaskGenerator
	Rules                *rule.Program
	AppendRules          *rule.Program
	Headers              map[string]string
	FilterExpr           *vm.Program
	MatchExpr            *vm.Program
	RecursiveExpr        *vm.Program
	OutputFile           *files.File
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
}

func (r *Runner) PrepareConfig() *pool.Config {
	config := &pool.Config{
		Thread:         r.Threads,
		Timeout:        time.Duration(r.Timeout) * time.Second,
		RateLimit:      r.RateLimit,
		Headers:        make(http.Header),
		Method:         r.Method,
		Mod:            pool.ModMap[r.Mod],
		OutputCh:       r.OutputCh,
		FuzzyCh:        r.fuzzyCh,
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
		RetryLimit:        r.RetryCount,
		ClientType:        r.ClientType,
		RandomUserAgent:   r.RandomUserAgent,
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

	for k, v := range r.Headers {
		config.Headers.Set(k, v)
	}

	if config.Headers.Get("User-Agent") == "" {
		config.Headers.Set("User-Agent", pkg.DefaultUserAgent)
	}

	if config.Headers.Get("Accept") == "" {
		config.Headers.Set("Accept", "*/*")
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
	// 如果设置了 DisableOutputHandler，则跳过内置的输出处理器
	// 这允许 SDK 等外部调用者完全控制 OutputCh 的处理
	if !r.DisableOutputHandler {
		r.OutputHandler()
	}
	var err error
	if r.IsCheck {
		// 仅check, 类似httpx
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
			go func() {
				for t := range r.Tasks.tasks {
					ch <- t.baseUrl
				}
				close(ch)
			}()
			checkPool.Worder = words.NewWorderWithChan(ch)
			checkPool.Worder.Fns = r.Fns
			checkPool.Bar = pkg.NewBar("check", r.Count-r.Offset, checkPool.Statistor, r.Progress)
			checkPool.Run(ctx, r.Offset, r.Count)
			r.poolwg.Done()
		})
		r.RunWithCheck(ctx)
	} else {
		// 完整探测模式
		go func() {
			for t := range r.Tasks.tasks {
				r.taskCh <- t
			}
			close(r.taskCh)
		}()

		if r.Count > 0 {
			r.newBar(r.Count)
		}

		r.Pools, err = ants.NewPoolWithFunc(r.PoolSize, func(i interface{}) {
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
				brutePool.Cancel()
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
				brutePool.Statistor = pkg.NewStatistor(t.baseUrl)
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
				if !r.Force {
					// 如果没开启force, init失败将会关闭pool
					brutePool.Bar.Close()
					brutePool.Close()
					r.PrintStat(brutePool)
					r.Done()
					return
				}
			}

			brutePool.Run(brutePool.Statistor.Offset, limit)

			if brutePool.IsFailed && len(brutePool.FailedBaselines) > 0 {
				// 如果因为错误积累退出, end将指向第一个错误发生时, 防止resume时跳过大量目标
				brutePool.Statistor.End = brutePool.FailedBaselines[0].Number
			}
			r.PrintStat(brutePool)
			r.Done()
		})
		r.Run(ctx)
	}
	if err != nil {
		return err
	}

	return nil
}

func (r *Runner) Run(ctx context.Context) {
Loop:
	for {
		select {
		case <-ctx.Done():
			// 如果超过了deadline, 尚未开始的任务都将被记录到stat中
			if len(r.taskCh) > 0 {
				for t := range r.taskCh {
					stat := pkg.NewStatistor(t.baseUrl)
					r.saveStat(stat.Json())
				}
			}
			if r.StatFile != nil {
				logs.Log.Importantf("already save all stat to %s", r.StatFile.Filename)
			}
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

	r.OutWg.Wait()
}

func (r *Runner) AddRecursive(bl *baseline.Baseline) {
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
}

func (r *Runner) saveStat(content string) {
	if r.StatFile != nil {
		r.StatFile.SafeWrite(content)
		r.StatFile.SafeSync()
	}
}

func (r *Runner) Output(bl *baseline.Baseline) {
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

	if bl.IsValid {
		logs.Log.Console(out + "\n")
	} else if r.Fuzzy && bl.IsFuzzy {
		logs.Log.Console("[fuzzy] " + out + "\n")
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
			case bl, ok := <-r.fuzzyCh:
				if !ok {
					return
				}
				r.Output(bl)
				r.OutWg.Done()
			}
		}
	}()
}
