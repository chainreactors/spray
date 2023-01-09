package internal

import (
	"context"
	"fmt"
	"github.com/antonmedv/expr/vm"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words"
	"github.com/chainreactors/words/rule"
	"github.com/gosuri/uiprogress"
	"github.com/panjf2000/ants/v2"
	"sync"
	"time"
)

var (
	WhiteStatus = []int{200}
	BlackStatus = []int{400, 410}
	FuzzyStatus = []int{403, 404, 500, 501, 502, 503}
	WAFStatus   = []int{493, 418}
)

var (
	dictCache     = make(map[string][]string)
	wordlistCache = make(map[string][]string)
	ruleCache     = make(map[string][]rule.Expression)
)

type Runner struct {
	taskCh   chan *Task
	poolwg   sync.WaitGroup
	bar      *uiprogress.Bar
	finished int

	Tasks          []*Task
	URLList        []string
	Wordlist       []string
	Rules          *rule.Program
	AppendRules    *rule.Program
	Headers        map[string]string
	Fns            []func(string) string
	FilterExpr     *vm.Program
	MatchExpr      *vm.Program
	RecursiveExpr  *vm.Program
	RecuDepth      int
	Threads        int
	PoolSize       int
	Pools          *ants.PoolWithFunc
	PoolName       map[string]bool
	Timeout        int
	Mod            string
	Probes         []string
	OutputCh       chan *pkg.Baseline
	FuzzyCh        chan *pkg.Baseline
	Fuzzy          bool
	OutputFile     *files.File
	FuzzyFile      *files.File
	DumpFile       *files.File
	StatFile       *files.File
	Progress       *uiprogress.Progress
	Offset         int
	Limit          int
	Total          int
	Deadline       int
	CheckPeriod    int
	ErrPeriod      int
	BreakThreshold int
	Color          bool
	CheckOnly      bool
	Force          bool
	IgnoreWaf      bool
	Crawl          bool
	Active         bool
	Bak            bool
	Common         bool
}

func (r *Runner) PrepareConfig() *pkg.Config {
	config := &pkg.Config{
		Thread:         r.Threads,
		Timeout:        r.Timeout,
		Headers:        r.Headers,
		Mod:            pkg.ModMap[r.Mod],
		OutputCh:       r.OutputCh,
		FuzzyCh:        r.FuzzyCh,
		Fuzzy:          r.Fuzzy,
		CheckPeriod:    r.CheckPeriod,
		ErrPeriod:      r.ErrPeriod,
		BreakThreshold: r.BreakThreshold,
		MatchExpr:      r.MatchExpr,
		FilterExpr:     r.FilterExpr,
		RecuExpr:       r.RecursiveExpr,
		AppendRule:     r.AppendRules,
		IgnoreWaf:      r.IgnoreWaf,
		Crawl:          r.Crawl,
		Active:         r.Active,
		Bak:            r.Bak,
		Common:         r.Common,
	}
	if config.Mod == pkg.PathSpray {
		config.ClientType = ihttp.FAST
	} else if config.Mod == pkg.HostSpray {
		config.ClientType = ihttp.STANDARD
	}
	return config
}

func (r *Runner) Prepare(ctx context.Context) error {
	var err error
	if r.CheckOnly {
		// 仅check, 类似httpx
		r.Pools, err = ants.NewPoolWithFunc(1, func(i interface{}) {
			config := r.PrepareConfig()

			pool, err := NewCheckPool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.cancel()
				r.poolwg.Done()
				return
			}
			pool.worder = words.NewWorder(r.URLList)
			pool.worder.Fns = r.Fns
			pool.bar = pkg.NewBar("check", r.Total-r.Offset, r.Progress)
			pool.Run(ctx, r.Offset, r.Total)
			r.poolwg.Done()
		})
	} else {
		go func() {
			for _, t := range r.Tasks {
				r.taskCh <- t
			}
			close(r.taskCh)
		}()

		if len(r.Tasks) > 0 {
			r.bar = r.Progress.AddBar(len(r.Tasks))
			r.bar.PrependCompleted()
			r.bar.PrependFunc(func(b *uiprogress.Bar) string {
				return fmt.Sprintf("total progressive: %d/%d ", r.finished, len(r.Tasks))
			})
			r.bar.AppendElapsed()
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

			pool, err := NewPool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.cancel()
				r.Done()
				return
			}
			if t.origin != nil && len(r.Wordlist) == 0 {
				// 如果是从断点续传中恢复的任务, 则自动设置word,dict与rule, 不过优先级低于命令行参数
				pool.Statistor = pkg.NewStatistorFromStat(t.origin)
				wl, err := loadWordlist(t.origin.Word, t.origin.Dictionaries)
				if err != nil {
					logs.Log.Error(err.Error())
					r.Done()
					return
				}
				pool.worder = words.NewWorder(wl)
				pool.worder.Fns = r.Fns
				rules, err := loadRuleWithFiles(t.origin.RuleFiles, t.origin.RuleFilter)
				if err != nil {
					logs.Log.Error(err.Error())
					r.Done()
					return
				}
				pool.worder.Rules = rules
				if len(rules) > 0 {
					pool.Statistor.Total = len(rules) * len(wl)
				} else {
					pool.Statistor.Total = len(wl)
				}
			} else {
				pool.Statistor = pkg.NewStatistor(t.baseUrl)
				pool.worder = words.NewWorder(r.Wordlist)
				pool.worder.Fns = r.Fns
				pool.worder.Rules = r.Rules.Expressions
			}

			var limit int
			if pool.Statistor.Total > r.Limit && r.Limit != 0 {
				limit = r.Limit
			} else {
				limit = pool.Statistor.Total
			}
			pool.bar = pkg.NewBar(config.BaseURL, limit-pool.Statistor.Offset, r.Progress)
			err = pool.Init()
			if err != nil {
				logs.Log.Error(err.Error())
				if !r.Force {
					// 如果没开启force, init失败将会关闭pool
					pool.cancel()
					r.Done()
					return
				}
			}

			pool.Run(ctx, pool.Statistor.Offset, limit)

			if pool.isFailed && len(pool.failedBaselines) > 0 {
				// 如果因为错误积累退出, end将指向第一个错误发生时, 防止resume时跳过大量目标
				pool.Statistor.End = pool.failedBaselines[0].Number
			}
			if r.Color {
				logs.Log.Important(pool.Statistor.ColorString())
				logs.Log.Important(pool.Statistor.ColorDetail())
			} else {
				logs.Log.Important(pool.Statistor.String())
				logs.Log.Important(pool.Statistor.Detail())
			}

			if r.StatFile != nil {
				r.StatFile.SafeWrite(pool.Statistor.Json())
				r.StatFile.SafeSync()
			}
			r.Done()
		})
	}

	if err != nil {
		return err
	}
	r.Outputting()
	return nil
}

func (r *Runner) AddPool(task *Task) {
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
			for t := range r.taskCh {
				stat := pkg.NewStatistor(t.baseUrl)
				r.StatFile.SafeWrite(stat.Json())
			}
			logs.Log.Importantf("save all stat to %s", r.StatFile.Filename)
			break Loop
		case t, ok := <-r.taskCh:
			if !ok {
				break Loop
			}
			r.AddPool(t)
		}
	}

	r.poolwg.Wait()
	//time.Sleep(100 * time.Millisecond) // 延迟100ms, 等所有数据处理完毕
	for {
		if len(r.OutputCh) == 0 {
			close(r.OutputCh)
			break
		}
	}

	for {
		if len(r.FuzzyCh) == 0 {
			close(r.FuzzyCh)
			break
		}
	}
	time.Sleep(100 * time.Millisecond) // 延迟100ms, 等所有数据处理完毕
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
		if len(r.OutputCh) == 0 {
			close(r.OutputCh)
			break
		}
	}

	time.Sleep(100 * time.Millisecond) // 延迟100ms, 等所有数据处理完毕
}

func (r *Runner) Done() {
	r.bar.Incr()
	r.finished++
	r.poolwg.Done()
}

func (r *Runner) Outputting() {
	go func() {
		var saveFunc func(*pkg.Baseline)

		if r.OutputFile != nil {
			saveFunc = func(bl *pkg.Baseline) {
				r.OutputFile.SafeWrite(bl.Jsonify() + "\n")
				r.OutputFile.SafeSync()
			}
		} else {
			if len(r.Probes) > 0 {
				if r.Color {
					saveFunc = func(bl *pkg.Baseline) {
						logs.Log.Console(logs.GreenBold("[+] " + bl.Format(r.Probes) + "\n"))
					}
				} else {
					saveFunc = func(bl *pkg.Baseline) {
						logs.Log.Console("[+] " + bl.Format(r.Probes) + "\n")
					}
				}
			} else {
				if r.Color {
					saveFunc = func(bl *pkg.Baseline) {
						logs.Log.Console(logs.GreenBold("[+] " + bl.ColorString() + "\n"))
					}
				} else {
					saveFunc = func(bl *pkg.Baseline) {
						logs.Log.Console("[+] " + bl.String() + "\n")
					}
				}

			}
		}

		for {
			select {
			case bl, ok := <-r.OutputCh:
				if !ok {
					return
				}
				if r.DumpFile != nil {
					r.DumpFile.SafeWrite(bl.Jsonify() + "\n")
					r.DumpFile.SafeSync()
				}
				if bl.IsValid {
					saveFunc(bl)
					if bl.Recu {
						r.AddPool(&Task{baseUrl: bl.UrlString, depth: bl.RecuDepth + 1})
					}
				} else {
					if r.Color {
						logs.Log.Debug(bl.ColorString())
					} else {
						logs.Log.Debug(bl.String())
					}
				}
			}
		}
	}()

	go func() {
		var fuzzySaveFunc func(*pkg.Baseline)
		if r.FuzzyFile != nil {
			fuzzySaveFunc = func(bl *pkg.Baseline) {
				r.FuzzyFile.SafeWrite(bl.Jsonify() + "\n")
			}
		} else {
			if r.Color {
				fuzzySaveFunc = func(bl *pkg.Baseline) {
					logs.Log.Console(logs.GreenBold("[fuzzy] " + bl.ColorString() + "\n"))
				}
			} else {
				fuzzySaveFunc = func(bl *pkg.Baseline) {
					logs.Log.Console("[fuzzy] " + bl.String() + "\n")
				}
			}
		}

		for {
			select {
			case bl, ok := <-r.FuzzyCh:
				if !ok {
					return
				}
				if r.Fuzzy {
					fuzzySaveFunc(bl)
				}
			}
		}
	}()
}
