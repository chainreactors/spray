package internal

import (
	"context"
	"fmt"
	"github.com/antonmedv/expr/vm"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words/rule"
	"github.com/gosuri/uiprogress"
	"github.com/panjf2000/ants/v2"
	"net/http"
	"sync"
	"time"
)

var (
	WhiteStatus = []int{200}
	BlackStatus = []int{400, 404, 410}
	FuzzyStatus = []int{403, 500, 501, 502, 503}
	WAFStatus   = []int{493, 418}
)

type Runner struct {
	taskCh   chan *Task
	poolwg   sync.WaitGroup
	bar      *uiprogress.Bar
	finished int

	Tasks          []*Task
	URLList        []string
	Wordlist       []string
	Rules          []rule.Expression
	Headers        http.Header
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
	StatFile       *files.File
	Force          bool
	Progress       *uiprogress.Progress
	Offset         int
	Total          int
	Deadline       int
	CheckPeriod    int
	ErrPeriod      int
	BreakThreshold int
	CheckOnly      bool
}

func (r *Runner) PrepareConfig() *pkg.Config {
	config := &pkg.Config{
		Thread:         r.Threads,
		Timeout:        r.Timeout,
		Headers:        r.Headers,
		Mod:            pkg.ModMap[r.Mod],
		Fns:            r.Fns,
		Rules:          r.Rules,
		OutputCh:       r.OutputCh,
		FuzzyCh:        r.FuzzyCh,
		CheckPeriod:    r.CheckPeriod,
		ErrPeriod:      r.ErrPeriod,
		BreakThreshold: r.BreakThreshold,
		MatchExpr:      r.MatchExpr,
		FilterExpr:     r.FilterExpr,
		RecuExpr:       r.RecursiveExpr,
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
			config.Wordlist = r.URLList
			pool, err := NewCheckPool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.cancel()
				r.poolwg.Done()
				return
			}
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
			config := r.PrepareConfig()
			config.BaseURL = t.baseUrl
			config.Wordlist = r.Wordlist
			pool, err := NewPool(ctx, config)
			if err != nil {
				logs.Log.Error(err.Error())
				pool.cancel()
				r.Done()
				return
			}

			pool.bar = pkg.NewBar(config.BaseURL, t.total-t.offset, r.Progress)
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

			pool.Run(ctx, t.offset, t.total)
			logs.Log.Important(pool.Statistor.String())
			logs.Log.Important(pool.Statistor.Detail())
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
			logs.Log.Error("cancel with deadline")
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
				saveFunc = func(bl *pkg.Baseline) {
					logs.Log.Console("[+] " + bl.Format(r.Probes) + "\n")
				}
			} else {
				saveFunc = func(bl *pkg.Baseline) {
					logs.Log.Console("[+] " + bl.String() + "\n")
				}
			}
		}

		for {
			select {
			case bl, ok := <-r.OutputCh:
				if !ok {
					return
				}

				if bl.IsValid {
					saveFunc(bl)
					if bl.Recu {
						r.AddPool(&Task{bl.UrlString, 0, r.Total, bl.RecuDepth + 1})
					}
				} else {
					logs.Log.Debug(bl.String())
				}
			}
		}
	}()

	go func() {
		var fuzzySaveFunc func(*pkg.Baseline)
		if r.FuzzyFile != nil {
			fuzzySaveFunc = func(bl *pkg.Baseline) {
				r.FuzzyFile.SafeWrite(bl.Jsonify() + "\n")
				r.FuzzyFile.SafeSync()
			}
		} else {
			fuzzySaveFunc = func(bl *pkg.Baseline) {
				if r.Fuzzy {
					logs.Log.Console("[baseline.fuzzy] " + bl.String() + "\n")
				}
			}
		}

		for {
			select {
			case bl, ok := <-r.FuzzyCh:
				if !ok {
					return
				}
				fuzzySaveFunc(bl)
			}
		}
	}()
}
