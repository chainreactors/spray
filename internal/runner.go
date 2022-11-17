package internal

import (
	"context"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/gosuri/uiprogress"
	"github.com/panjf2000/ants/v2"
	"net/http"
	"sync"
	"time"
)

var (
	BlackStatus = []int{}
	FuzzyStatus = []int{403, 500, 501, 502, 503}
	WAFStatus   = []int{493, 418}
)

type Runner struct {
	URLList        chan string
	Wordlist       []string
	Headers        http.Header
	Fns            []func(string) string
	Threads        int
	PoolSize       int
	Pools          *ants.PoolWithFunc
	poolwg         sync.WaitGroup
	Timeout        int
	Mod            string
	Probes         []string
	OutputCh       chan *pkg.Baseline
	FuzzyCh        chan *pkg.Baseline
	Fuzzy          bool
	OutputFile     *files.File
	FuzzyFile      *files.File
	Force          bool
	Progress       *uiprogress.Progress
	Offset         int
	Limit          int
	Deadline       int
	CheckPeriod    int
	ErrPeriod      int
	BreakThreshold int
	CheckOnly      bool
}

func (r *Runner) Prepare(ctx context.Context) error {
	var err error
	CheckBadStatus = func(status int) bool {
		for _, black := range BlackStatus {
			if black == status {
				return true
			}
		}
		return false
	}

	r.Pools, err = ants.NewPoolWithFunc(r.PoolSize, func(i interface{}) {
		u := i.(string)
		config := &pkg.Config{
			BaseURL:        u,
			Wordlist:       r.Wordlist,
			Thread:         r.Threads,
			Timeout:        r.Timeout,
			Headers:        r.Headers,
			Mod:            pkg.ModMap[r.Mod],
			Fns:            r.Fns,
			OutputCh:       r.OutputCh,
			FuzzyCh:        r.FuzzyCh,
			CheckPeriod:    r.CheckPeriod,
			ErrPeriod:      r.ErrPeriod,
			BreakThreshold: r.BreakThreshold,
		}

		if config.Mod == pkg.PathSpray {
			config.ClientType = ihttp.FAST
		} else if config.Mod == pkg.HostSpray {
			config.ClientType = ihttp.STANDARD
		}

		pool, err := NewPool(ctx, config)
		if err != nil {
			logs.Log.Error(err.Error())
			pool.cancel()
			r.poolwg.Done()
			return
		}
		pool.bar = pkg.NewBar(u, r.Limit-r.Offset, r.Progress)
		err = pool.Init()
		if err != nil {
			logs.Log.Error(err.Error())
			if !r.Force {
				// 如果没开启force, init失败将会关闭pool
				pool.cancel()
				r.poolwg.Done()
				return
			}
		}

		pool.Run(ctx, r.Offset, r.Limit)
		r.poolwg.Done()
	})

	if err != nil {
		return err
	}
	r.Outputting()
	return nil
}

func (r *Runner) Run(ctx context.Context) {
Loop:
	for {
		select {
		case <-ctx.Done():
			logs.Log.Error("cancel with deadline")
			break Loop
		case u, ok := <-r.URLList:
			if !ok {
				break Loop
			}
			r.poolwg.Add(1)
			r.Pools.Invoke(u)
		}
	}

	r.poolwg.Wait()
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
	time.Sleep(100) // 延迟100ms, 等所有数据处理完毕
}

func (r *Runner) Outputting() {
	go func() {
		var outFunc func(*pkg.Baseline)
		if len(r.Probes) > 0 {
			outFunc = func(bl *pkg.Baseline) {
				logs.Log.Console("[+] " + bl.Format(r.Probes) + "\n")
			}
		} else {
			outFunc = func(bl *pkg.Baseline) {
				logs.Log.Console("[+] " + bl.String() + "\n")
			}
		}

		for {
			select {
			case bl := <-r.OutputCh:
				if bl.IsValid {
					outFunc(bl)
				} else {
					logs.Log.Debug(bl.String())
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case bl := <-r.FuzzyCh:
				if r.Fuzzy {
					logs.Log.Console("[baseline.fuzzy] " + bl.String() + "\n")
				}
			}
		}
	}()
}
