package internal

import (
	"context"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/gosuri/uiprogress"
	"github.com/panjf2000/ants/v2"
	"net/http"
	"sync"
)

var BlackStatus = []int{400, 404, 410}
var FuzzyStatus = []int{403, 500, 501, 502, 503}

type Runner struct {
	URLList  []string
	Wordlist []string
	Headers  http.Header
	Fns      []func(string) string
	Threads  int
	PoolSize int
	Pools    *ants.PoolWithFunc
	poolwg   sync.WaitGroup
	Timeout  int
	Mod      string
	OutputCh chan *baseline
	Progress *uiprogress.Progress
}

func (r *Runner) Prepare() error {
	var err error
	CheckStatusCode = func(status int) bool {
		for _, black := range BlackStatus {
			if black == status {
				return false
			}
		}
		return true
	}

	r.OutputCh = make(chan *baseline, 100)
	ctx := context.Background()

	r.Pools, err = ants.NewPoolWithFunc(r.PoolSize, func(i interface{}) {
		u := i.(string)
		config := &pkg.Config{
			BaseURL:  u,
			Wordlist: r.Wordlist,
			Thread:   r.Threads,
			Timeout:  r.Timeout,
			Headers:  r.Headers,
			Mod:      pkg.ModMap[r.Mod],
			Fns:      r.Fns,
		}

		if config.Mod == pkg.PathSpray {
			config.ClientType = ihttp.FAST
		} else if config.Mod == pkg.HostSpray {
			config.ClientType = ihttp.STANDARD
		}

		pool, err := NewPool(ctx, config, r.OutputCh)
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		pool.bar = pkg.NewBar(u, len(r.Wordlist), r.Progress)
		err = pool.Init()
		if err != nil {
			logs.Log.Error(err.Error())
			return
		}
		// todo pool 总超时时间
		pool.Run(ctx)
		r.poolwg.Done()
	})

	if err != nil {
		return err
	}
	go r.Outputting()
	return nil
}

func (r *Runner) Run() {
	// todo pool 结束与并发控制
	for _, u := range r.URLList {
		r.poolwg.Add(1)
		r.Pools.Invoke(u)
	}
	r.poolwg.Wait()
	for {
		if len(r.OutputCh) == 0 {
			close(r.OutputCh)
			return
		}
	}
}

func (r *Runner) Outputting() {
	for {
		select {
		case bl := <-r.OutputCh:
			if bl.IsValid {
				logs.Log.Console("[+] " + bl.String() + "\n")
			} else {
				logs.Log.Debug(bl.String())
			}
		}
	}
}
