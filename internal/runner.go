package internal

import (
	"fmt"
	"github.com/chainreactors/logs"
	"io/ioutil"
	"net/http"
	"os"
	"spray/pkg"
	"strings"
	"sync"
)

var BlackStatus = []int{404, 410}
var FuzzyStatus = []int{403, 500, 501, 503}

type Runner struct {
	URL        string
	URLFile    string
	URLList    []string
	WordFile   string
	Wordlist   []string
	Headers    http.Header
	OutputFile string
	Offset     int
	Limit      int
	Threads    int
	PoolSize   int
	Pools      map[string]*Pool
	Deadline   int // todo 总的超时时间,适配云函数的deadline
	Debug      bool
	Mod        string
	OutputCh   chan *baseline
}

func (r *Runner) Prepare() error {
	if r.Debug {
		logs.Log.Level = logs.Debug
	}
	var file *os.File
	var err error
	urlfrom := r.URLFile
	if r.URL != "" {
		r.URLList = append(r.URLList, r.URL)
		urlfrom = "cmd"
	} else if r.URLFile != "" {
		file, err = os.Open(r.URLFile)
		if err != nil {
			return err
		}
	} else if pkg.HasStdin() {
		file = os.Stdin
		urlfrom = "stdin"
	}

	if file != nil {
		content, err := ioutil.ReadAll(file)
		if err != nil {
			return err
		}
		r.URLList = strings.Split(string(content), "\n")
	}

	// todo url formatter
	for i, u := range r.URLList {
		r.URLList[i] = strings.TrimSpace(u)
	}
	logs.Log.Importantf("load %d urls from %s", len(r.URLList), urlfrom)

	if r.WordFile != "" {
		content, err := ioutil.ReadFile(r.WordFile)
		if err != nil {
			return err
		}
		r.Wordlist = strings.Split(string(content), "\n")
	} else {
		return fmt.Errorf("not special wordlist")
	}

	if r.Wordlist != nil && len(r.Wordlist) > 0 {
		// todo  suffix/prefix/trim/generator
		for i, word := range r.Wordlist {
			r.Wordlist[i] = strings.TrimSpace(word)
		}
		logs.Log.Importantf("load %d word from %s", len(r.Wordlist), r.WordFile)
	} else {
		return fmt.Errorf("no wordlist")
	}

	CheckStatusCode = func(status int) bool {
		for _, black := range BlackStatus {
			if black == status {
				return false
			}
		}
		return true
	}

	r.OutputCh = make(chan *baseline, 100)
	r.Pools = make(map[string]*Pool)
	go r.Outputting()
	return nil
}

func (r *Runner) Run() {
	// todo pool 结束与并发控制
	var wg sync.WaitGroup
	for _, u := range r.URLList {
		wg.Add(1)
		u := u
		go func() {
			config := &pkg.Config{
				BaseURL:  u,
				Wordlist: r.Wordlist,
				Thread:   r.Threads,
				Timeout:  2,
				Headers:  r.Headers,
			}
			pool, err := NewPool(config, r.OutputCh)
			if err != nil {
				logs.Log.Error(err.Error())
				return
			}

			err = pool.Init()
			if err != nil {
				logs.Log.Error(err.Error())
				return
			}
			r.Pools[u] = pool
			// todo pool 总超时时间
			pool.Run()
			wg.Done()
		}()
	}
	wg.Wait()
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
				logs.Log.Console(bl.String() + "\n")
			} else {
				logs.Log.Debug(bl.String())
			}
		}
	}
}
