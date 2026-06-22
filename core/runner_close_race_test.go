package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/spray/core/baseline"
)

// TestRunWithCheck_NoSendOnClosedChannel reproduces the race condition where
// RunWithCheck closes OutputCh while the CheckPool's Handler goroutine is
// still sending results via putToOutput.
//
// Before the fix (missing poolwg.Wait), context cancellation caused
// RunWithCheck to close OutputCh before the pool finished, triggering
// "panic: send on closed channel" in putToOutput.
func TestRunWithCheck_NoSendOnClosedChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok")
	}))
	defer srv.Close()

	const numURLs = 20

	// Build a TaskGenerator manually to avoid NewTaskGenerator's port parser.
	gen := &TaskGenerator{
		tasks: make(chan *Task),
		In:    make(chan *Task),
	}
	go func() {
		for task := range gen.In {
			gen.tasks <- task
		}
		close(gen.tasks)
	}()
	go func() {
		for i := 0; i < numURLs; i++ {
			gen.In <- &Task{baseUrl: fmt.Sprintf("%s/path%d", srv.URL, i)}
		}
		close(gen.In)
	}()

	opt := &Option{}
	opt.Threads = 5
	opt.Timeout = 3
	opt.PoolSize = 1
	opt.Limit = numURLs
	opt.Quiet = true
	opt.NoColor = true
	opt.Method = "GET"
	opt.Client = "standard"

	runner := &Runner{
		Option:   opt,
		taskCh:   make(chan *Task),
		OutputCh: make(chan *baseline.Baseline, 256),
		poolwg:   &sync.WaitGroup{},
		OutWg:    &sync.WaitGroup{},
		FuzzyCh:  make(chan *baseline.Baseline, 256),
		Headers:  make(map[string]string),
		Total:    numURLs,
		IsCheck:  true,
		Count:    numURLs,
	}
	runner.Tasks = gen

	// Cancel the context after a short delay — while the pool is in the
	// middle of processing. This is the trigger for the old race.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Drain output channels in background so sends don't block.
	var drainWg sync.WaitGroup
	drainWg.Add(2)
	go func() {
		defer drainWg.Done()
		for range runner.OutputCh {
			runner.OutWg.Done()
		}
	}()
	go func() {
		defer drainWg.Done()
		for range runner.FuzzyCh {
			runner.OutWg.Done()
		}
	}()

	// This is the call that would panic before the fix.
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.RunWithCheck(ctx)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("RunWithCheck did not return within 30s")
	}

	drainWg.Wait()
}
