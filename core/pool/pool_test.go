package pool

import (
	"context"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core/baseline"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestBasePool(ctx context.Context, cancel context.CancelFunc) *BasePool {
	return &BasePool{
		Config: &Config{
			Thread:   4,
			OutputCh: make(chan *baseline.Baseline, 100),
			FuzzyCh:  make(chan *baseline.Baseline, 100),
			Outwg:    &sync.WaitGroup{},
		},
		ctx:         ctx,
		Cancel:      cancel,
		additionCh:  make(chan *Unit, 40), // Thread*10
		closeCh:     make(chan struct{}),
		processCh:   make(chan *baseline.Baseline, 8), // Thread*2
		wg:          &sync.WaitGroup{},
		handlerDone: make(chan struct{}),
	}
}

func newTestBaseline() *baseline.Baseline {
	return &baseline.Baseline{
		SprayResult: &parsers.SprayResult{
			UrlString: "http://example.com/test",
			IsValid:   true,
		},
	}
}

// mustFinish fails the test if fn does not return within d.
func mustFinish(t *testing.T, d time.Duration, msg string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("timeout: %s", msg)
	}
}

// ---------------------------------------------------------------------------
// addAddition
// ---------------------------------------------------------------------------

func TestAddAddition_Normal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	pool.addAddition(&Unit{path: "/a", source: parsers.WordSource})

	select {
	case u := <-pool.additionCh:
		if u.path != "/a" {
			t.Fatalf("path = %q, want /a", u.path)
		}
	case <-time.After(time.Second):
		t.Fatal("addAddition: channel receive timed out")
	}
	pool.wg.Done() // balance the Add(1)
	pool.wg.Wait() // must not hang
}

func TestAddAddition_AfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)
	cancel()

	pool.addAddition(&Unit{path: "/a", source: parsers.WordSource})

	select {
	case <-pool.additionCh:
		t.Fatal("should not send after cancel")
	default:
	}
	// wg must be zero — the cancelled path must not leak a counter
	pool.wg.Wait()
}

// Regression: old code had a `default` branch that spawned an async goroutine.
// If the goroutine sent successfully, wg.Done() was never called — wg leak.
// This test verifies wg stays balanced after many addAddition calls.
func TestAddAddition_WgBalance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	const N = 100
	// drain concurrently so addAddition never blocks on a full buffer
	var received int32
	go func() {
		for range pool.additionCh {
			atomic.AddInt32(&received, 1)
			pool.wg.Done()
		}
	}()

	for i := 0; i < N; i++ {
		pool.addAddition(&Unit{path: "/x", source: parsers.WordSource})
	}

	mustFinish(t, 2*time.Second, "wg.Wait hung — wg counter leaked", func() {
		pool.wg.Wait()
	})
	close(pool.additionCh) // stop drain goroutine
	if r := atomic.LoadInt32(&received); r != N {
		t.Fatalf("received %d items, want %d", r, N)
	}
}

func TestAddAddition_FullBufferUnblocksOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	// fill buffer
	for i := 0; i < cap(pool.additionCh); i++ {
		pool.additionCh <- &Unit{path: "/fill"}
	}

	mustFinish(t, 2*time.Second, "addAddition on full buffer not unblocked by cancel", func() {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		pool.addAddition(&Unit{path: "/blocked", source: parsers.WordSource})
	})
}

func TestAddAddition_ConcurrentShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	var ext sync.WaitGroup
	for i := 0; i < 200; i++ {
		ext.Add(1)
		go func() {
			defer ext.Done()
			pool.addAddition(&Unit{path: "/c", source: parsers.WordSource})
		}()
	}

	time.Sleep(2 * time.Millisecond)
	cancel()

	// drain so senders can unblock
	go func() {
		for range pool.additionCh {
			pool.wg.Done()
		}
	}()

	mustFinish(t, 5*time.Second, "concurrent addAddition+cancel hung", func() {
		ext.Wait()
	})
	close(pool.additionCh)
}

// ---------------------------------------------------------------------------
// sendProcess
// ---------------------------------------------------------------------------

func TestSendProcess_Normal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	bl := newTestBaseline()
	pool.sendProcess(bl)

	select {
	case got := <-pool.processCh:
		if got.UrlString != bl.UrlString {
			t.Fatalf("got %q, want %q", got.UrlString, bl.UrlString)
		}
	case <-time.After(time.Second):
		t.Fatal("sendProcess: channel receive timed out")
	}
}

func TestSendProcess_AfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)
	cancel()

	mustFinish(t, 2*time.Second, "sendProcess blocked after cancel", func() {
		pool.sendProcess(newTestBaseline())
	})
}

func TestSendProcess_FullBufferUnblocksOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	for i := 0; i < cap(pool.processCh); i++ {
		pool.processCh <- newTestBaseline()
	}

	mustFinish(t, 2*time.Second, "sendProcess on full buffer not unblocked by cancel", func() {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		pool.sendProcess(newTestBaseline())
	})
}

func TestSendProcess_ConcurrentShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	var ext sync.WaitGroup
	for i := 0; i < 200; i++ {
		ext.Add(1)
		go func() {
			defer ext.Done()
			pool.sendProcess(newTestBaseline())
		}()
	}

	time.Sleep(2 * time.Millisecond)
	cancel()

	go func() {
		for range pool.processCh {
		}
	}()

	mustFinish(t, 5*time.Second, "concurrent sendProcess+cancel hung", func() {
		ext.Wait()
	})
	close(pool.processCh)
}

// ---------------------------------------------------------------------------
// putToOutput
// ---------------------------------------------------------------------------

func TestPutToOutput_Normal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	pool.putToOutput(newTestBaseline())

	select {
	case <-pool.OutputCh:
	case <-time.After(time.Second):
		t.Fatal("putToOutput: receive timed out")
	}
	pool.Outwg.Done()
	pool.Outwg.Wait()
}

func TestPutToOutput_AfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)
	cancel()

	mustFinish(t, 2*time.Second, "putToOutput blocked after cancel", func() {
		pool.putToOutput(newTestBaseline())
	})
	// select may have picked OutputCh (buffer available) or ctx.Done();
	// drain if sent so Outwg stays balanced.
	select {
	case <-pool.OutputCh:
		pool.Outwg.Done()
	default:
	}
	pool.Outwg.Wait()
}

func TestPutToOutput_OutwgBalance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	// fill OutputCh so next send will block
	for i := 0; i < cap(pool.OutputCh); i++ {
		pool.OutputCh <- newTestBaseline()
		pool.Outwg.Add(1) // manual balance for the fills
	}

	mustFinish(t, 2*time.Second, "putToOutput on full ch not unblocked by cancel", func() {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		pool.putToOutput(newTestBaseline())
	})

	// drain and done for fills
	for i := 0; i < cap(pool.OutputCh); i++ {
		<-pool.OutputCh
		pool.Outwg.Done()
	}
	pool.Outwg.Wait()
}

// ---------------------------------------------------------------------------
// putToFuzzy
// ---------------------------------------------------------------------------

func TestPutToFuzzy_Normal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	pool.putToFuzzy(newTestBaseline())

	select {
	case bl := <-pool.FuzzyCh:
		if !bl.IsFuzzy {
			t.Fatal("IsFuzzy should be true")
		}
	case <-time.After(time.Second):
		t.Fatal("putToFuzzy: receive timed out")
	}
	pool.Outwg.Done()
	pool.Outwg.Wait()
}

func TestPutToFuzzy_AfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)
	cancel()

	mustFinish(t, 2*time.Second, "putToFuzzy blocked after cancel", func() {
		pool.putToFuzzy(newTestBaseline())
	})
	select {
	case <-pool.FuzzyCh:
		pool.Outwg.Done()
	default:
	}
	pool.Outwg.Wait()
}

// ---------------------------------------------------------------------------
// Handler lifecycle — close(processCh) must exit for-range
// ---------------------------------------------------------------------------

// Regression: processCh was never closed → Handler goroutine leaked forever.
func TestHandlerDone_SignaledOnProcessChClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
		}
	}()

	close(pool.processCh)

	select {
	case <-pool.handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handlerDone not signaled after processCh closed")
	}
}

func TestHandlerDone_ProcessesAllBeforeExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	var count int
	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
			count++
		}
	}()

	const N = 20
	for i := 0; i < N; i++ {
		pool.processCh <- newTestBaseline()
	}
	close(pool.processCh)
	<-pool.handlerDone

	if count != N {
		t.Fatalf("handler processed %d items, want %d", count, N)
	}
}

// ---------------------------------------------------------------------------
// Full shutdown sequence (integration-level)
// ---------------------------------------------------------------------------

func TestShutdownSequence_NoDeadlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	// simulate Handler
	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
		}
	}()

	// simulate some work
	for i := 0; i < 10; i++ {
		pool.addAddition(&Unit{path: "/w", source: parsers.WordSource})
	}
	// simulate consumer
	for i := 0; i < 10; i++ {
		<-pool.additionCh
		pool.sendProcess(newTestBaseline())
		pool.wg.Done()
	}

	// shutdown: Cancel → wg.Wait → close(processCh) → <-handlerDone
	mustFinish(t, 5*time.Second, "shutdown sequence deadlocked", func() {
		cancel()
		pool.wg.Wait()
		close(pool.processCh)
		<-pool.handlerDone
	})
}

func TestShutdownSequence_CancelMidFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
		}
	}()

	// producers still running when cancel fires
	var ext sync.WaitGroup
	for i := 0; i < 50; i++ {
		ext.Add(1)
		go func() {
			defer ext.Done()
			pool.addAddition(&Unit{path: "/m", source: parsers.WordSource})
		}()
	}
	for i := 0; i < 50; i++ {
		ext.Add(1)
		go func() {
			defer ext.Done()
			pool.sendProcess(newTestBaseline())
		}()
	}

	time.Sleep(5 * time.Millisecond)
	cancel()

	// drain additionCh
	go func() {
		for range pool.additionCh {
			pool.wg.Done()
		}
	}()

	mustFinish(t, 5*time.Second, "mid-flight cancel deadlocked", func() {
		ext.Wait()
		pool.wg.Wait()
		close(pool.processCh)
		<-pool.handlerDone
		close(pool.additionCh)
	})
}

// ---------------------------------------------------------------------------
// Goroutine leak detection
// ---------------------------------------------------------------------------

func TestNoGoroutineLeak(t *testing.T) {
	// let background goroutines from prior tests settle
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	pool := newTestBasePool(ctx, cancel)

	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
		}
	}()

	for i := 0; i < 10; i++ {
		pool.addAddition(&Unit{path: "/l", source: parsers.WordSource})
	}
	go func() {
		for range pool.additionCh {
			pool.wg.Done()
		}
	}()

	cancel()
	pool.wg.Wait()
	close(pool.processCh)
	<-pool.handlerDone
	close(pool.additionCh)

	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
}
