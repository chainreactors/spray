package pool

import (
	"context"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/parsers"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
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

func TestAppendBasePathTreatsValidPathAsDirectory(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "/"},
		{name: "root", in: "/", want: "/"},
		{name: "directory", in: "/xxl-job-admin/", want: "/xxl-job-admin/"},
		{name: "path without slash", in: "/xxl-job-admin", want: "/xxl-job-admin/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appendBasePath(tt.in); got != tt.want {
				t.Fatalf("appendBasePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAppendDerivationSourcesDoNotCascadePluginOutputs(t *testing.T) {
	allowed := []parsers.SpraySource{
		parsers.InitIndexSource,
		parsers.WordSource,
		parsers.RedirectSource,
		parsers.CrawlSource,
	}
	for _, source := range allowed {
		if !canDeriveAppendFromSource(source) {
			t.Fatalf("%s should allow append derivation", source.Name())
		}
	}

	blocked := []parsers.SpraySource{
		parsers.FingerSource,
		parsers.BakSource,
		parsers.CommonFileSource,
		parsers.AppendSource,
		parsers.AppendRuleSource,
		parsers.RuleSource,
		parsers.RetrySource,
	}
	for _, source := range blocked {
		if canDeriveAppendFromSource(source) {
			t.Fatalf("%s should not allow append derivation", source.Name())
		}
	}
}

func TestAdaptiveFuzzyBaselineSuppressesRepeatedUnauthorizedPages(t *testing.T) {
	withStatusFilters(t)
	pool := newTestBrutePoolForCompare(t)

	first := newCompareBaseline(401, "/orders.log.1", "auth required for /orders.log.1")
	first.Source = parsers.AppendSource
	pool.handleBaseline(first)
	drainOutput(t, pool)

	if first.IsValid {
		t.Fatal("first 401 baseline sample stayed valid")
	}
	if !first.IsFuzzy {
		t.Fatal("first 401 baseline sample was not marked fuzzy")
	}
	if _, ok := pool.baselines[401]; !ok {
		t.Fatal("401 adaptive baseline was not learned")
	}

	second := newCompareBaseline(401, "/orders.log.old", "auth required for /orders.log.old")
	second.Source = parsers.AppendSource
	pool.handleBaseline(second)
	drainOutput(t, pool)

	if second.IsValid {
		t.Fatal("repeated 401 default page stayed valid")
	}
	if second.Reason != pkg.ErrFuzzyCompareFailed.Error() {
		t.Fatalf("reason = %q, want %q", second.Reason, pkg.ErrFuzzyCompareFailed.Error())
	}
}

func TestFuzzyStatusLearnsAndSuppressesDefaultResponseVariants(t *testing.T) {
	withStatusFilters(t)
	pool := newTestBrutePoolForCompare(t)

	results := []*baseline.Baseline{
		newCompareBaseline(500, "/temp.zip.2", "json data "+strings.Repeat("a", 120)),
		newCompareBaseline(500, "/temp.zip.zip", "json data "+strings.Repeat("b", 122)),
		newCompareBaseline(500, "/jolokia/exec/ch.qos.logback.classic", "json data "+strings.Repeat("c", 220)),
	}
	for _, result := range results {
		result.Source = parsers.AppendRuleSource
		pool.handleBaseline(result)
		drainOutput(t, pool)
		if result.IsValid {
			t.Fatalf("%s stayed valid; fuzzy status default variants should be suppressed", result.Path)
		}
		if !result.IsFuzzy {
			t.Fatalf("%s was not marked fuzzy", result.Path)
		}
		if result.Reason != pkg.ErrFuzzyCompareFailed.Error() {
			t.Fatalf("%s reason = %q, want %q", result.Path, result.Reason, pkg.ErrFuzzyCompareFailed.Error())
		}
	}

	if got := len(pool.fuzzyBaselines[500]); got < 2 {
		t.Fatalf("learned fuzzy 500 baselines = %d, want multiple default variants", got)
	}
}

func TestAdaptiveFuzzyBaselineDoesNotLearnSuccessStatus(t *testing.T) {
	withStatusFilters(t)
	pool := newTestBrutePoolForCompare(t)

	result := newCompareBaseline(200, "/admin", strings.Repeat("admin panel ", 8))
	result.Source = parsers.AppendSource
	pool.handleBaseline(result)
	drainOutput(t, pool)

	if !result.IsValid {
		t.Fatalf("200 result was filtered: %s", result.Reason)
	}
	if _, ok := pool.baselines[200]; ok {
		t.Fatal("200 status should not be learned as adaptive fuzzy baseline")
	}
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

func withStatusFilters(t *testing.T) {
	t.Helper()
	oldWhite := append([]int(nil), pkg.WhiteStatus...)
	oldBlack := append([]int(nil), pkg.BlackStatus...)
	oldFuzzy := append([]int(nil), pkg.FuzzyStatus...)
	oldWAF := append([]int(nil), pkg.WAFStatus...)
	pkg.WhiteStatus = []int{200}
	pkg.BlackStatus = []int{400, 410}
	pkg.FuzzyStatus = []int{500, 501, 502, 503, 301, 302, 404}
	pkg.WAFStatus = []int{493, 418, 1020, 406, 429, 412}
	t.Cleanup(func() {
		pkg.WhiteStatus = oldWhite
		pkg.BlackStatus = oldBlack
		pkg.FuzzyStatus = oldFuzzy
		pkg.WAFStatus = oldWAF
	})
}

func newTestBrutePoolForCompare(t *testing.T) *BrutePool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	base := newTestBasePool(ctx, cancel)
	base.Statistor = pkg.NewStatistor("http://example.com")
	pool := &BrutePool{
		Baselines: NewBaselines(),
		BasePool:  base,
	}
	pool.random = newCompareBaseline(200, "/__random__", strings.Repeat("not found ", 8))
	pool.index = newCompareBaseline(200, "/", strings.Repeat("index ", 8))
	return pool
}

func newCompareBaseline(status int, path string, body string) *baseline.Baseline {
	raw := []byte(body)
	u := "http://example.com" + path
	parsed, _ := url.Parse(u)
	return &baseline.Baseline{
		SprayResult: &parsers.SprayResult{
			UrlString:   u,
			Path:        path,
			Host:        "example.com",
			IsValid:     true,
			Status:      status,
			BodyLength:  len(body),
			ContentType: "txt",
			Title:       "txt data",
			Hashes:      parsers.NewHashes(raw),
			Unique:      pkg.CRC16Hash([]byte("example.com")),
		},
		Url:  parsed,
		Body: []byte(body),
		Raw:  raw,
	}
}

func drainOutput(t *testing.T, pool *BrutePool) {
	t.Helper()
	select {
	case <-pool.OutputCh:
		pool.Outwg.Done()
	default:
	}
	for {
		select {
		case <-pool.FuzzyCh:
			pool.Outwg.Done()
		default:
			return
		}
	}
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

func TestPutToOutputSnapshotsBaseline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	bl := newTestBaseline()
	bl.Frameworks = common.Frameworks{
		"nginx": common.NewFramework("nginx", common.FrameFromFingers),
	}
	bl.Title = "before"
	pool.putToOutput(bl)

	got := <-pool.OutputCh
	pool.Outwg.Done()
	bl.Title = "after"
	bl.Frameworks["apache"] = common.NewFramework("apache", common.FrameFromFingers)

	if got.Title != "before" {
		t.Fatalf("snapshot title = %q, want before", got.Title)
	}
	if _, ok := got.Frameworks["apache"]; ok {
		t.Fatal("output snapshot shares Frameworks map with original baseline")
	}
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
		if bl.IsValid {
			t.Fatal("fuzzy output snapshot should not stay valid")
		}
	case <-time.After(time.Second):
		t.Fatal("putToFuzzy: receive timed out")
	}
	pool.Outwg.Done()
	pool.Outwg.Wait()
}

func TestPutToFuzzySnapshotsBaseline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := newTestBasePool(ctx, cancel)

	bl := newTestBaseline()
	bl.Frameworks = common.Frameworks{
		"nginx": common.NewFramework("nginx", common.FrameFromFingers),
	}
	bl.Title = "before"
	pool.putToFuzzy(bl)

	got := <-pool.FuzzyCh
	pool.Outwg.Done()
	bl.Title = "after"
	bl.Frameworks["apache"] = common.NewFramework("apache", common.FrameFromFingers)

	if got.Title != "before" {
		t.Fatalf("snapshot title = %q, want before", got.Title)
	}
	if _, ok := got.Frameworks["apache"]; ok {
		t.Fatal("fuzzy snapshot shares Frameworks map with original baseline")
	}
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

	// simulate Handler — must wg.Done() to match sendProcess's wg.Add(1)
	go func() {
		defer close(pool.handlerDone)
		for range pool.processCh {
			pool.wg.Done()
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
			pool.wg.Done()
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

// ---------------------------------------------------------------------------
// Regression: scopeLocker must release on panic (defer)
// ---------------------------------------------------------------------------

func TestScopeLocker_PanicReleasesLock(t *testing.T) {
	pool := &BrutePool{
		BasePool:  &BasePool{},
		scopeurls: make(map[string]struct{}),
	}

	func() {
		defer func() { recover() }()
		pool.scopeLocker.Lock()
		defer pool.scopeLocker.Unlock()
		panic("simulated panic inside critical section")
	}()

	mustFinish(t, 2*time.Second, "scopeLocker not released after panic", func() {
		pool.scopeLocker.Lock()
		pool.scopeLocker.Unlock()
	})
}

// ---------------------------------------------------------------------------
// Regression: ants pool with invalid thread count must return error
// ---------------------------------------------------------------------------

func TestNewBrutePool_ValidThread(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := &Config{
		BaseURL:   "http://example.com",
		Thread:    2,
		RateLimit: 1,
		Request:   &ihttp.RequestConfig{},
	}
	pool, err := NewBrutePool(ctx, config)
	if err != nil {
		t.Fatalf("NewBrutePool with valid config: %v", err)
	}
	if pool.reqPool == nil {
		t.Fatal("reqPool should not be nil")
	}
	if pool.scopePool == nil {
		t.Fatal("scopePool should not be nil")
	}
	pool.Cancel()
	close(pool.processCh)
	<-pool.handlerDone
}

// ---------------------------------------------------------------------------
// handleBaseline processes all items and exits on cancel + close
// ---------------------------------------------------------------------------

func TestHandleBaseline_CancelMidProcessing(t *testing.T) {
	withStatusFilters(t)
	ctx, cancel := context.WithCancel(context.Background())
	base := newTestBasePool(ctx, cancel)
	base.Statistor = pkg.NewStatistor("http://example.com")
	base.Bar = &pkg.Bar{}
	pool := &BrutePool{
		Baselines: NewBaselines(),
		BasePool:  base,
		uniques:   make(map[uint16]struct{}),
	}
	pool.random = newCompareBaseline(200, "/__random__", strings.Repeat("not found ", 8))
	pool.index = newCompareBaseline(200, "/", strings.Repeat("index ", 8))

	go pool.Handler()

	for i := 0; i < 20; i++ {
		bl := newCompareBaseline(404, "/test", "not found")
		bl.Source = parsers.WordSource
		pool.wg.Add(1)
		pool.processCh <- bl
	}

	cancel()

	mustFinish(t, 5*time.Second, "Handler did not exit after cancel+close", func() {
		close(pool.processCh)
		<-pool.handlerDone
	})
}

// ---------------------------------------------------------------------------
// Map access in Handler is single-threaded (race detector must not fire)
// ---------------------------------------------------------------------------

func TestHandleBaseline_MapAccessSingleThreaded(t *testing.T) {
	withStatusFilters(t)
	pool := newTestBrutePoolForCompare(t)
	pool.uniques = make(map[uint16]struct{})
	pool.Bar = &pkg.Bar{}

	go pool.Handler()

	for i := 0; i < 50; i++ {
		bl := newCompareBaseline(200+i%5, "/path"+string(rune('a'+i%26)), strings.Repeat("body", 10+i))
		bl.Source = parsers.WordSource
		pool.wg.Add(1)
		pool.processCh <- bl
	}

	close(pool.processCh)

	mustFinish(t, 5*time.Second, "Handler did not finish", func() {
		<-pool.handlerDone
	})
	drainOutput(t, pool)

	if pool.Statistor.ReqTotal != 50 {
		t.Fatalf("ReqTotal = %d, want 50", pool.Statistor.ReqTotal)
	}
}
