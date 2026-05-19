package core

import (
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/spray/pkg"
)

func mustFinishCore(t *testing.T, d time.Duration, msg string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("timeout: %s", msg)
	}
}

func TestRecordStat_ConcurrentSafety(t *testing.T) {
	r := &Runner{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.recordStat(&pkg.Statistor{
				Total:        n,
				ReqTotal:     int32(n * 2),
				FoundNumber:  1,
				FailedNumber: 0,
			})
		}(i)
	}

	mustFinishCore(t, 5*time.Second, "concurrent recordStat deadlocked", func() {
		wg.Wait()
	})

	stats := r.Stats()
	if stats.Requests == 0 {
		t.Fatal("stats.Requests should be > 0 after concurrent writes")
	}
}

func TestRecordStat_NilStat(t *testing.T) {
	r := &Runner{}
	r.recordStat(nil)

	stats := r.Stats()
	if stats.Requests != 0 {
		t.Fatalf("stats.Requests = %d, want 0 for nil stat", stats.Requests)
	}
}
