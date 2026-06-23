package core

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func generateWordlist(n int) string {
	bases := []string{
		"admin", "login", "api", "docs", "swagger", "health", "status",
		"config", "test", "dev", "staging", "debug", "console", "dashboard",
		"portal", "gateway", "proxy", "server", "monitor", "metrics",
		"info", "version", "ping", "actuator", "env", "trace", "dump",
		"backup", "static", "assets", "images", "css", "js", "fonts",
		"uploads", "media", "files", "data", "db", "cache", "tmp",
		"log", "error", "report", "download", "export", "search",
		"auth", "oauth", "sso", "token", "user", "account", "profile",
		"settings", "register", "reset", "password", "system", "manage",
		"blog", "news", "post", "page", "article", "category", "feed",
		"json", "xml", "yaml", "csv", "robots", "favicon", "security",
	}
	exts := []string{"", ".html", ".php", ".json", ".xml", "/index", "/api", "/v1"}
	var words []string
	for i := 0; i < n; i++ {
		base := bases[i%len(bases)]
		ext := exts[i/len(bases)%len(exts)]
		suffix := ""
		if i >= len(bases)*len(exts) {
			suffix = fmt.Sprintf("%d", i)
		}
		words = append(words, base+suffix+ext)
	}
	return strings.Join(words, "\n")
}

func TestE2E_CIDR_1000Words(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long CIDR test in short mode")
	}

	var handlers []*httptest.Server
	for i := 0; i < 16; i++ {
		idx := i
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate varied responses per "host"
			switch {
			case idx%4 == 0:
				// Normal site: 200 for index, 404 for most, 200 for /admin
				if r.URL.Path == "/" || r.URL.Path == "/admin" {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(200)
					fmt.Fprintf(w, "<html><title>Server %d</title><body>content %s</body></html>", idx, r.URL.Path)
				} else {
					w.WriteHeader(404)
					fmt.Fprint(w, "not found")
				}
			case idx%4 == 1:
				// WAF: always same response
				w.WriteHeader(200)
				fmt.Fprint(w, "<html><body>Access Denied</body></html>")
			case idx%4 == 2:
				// Slow server
				time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
				w.WriteHeader(200)
				fmt.Fprintf(w, "slow response %s", r.URL.Path)
			case idx%4 == 3:
				// Error server
				w.WriteHeader(500)
				fmt.Fprint(w, "internal error")
			}
		}))
		handlers = append(handlers, s)
	}
	defer func() {
		for _, s := range handlers {
			s.Close()
		}
	}()

	// Build URL list (simulating CIDR scan in check mode)
	var urls []string
	for _, s := range handlers {
		urls = append(urls, s.URL)
	}
	urlFile := writeTempFile(t, strings.Join(urls, "\n"))
	wordFile := writeTempFile(t, generateWordlist(1000))

	// Scale tests: find the hang boundary
	for _, tc := range []struct {
		name    string
		targets int
		words   int
		pool    int
		timeout time.Duration
	}{
		{"4t_100w", 4, 100, 2, 30 * time.Second},
		{"8t_100w", 8, 100, 4, 30 * time.Second},
		{"16t_100w", 16, 100, 5, 60 * time.Second},
		{"4t_500w", 4, 500, 2, 60 * time.Second},
		{"16t_500w", 16, 500, 5, 120 * time.Second},
	} {
		tc := tc
		t.Run("Brute_"+tc.name, func(t *testing.T) {
			testUrlFile := writeTempFile(t, strings.Join(urls[:tc.targets], "\n"))
			testWordFile := writeTempFile(t, generateWordlist(tc.words))

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				_, err := runSpray(t, ctx, []string{
					"-l", testUrlFile,
					"-d", testWordFile,
					"--no-bar", "-q", "--no-stat",
					"-t", "10",
					"-P", fmt.Sprintf("%d", tc.pool),
				})
				done <- err
			}()

			select {
			case err := <-done:
				if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
					t.Logf("returned: %v", err)
				}
			case <-time.After(tc.timeout + 10*time.Second):
				cancel()
				t.Fatalf("HANG: did not exit within %v", tc.timeout+10*time.Second)
			}
		})
	}

	// Diagnostic: 2 targets x 500 words, with goroutine dump on timeout
	t.Run("Brute_2t_500w_diag", func(t *testing.T) {
		diagUrlFile := writeTempFile(t, strings.Join(urls[:2], "\n"))
		diagWordFile := writeTempFile(t, generateWordlist(500))

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := runSpray(t, ctx, []string{
				"-l", diagUrlFile,
				"-d", diagWordFile,
				"--no-bar", "-q", "--no-stat",
				"-t", "10",
				"-P", "2",
			})
			done <- err
		}()

		select {
		case err := <-done:
			if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
				t.Logf("returned: %v", err)
			}
			t.Log("diagnostic test completed OK")
		case <-time.After(20 * time.Second):
			buf := make([]byte, 1<<22)
			n := runtime.Stack(buf, true)
			stacks := string(buf[:n])
			// Only show goroutines stuck in spray code
			var relevant []string
			for _, block := range strings.Split(stacks, "\n\n") {
				if strings.Contains(block, "chainreactors/spray") &&
					!strings.Contains(block, "httptest") &&
					!strings.Contains(block, "testing.tRunner") {
					relevant = append(relevant, block)
				}
			}
			t.Logf("STUCK GOROUTINES (%d):\n%s", len(relevant), strings.Join(relevant, "\n\n"))
			cancel()
			t.Fatal("HANG DETECTED in diagnostic test")
		}
	})

	// Test 2: check mode with 16 targets
	t.Run("CheckMode_16Targets", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := runSpray(t, ctx, []string{
				"-l", urlFile,
				"--no-bar", "-q", "--no-stat",
			})
			done <- err
		}()

		select {
		case err := <-done:
			if err != nil && err != context.DeadlineExceeded {
				t.Logf("spray returned error (acceptable): %v", err)
			}
			t.Log("check mode completed without hang")
		case <-time.After(30 * time.Second):
			cancel()
			t.Fatal("HANG DETECTED: check mode did not complete within 30s")
		}
	})

	// Test 3: brute mode with cancel mid-flight (many in-flight requests)
	t.Run("BruteMode_CancelMidFlight", func(t *testing.T) {
		if raceEnabled {
			t.Skip("cancel stress test is covered by the normal test job; skip under race detector")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := runSpray(t, ctx, []string{
				"-l", urlFile,
				"-d", wordFile,
				"--no-bar", "-q", "--no-stat",
				"-t", "20",
				"-P", "5",
			})
			done <- err
		}()

		grace := 60 * time.Second
		select {
		case <-done:
			t.Log("cancel mid-flight completed without hang")
		case <-time.After(grace):
			t.Fatalf("HANG DETECTED: cancel mid-flight did not exit within %s", grace)
		}
	})
}
