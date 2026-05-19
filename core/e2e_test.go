package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}

func runSpray(t *testing.T, ctx context.Context, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := RunWithArgs(ctx, args, RunOptions{
		Output:        &buf,
		DefaultConfig: filepath.Join(t.TempDir(), "noconfig.yaml"),
		Version:       "test",
	})
	return buf.String(), err
}

// ---------------------------------------------------------------------------
// E2E: normal brute scan completes successfully
// ---------------------------------------------------------------------------

func TestE2E_NormalBruteScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			fmt.Fprint(w, "<html><head><title>Admin Panel</title></head><body>admin content here with enough text to differ from 404</body></html>")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	wordlist := writeTempFile(t, "admin\nfoo\nbar\nbaz\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--no-bar",
		"-q",
		"--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E: context cancellation mid-scan
// ---------------------------------------------------------------------------

func TestE2E_ContextCancellation(t *testing.T) {
	var reqCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer server.Close()

	var words []string
	for i := 0; i < 500; i++ {
		words = append(words, fmt.Sprintf("word%d", i))
	}
	wordlist := writeTempFile(t, strings.Join(words, "\n"))

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	goroutinesBefore := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	_, _ = runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--no-bar",
		"-q",
		"--no-stat",
		"-t", "4",
	})

	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	reqs := atomic.LoadInt64(&reqCount)
	if reqs >= 500 {
		t.Logf("warning: all %d requests completed before cancel fired", reqs)
	}

	if goroutinesAfter > goroutinesBefore+10 {
		t.Errorf("goroutine leak: before=%d after=%d", goroutinesBefore, goroutinesAfter)
	}
}

// ---------------------------------------------------------------------------
// E2E: server errors trigger error threshold
// ---------------------------------------------------------------------------

func TestE2E_ServerErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "internal server error")
	}))
	defer server.Close()

	var words []string
	for i := 0; i < 100; i++ {
		words = append(words, fmt.Sprintf("err%d", i))
	}
	wordlist := writeTempFile(t, strings.Join(words, "\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--no-bar",
		"-q",
		"--no-stat",
	})
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E: WAF-like behavior (identical responses)
// ---------------------------------------------------------------------------

func TestE2E_WAFBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body>Access Denied by WAF - your request has been blocked</body></html>")
	}))
	defer server.Close()

	wordlist := writeTempFile(t, "admin\nlogin\nbackup\nconfig\ntest\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--no-bar",
		"-q",
		"--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E: multi-target check mode
// ---------------------------------------------------------------------------

func TestE2E_MultiTargetCheck(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "server response for %s", r.Host)
	})

	s1 := httptest.NewServer(handler)
	defer s1.Close()
	s2 := httptest.NewServer(handler)
	defer s2.Close()
	s3 := httptest.NewServer(handler)
	defer s3.Close()

	urlFile := writeTempFile(t, fmt.Sprintf("%s\n%s\n%s\n", s1.URL, s2.URL, s3.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-l", urlFile,
		"--no-bar",
		"-q",
		"--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E: mixed status codes with valid findings
// ---------------------------------------------------------------------------

func TestE2E_MixedStatusCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(200)
			fmt.Fprint(w, "<html><head><title>Login</title></head><body>login form with unique content</body></html>")
		case "/secret":
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden - you shall not pass this unique forbidden page")
		case "/redirect":
			http.Redirect(w, r, "/login", 302)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	wordlist := writeTempFile(t, "login\nsecret\nredirect\nnotexist1\nnotexist2\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--no-bar",
		"-q",
		"--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}
}
