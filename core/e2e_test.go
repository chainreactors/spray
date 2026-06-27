package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

func TestE2E_ForceDoesNotRunBruteAfterInitFailure(t *testing.T) {
	var wordHits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			atomic.AddInt64(&wordHits, 1)
			w.WriteHeader(200)
			fmt.Fprint(w, "admin")
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/__random__" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack init response: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer server.Close()

	wordlist := writeTempFile(t, "admin\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--index=/",
		"--random=/__random__",
		"--force",
		"--client", "standard",
		"--no-bar",
		"-q",
		"--no-stat",
		"-t", "1",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}

	if got := atomic.LoadInt64(&wordHits); got != 0 {
		t.Fatalf("word requests after init failure = %d, want 0", got)
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

func TestE2E_QuietSuppressesCheckOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(400)
		fmt.Fprint(w, "<html><body>bad request</body></html>")
	}))
	defer server.Close()

	urlFile := writeTempFile(t, server.URL+"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := runSpray(t, ctx, []string{
		"-l", urlFile,
		"-q",
		"--no-bar",
		"--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("quiet check mode output = %q, want empty", out)
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

// ---------------------------------------------------------------------------
// E2E: scan with --extract flags completes without error
// ---------------------------------------------------------------------------

func extractServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<html><head><title>Page %s</title></head><body>
			ip=10.20.30.40 email=test@example.com
			token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE
			password="s3cret" version: 1.2.3
			AccessKeyId=AKIAIOSFODNN7EXAMPLE unique content %s
		</body></html>`, r.URL.Path, r.URL.Path)
	}))
}

func TestE2E_ExtractByTag(t *testing.T) {
	server := extractServer()
	defer server.Close()

	wordlist := writeTempFile(t, "xleakpage1\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--extract", "ip",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --extract ip: %v", err)
	}
}

func TestE2E_ExtractMultipleTags(t *testing.T) {
	server := extractServer()
	defer server.Close()

	wordlist := writeTempFile(t, "xleakpage2\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--extract", "ip",
		"--extract", "mail",
		"--extract", "jwt",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with multiple --extract: %v", err)
	}
}

func TestE2E_ExtractCategoryTag(t *testing.T) {
	server := extractServer()
	defer server.Close()

	wordlist := writeTempFile(t, "xleakpage3\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--extract", "cloud",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --extract cloud: %v", err)
	}
}

func TestE2E_ExtractCustomRegex(t *testing.T) {
	server := extractServer()
	defer server.Close()

	wordlist := writeTempFile(t, "xleakpage4\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--extract", `version[\s:]+(\d+\.\d+\.\d+)`,
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with custom regex extract: %v", err)
	}
}

func TestE2E_ReconPlugin(t *testing.T) {
	server := extractServer()
	defer server.Close()

	wordlist := writeTempFile(t, "xleakpage5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--recon",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --recon: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E: --crawl recursively follows URLs found in pages
// ---------------------------------------------------------------------------

func TestE2E_CrawlRecursive(t *testing.T) {
	var visited sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited.Store(r.URL.Path, true)
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><head><title>Index Page</title></head><body>`+
				`<a href="/crawlpage1">link</a>`+
				` unique index content that differs from random baseline page `+
				strings.Repeat("index-padding ", 20)+
				`</body></html>`)
		case "/crawlpage1":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><head><title>CrawlPage1</title></head><body>`+
				`<a href="/crawlpage2">link</a>`+
				` unique page1 content that differs from random baseline page `+
				strings.Repeat("page1-padding ", 20)+
				`</body></html>`)
		case "/crawlpage2":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><head><title>CrawlPage2</title></head><body>`+
				` crawl reached page2 with unique content `+
				strings.Repeat("page2-padding ", 20)+
				`</body></html>`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	dumpFile := filepath.Join(t.TempDir(), "crawl_dump.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"--crawl",
		"--crawl-depth", "5",
		"--dump-file", dumpFile,
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --crawl: %v", err)
	}

	dump, err := os.ReadFile(dumpFile)
	if err != nil {
		t.Fatalf("read dump file: %v", err)
	}
	dumpStr := string(dump)

	if !strings.Contains(dumpStr, "/crawlpage1") {
		t.Error("crawl did not reach /crawlpage1")
	}
	if !strings.Contains(dumpStr, "/crawlpage2") {
		_, reached := visited.Load("/crawlpage2")
		t.Errorf("crawl did not recursively reach /crawlpage2 (server saw request: %v, dump length: %d)", reached, len(dump))
	}
}

func TestE2E_CrawlHonorsMaxLength(t *testing.T) {
	var visited sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited.Store(r.URL.Path, true)
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><head><title>Index Page</title></head><body>`)
			fmt.Fprint(w, strings.Repeat("padding ", 200))
			fmt.Fprint(w, `<a href="/after-limit">late link</a></body></html>`)
		case "/after-limit":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><body>this page should not be crawled when max-length is 1KB</body></html>`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"--crawl",
		"--crawl-depth", "1",
		"--max-length", "1",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --crawl: %v", err)
	}

	if _, ok := visited.Load("/after-limit"); ok {
		t.Fatal("crawl followed a link located beyond --max-length 1KB")
	}
}

func TestE2E_CrawlRelativeAssetsUnderBasePath(t *testing.T) {
	var visited sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited.Store(r.URL.Path, true)
		switch r.URL.Path {
		case "/app/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><head><title>SPA</title>`+
				`<script src="./static/js/app.js"></script>`+
				`</head><body>`+
				` unique spa index content that differs from random baseline page `+
				strings.Repeat("spa-padding ", 20)+
				`</body></html>`)
		case "/app/static/js/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(200)
			fmt.Fprint(w, `console.log("app asset reached");`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL + "/app/#/login",
		"--crawl",
		"--crawl-depth", "2",
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs with --crawl: %v", err)
	}

	if _, ok := visited.Load("/app/static/js/app.js"); !ok {
		_, duplicated := visited.Load("/app/app/static/js/app.js")
		t.Fatalf("crawl did not request /app/static/js/app.js (duplicated path requested: %v)", duplicated)
	}
	if _, duplicated := visited.Load("/app/app/static/js/app.js"); duplicated {
		t.Fatal("crawl requested duplicated base path /app/app/static/js/app.js")
	}
}

// ---------------------------------------------------------------------------
// E2E: --recon extracts data from invalid baselines (not just valid ones)
// ---------------------------------------------------------------------------

func TestE2E_ExtractOnInvalidBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><title>Index</title><body>index page</body></html>`)
		default:
			w.WriteHeader(200)
			fmt.Fprintf(w, `<html><body>
				Generic response ip=192.168.1.100 email=leak@internal.corp
				token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE
			</body></html>`)
		}
	}))
	defer server.Close()

	wordlist := writeTempFile(t, "secret1\nsecret2\nsecret3\nsecret4\nsecret5\n")
	dumpFile := filepath.Join(t.TempDir(), "extract_dump.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := runSpray(t, ctx, []string{
		"-u", server.URL,
		"-d", wordlist,
		"--recon",
		"--dump-file", dumpFile,
		"--no-bar", "-q", "--no-stat",
	})
	if err != nil {
		t.Fatalf("RunWithArgs: %v", err)
	}

	dump, err := os.ReadFile(dumpFile)
	if err != nil {
		t.Fatalf("read dump file: %v", err)
	}

	hasExtractOnInvalid := false
	for _, line := range strings.Split(strings.TrimSpace(string(dump)), "\n") {
		if line == "" {
			continue
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if url, ok := result["url"].(string); ok && strings.HasSuffix(url, "/") {
			continue
		}
		extracts, _ := result["extracts"].([]interface{})
		if len(extracts) > 0 {
			hasExtractOnInvalid = true
			break
		}
	}
	if !hasExtractOnInvalid {
		t.Error("expected extract results on invalid baselines, but found none")
	}
}
