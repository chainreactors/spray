package ihttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

type seenReqRequest struct {
	userAgent string
	accept    string
	secCHUA   string
	host      string
	body      string
}

func TestReqClientAppliesChromeImpersonationHeaders(t *testing.T) {
	seenCh := make(chan seenReqRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seenReqRequest{
			userAgent: r.Header.Get("User-Agent"),
			accept:    r.Header.Get("Accept"),
			secCHUA:   r.Header.Get("Sec-Ch-Ua"),
			host:      r.Host,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Type:              REQ,
		Timeout:           5 * time.Second,
		Thread:            1,
		ClientFingerprint: "chrome",
	})
	req, err := (&RequestConfig{Method: http.MethodGet}).Build(context.Background(), REQ, server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode(), http.StatusNoContent)
	}

	seen := <-seenCh
	if !strings.Contains(seen.userAgent, "Chrome/120") {
		t.Fatalf("chrome user-agent not applied: %q", seen.userAgent)
	}
	if seen.accept == "" || seen.accept == "*/*" {
		t.Fatalf("browser accept header not applied: %q", seen.accept)
	}
	if seen.secCHUA == "" {
		t.Fatal("chrome sec-ch-ua header not applied")
	}
}

func TestReqClientPreservesExplicitHeadersHostAndBody(t *testing.T) {
	seenCh := make(chan seenReqRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		seenCh <- seenReqRequest{
			userAgent: r.Header.Get("User-Agent"),
			accept:    r.Header.Get("Accept"),
			host:      r.Host,
			body:      string(body),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	headers := make(http.Header)
	headers.Set("User-Agent", "spray-test-agent")
	headers.Set("Accept", "application/json")
	client := NewClient(&ClientConfig{
		Type:              REQ,
		Timeout:           5 * time.Second,
		Thread:            1,
		ClientFingerprint: "chrome",
	})
	req, err := (&RequestConfig{
		Method:  http.MethodPost,
		Headers: headers,
		Host:    "virtual.example",
		Body:    []byte("hello=req"),
	}).Build(context.Background(), REQ, server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode(), http.StatusOK)
	}

	seen := <-seenCh
	if seen.userAgent != "spray-test-agent" {
		t.Fatalf("user-agent override lost: got %q", seen.userAgent)
	}
	if seen.accept != "application/json" {
		t.Fatalf("accept override lost: got %q", seen.accept)
	}
	if seen.host != "virtual.example" {
		t.Fatalf("host override lost: got %q", seen.host)
	}
	if seen.body != "hello=req" {
		t.Fatalf("body lost: got %q", seen.body)
	}
}

func TestStandardClientFingerprintTLSRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("standard-ok"))
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Type:              STANDARD,
		Timeout:           5 * time.Second,
		Thread:            1,
		ClientFingerprint: "chrome",
	})
	req, err := (&RequestConfig{Method: http.MethodGet}).Build(context.Background(), STANDARD, server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode(), http.StatusOK)
	}
	if got := string(resp.Body()); got != "standard-ok" {
		t.Fatalf("unexpected body: got %q", got)
	}
}

func TestFastClientFingerprintTLSRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fast-ok"))
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Type:              FAST,
		Timeout:           5 * time.Second,
		Thread:            1,
		ClientFingerprint: "chrome",
		IsTLS:             true,
	})
	req, err := (&RequestConfig{Method: http.MethodGet}).Build(context.Background(), FAST, server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer fasthttp.ReleaseRequest(req.FastRequest)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer fasthttp.ReleaseResponse(resp.FastResponse)

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode(), http.StatusOK)
	}
	if got := string(resp.Body()); got != "fast-ok" {
		t.Fatalf("unexpected body: got %q", got)
	}
}
