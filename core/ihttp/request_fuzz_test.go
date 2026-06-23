package ihttp

import (
	"context"
	"net/http"
	"testing"
)

func TestBuild_FuzzInPath(t *testing.T) {
	rc := &RequestConfig{
		Method:  "GET",
		Headers: make(http.Header),
		Path:    "/api/{{FUZZ}}/info",
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	uri := req.URI()
	if uri != "http://example.com/api/admin/info" {
		t.Errorf("URI = %q, want http://example.com/api/admin/info", uri)
	}
}

func TestBuild_FuzzInHost(t *testing.T) {
	rc := &RequestConfig{
		Method:  "GET",
		Headers: make(http.Header),
		Host:    "{{FUZZ}}.internal.com",
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://10.0.0.1", "/test", "", "dev")
	if err != nil {
		t.Fatal(err)
	}
	host := req.Host()
	if host != "dev.internal.com" {
		t.Errorf("Host = %q, want dev.internal.com", host)
	}
}

func TestBuild_FuzzInHeader(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer {{FUZZ}}")
	headers.Set("X-Normal", "static-value")

	rc := &RequestConfig{
		Method:  "GET",
		Headers: headers,
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "/test", "", "token123")
	if err != nil {
		t.Fatal(err)
	}
	authVal := req.StandardRequest.Header.Get("Authorization")
	if authVal != "Bearer token123" {
		t.Errorf("Authorization = %q, want 'Bearer token123'", authVal)
	}
	normalVal := req.StandardRequest.Header.Get("X-Normal")
	if normalVal != "static-value" {
		t.Errorf("X-Normal = %q, want 'static-value'", normalVal)
	}
}

func TestBuild_FuzzInBody(t *testing.T) {
	rc := &RequestConfig{
		Method:  "POST",
		Headers: make(http.Header),
		Body:    []byte(`{"user": "{{FUZZ}}"}`),
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "/login", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, _ := req.StandardRequest.Body.Read(buf)
	body := string(buf[:n])
	expected := `{"user": "admin"}`
	if body != expected {
		t.Errorf("Body = %q, want %q", body, expected)
	}
}

func TestBuild_FuzzInQuery(t *testing.T) {
	rc := &RequestConfig{
		Method:   "GET",
		Headers:  make(http.Header),
		RawQuery: "key={{FUZZ}}&other=static",
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "/search", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	uri := req.URI()
	if uri != "http://example.com/search?key=test&other=static" {
		t.Errorf("URI = %q, want http://example.com/search?key=test&other=static", uri)
	}
}

func TestBuild_NoFuzz(t *testing.T) {
	rc := &RequestConfig{
		Method:  "GET",
		Headers: make(http.Header),
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "/static", "", "ignored")
	if err != nil {
		t.Fatal(err)
	}
	uri := req.URI()
	if uri != "http://example.com/static" {
		t.Errorf("URI = %q, want http://example.com/static", uri)
	}
}

func TestBuild_FuzzMultipleFields(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Token", "{{FUZZ}}")

	rc := &RequestConfig{
		Method:  "POST",
		Headers: headers,
		Path:    "/user/{{FUZZ}}",
		Host:    "{{FUZZ}}.example.com",
		Body:    []byte(`{"id":"{{FUZZ}}"}`),
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://10.0.0.1", "", "", "abc")
	if err != nil {
		t.Fatal(err)
	}

	if got := req.StandardRequest.Header.Get("X-Token"); got != "abc" {
		t.Errorf("X-Token = %q, want abc", got)
	}
	if got := req.Host(); got != "abc.example.com" {
		t.Errorf("Host = %q, want abc.example.com", got)
	}
	buf := make([]byte, 1024)
	n, _ := req.StandardRequest.Body.Read(buf)
	if got := string(buf[:n]); got != `{"id":"abc"}` {
		t.Errorf("Body = %q, want %s", got, `{"id":"abc"}`)
	}
}

func TestBuild_FastHTTP_FuzzInHeader(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Key", "{{FUZZ}}")

	rc := &RequestConfig{
		Method:  "GET",
		Headers: headers,
	}
	req, err := rc.Build(context.Background(), FAST, "http://example.com", "/test", "", "val123")
	if err != nil {
		t.Fatal(err)
	}
	got := string(req.FastRequest.Header.Peek("X-Key"))
	if got != "val123" {
		t.Errorf("X-Key = %q, want val123", got)
	}
}

func TestBuild_EmptyWord(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Token", "{{FUZZ}}")

	rc := &RequestConfig{
		Method:  "GET",
		Headers: headers,
	}
	req, err := rc.Build(context.Background(), STANDARD, "http://example.com", "/test", "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := req.StandardRequest.Header.Get("X-Token")
	if got != "" {
		t.Errorf("X-Token with empty word = %q, want empty", got)
	}
}
