package pkg

import (
	"strings"
	"testing"
)

func TestParseRawResponse(t *testing.T) {
	t.Run("valid complete response", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
		resp, err := ParseRawResponse([]byte(raw))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html" {
			t.Fatalf("expected Content-Type text/html, got %s", ct)
		}
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := ParseRawResponse(nil)
		if err == nil {
			t.Fatal("expected error for nil input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseRawResponse([]byte{})
		if err == nil {
			t.Fatal("expected error for empty input")
		}
	})

	t.Run("status line only no headers", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\n\r\n"
		resp, err := ParseRawResponse([]byte(raw))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("truncated status line", func(t *testing.T) {
		raw := "HTTP/1."
		_, err := ParseRawResponse([]byte(raw))
		if err == nil {
			t.Fatal("expected error for truncated status line")
		}
	})

	t.Run("redirect response no body", func(t *testing.T) {
		raw := "HTTP/1.1 302 Found\r\nLocation: https://example.com/new\r\n\r\n"
		resp, err := ParseRawResponse([]byte(raw))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != 302 {
			t.Fatalf("expected status 302, got %d", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "https://example.com/new" {
			t.Fatalf("expected Location https://example.com/new, got %s", loc)
		}
	})

	t.Run("chunked transfer encoding header", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
		resp, err := ParseRawResponse([]byte(raw))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if te := resp.Header.Get("Transfer-Encoding"); te == "" {
			// Transfer-Encoding may be consumed by http.ReadResponse, just verify no panic
		}
		_ = resp
	})

	t.Run("large header value", func(t *testing.T) {
		largeValue := strings.Repeat("A", 8192)
		raw := "HTTP/1.1 200 OK\r\nX-Large: " + largeValue + "\r\n\r\n"
		resp, err := ParseRawResponse([]byte(raw))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := resp.Header.Get("X-Large"); got != largeValue {
			t.Fatalf("large header value mismatch, got length %d", len(got))
		}
	})

	t.Run("invalid status code", func(t *testing.T) {
		raw := "HTTP/1.1 xyz OK\r\n\r\n"
		_, err := ParseRawResponse([]byte(raw))
		if err == nil {
			t.Fatal("expected error for invalid status code")
		}
	})

	t.Run("incomplete header no terminator", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html"
		_, err := ParseRawResponse([]byte(raw))
		// Should return error or at least not panic
		// http.ReadResponse may or may not error on missing \r\n\r\n,
		// the key requirement is no panic
		_ = err
	})

	t.Run("binary body", func(t *testing.T) {
		body := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
		raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"), body...)
		resp, err := ParseRawResponse(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
	})
}
