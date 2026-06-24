package core

import (
	"testing"

	"github.com/chainreactors/spray/core/ihttp"
)

func TestPrepareConfigAutoStillDefaultsPathToFast(t *testing.T) {
	runner := &Runner{
		Option: &Option{
			RequestOptions: RequestOptions{Method: "GET"},
			MiscOptions:    MiscOptions{Mod: "path", Timeout: 5, Threads: 20},
		},
		Headers:    make(map[string]string),
		ClientType: ihttp.Auto,
	}

	config := runner.PrepareConfig()
	if config.ClientType != ihttp.FAST {
		t.Fatalf("unexpected auto client: got %d want %d", config.ClientType, ihttp.FAST)
	}
	if config.Request.Headers.Get("User-Agent") == "" {
		t.Fatal("default user-agent should still be set for fast client")
	}
	if config.Request.Headers.Get("Accept") != "*/*" {
		t.Fatalf("unexpected default accept header: %q", config.Request.Headers.Get("Accept"))
	}
}

func TestPrepareConfigReqKeepsBrowserProfileHeadersAvailable(t *testing.T) {
	runner := &Runner{
		Option: &Option{
			RequestOptions: RequestOptions{Method: "GET"},
			MiscOptions:    MiscOptions{Mod: "host", Timeout: 5, Threads: 20, ClientFingerprint: "safari"},
		},
		Headers:    make(map[string]string),
		ClientType: ihttp.REQ,
	}

	config := runner.PrepareConfig()
	if config.ClientType != ihttp.REQ {
		t.Fatalf("unexpected req client: got %d want %d", config.ClientType, ihttp.REQ)
	}
	if config.ClientFingerprint != "safari" {
		t.Fatalf("fingerprint not propagated: got %q", config.ClientFingerprint)
	}
	if got := config.Request.Headers.Get("User-Agent"); got != "" {
		t.Fatalf("req should let impersonation provide user-agent, got %q", got)
	}
	if got := config.Request.Headers.Get("Accept"); got != "" {
		t.Fatalf("req should let impersonation provide accept, got %q", got)
	}
}
