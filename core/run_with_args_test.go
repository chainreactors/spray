package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunWithArgsVersion(t *testing.T) {
	var out bytes.Buffer

	if err := RunWithArgs(context.Background(), []string{"--version"}, RunOptions{
		Output:  &out,
		Version: "dev",
	}); err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(out.String()); got != "dev" {
		t.Fatalf("unexpected version output: got %q want %q", got, "dev")
	}
}

func TestRunWithArgsHelp(t *testing.T) {
	var out bytes.Buffer

	if err := RunWithArgs(context.Background(), []string{"--help"}, RunOptions{
		Output: &out,
	}); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); !strings.Contains(got, "WIKI: https://chainreactors.github.io/wiki/spray") ||
		!strings.Contains(got, "spray -u http://example.com") {
		t.Fatalf("unexpected help output: %q", got)
	}
}
