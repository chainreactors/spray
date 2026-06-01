package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainreactors/logs"
)

func TestFormatParsesResultFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "results.json")

	content := `{"url":"http://127.0.0.1:80","host":"127.0.0.1","title":"home","status":200}
`
	if err := os.WriteFile(input, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	oldLog := logs.Log
	logs.Log = logs.NewLogger(oldLog.Level)
	logs.Log.SetOutput(&out)
	defer func() {
		logs.Log = oldLog
	}()

	opt := Option{}
	opt.Format = input
	opt.OutputProbe = "url,title"
	Format(opt)

	if got := strings.TrimSpace(out.String()); got != "http://127.0.0.1:80\thome" {
		t.Fatalf("unexpected formatted output: got %q", got)
	}
}
