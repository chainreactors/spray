package baseline

import (
	"testing"

	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/pkg"
	"github.com/valyala/fasthttp"
)

func TestCollectAddsHTTPLanguageExtract(t *testing.T) {
	var fastResp fasthttp.Response
	fastResp.SetStatusCode(200)
	fastResp.Header.Set("Content-Type", "text/html; charset=utf-8")
	fastResp.Header.Set("Content-Language", "en-US")
	fastResp.SetBodyString(`<html lang="en"><body>これは日本語のページです。サービス状態を表示します。</body></html>`)

	resp := &ihttp.Response{FastResponse: &fastResp}
	bl := NewBaseline("https://example.test/", "example.test", resp)
	bl.Collect()

	var found bool
	for _, e := range bl.Extracteds {
		if e.Name == "language" {
			found = true
			if len(e.ExtractResult) != 1 || e.ExtractResult[0] != "ja" {
				t.Fatalf("language extract_result = %v, want [ja]", e.ExtractResult)
			}
			break
		}
	}
	if !found {
		t.Fatal("language extract not found in Extracteds")
	}
}

func TestCollectAddsHTTPLanguageExtractWithoutFingerEngine(t *testing.T) {
	oldEnableAllFingerEngine := pkg.EnableAllFingerEngine
	pkg.EnableAllFingerEngine = false
	t.Cleanup(func() {
		pkg.EnableAllFingerEngine = oldEnableAllFingerEngine
	})

	var fastResp fasthttp.Response
	fastResp.SetStatusCode(200)
	fastResp.Header.Set("Content-Type", "text/html; charset=utf-8")
	fastResp.SetBodyString(`<html lang="en"><body>This is an English product page and the service is available for you from the web console with your account.</body></html>`)

	resp := &ihttp.Response{FastResponse: &fastResp}
	bl := NewBaseline("https://example.test/", "example.test", resp)
	bl.Collect()

	var found bool
	for _, e := range bl.Extracteds {
		if e.Name == "language" {
			found = true
			if len(e.ExtractResult) != 1 || e.ExtractResult[0] != "en" {
				t.Fatalf("language extract_result = %v, want [en]", e.ExtractResult)
			}
			break
		}
	}
	if !found {
		t.Fatal("language extract not found, want language detection even when finger engine is disabled")
	}
}
