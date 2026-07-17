package pkg

import (
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func TestExtractHTTPLanguageFromHeadersHTMLMetaAndBody(t *testing.T) {
	attrs := ExtractHTTPLanguage(
		[]byte("HTTP/1.1 200 OK\r\nContent-Language: zh-CN\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"),
		[]byte(`<html lang="zh-CN"><head><meta name="language" content="zh-CN"></head><body>欢迎使用平台，这里展示资产、任务、漏洞和生命周期。</body></html>`),
	)

	if attrs.ContentLanguage != "zh-cn" {
		t.Fatalf("content language = %q, want zh-cn", attrs.ContentLanguage)
	}
	if attrs.HTMLLang != "zh-cn" {
		t.Fatalf("html lang = %q, want zh-cn", attrs.HTMLLang)
	}
	if attrs.MetaLanguage != "zh-cn" {
		t.Fatalf("meta language = %q, want zh-cn", attrs.MetaLanguage)
	}
	if attrs.DetectedLanguage != "zh" {
		t.Fatalf("detected language = %q, want zh", attrs.DetectedLanguage)
	}
	if attrs.Language != "zh" || attrs.LanguageSource != "body" {
		t.Fatalf("language/source = %q/%q, want zh/body", attrs.Language, attrs.LanguageSource)
	}
}

func TestExtractHTTPLanguageBodyOverridesDeclared(t *testing.T) {
	attrs := ExtractHTTPLanguage(
		[]byte("HTTP/1.1 200 OK\r\nContent-Language: en-US\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"),
		[]byte(`<html lang="en"><body>これは日本語のページです。サービス状態を表示します。</body></html>`),
	)

	if attrs.ContentLanguage != "en-us" {
		t.Fatalf("content language = %q, want en-us", attrs.ContentLanguage)
	}
	if attrs.HTMLLang != "en" {
		t.Fatalf("html lang = %q, want en", attrs.HTMLLang)
	}
	if attrs.DetectedLanguage != "ja" {
		t.Fatalf("detected language = %q, want ja", attrs.DetectedLanguage)
	}
	if attrs.Language != "ja" || attrs.LanguageSource != "body" {
		t.Fatalf("language/source = %q/%q, want ja/body", attrs.Language, attrs.LanguageSource)
	}
}

func TestExtractHTTPLanguageFallsBackToHeader(t *testing.T) {
	attrs := ExtractHTTPLanguage(
		[]byte("HTTP/1.1 200 OK\r\nContent-Language: fr-FR\r\n\r\n"),
		nil,
	)

	if attrs.Language != "fr-fr" || attrs.LanguageSource != "header" {
		t.Fatalf("language/source = %q/%q, want fr-fr/header", attrs.Language, attrs.LanguageSource)
	}
}

func TestExtractHTTPLanguageDetectsEnglishBody(t *testing.T) {
	attrs := ExtractHTTPLanguage(
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"),
		[]byte(`<html><body>This is an English product page and the service is available for you from the web console with your account.</body></html>`),
	)

	if attrs.DetectedLanguage != "en" {
		t.Fatalf("detected language = %q, want en", attrs.DetectedLanguage)
	}
	if attrs.Language != "en" || attrs.LanguageSource != "body" {
		t.Fatalf("language/source = %q/%q, want en/body", attrs.Language, attrs.LanguageSource)
	}
}

func TestExtractHTTPLanguageDecodesGBKBody(t *testing.T) {
	html := `<html><head><meta charset="gbk"></head><body>欢迎使用平台，这里展示资产、任务、漏洞和生命周期。</body></html>`
	gbk, _, err := transform.String(simplifiedchinese.GBK.NewEncoder(), html)
	if err != nil {
		t.Fatalf("encode gbk fixture: %v", err)
	}

	attrs := ExtractHTTPLanguage(
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=gbk\r\n\r\n"),
		[]byte(gbk),
	)

	if attrs.DetectedLanguage != "zh" {
		t.Fatalf("detected language = %q, want zh", attrs.DetectedLanguage)
	}
	if attrs.Language != "zh" || attrs.LanguageSource != "body" {
		t.Fatalf("language/source = %q/%q, want zh/body", attrs.Language, attrs.LanguageSource)
	}
}

func TestHTTPLanguageExtractReturnsExtracted(t *testing.T) {
	attrs := HTTPLanguageAttrs{
		Language:       "zh",
		LanguageSource: "body",
	}

	extracted := HTTPLanguageExtract(attrs)
	if len(extracted) != 1 {
		t.Fatalf("extracted length = %d, want 1", len(extracted))
	}
	if extracted[0].Name != "language" {
		t.Fatalf("extracted name = %q, want language", extracted[0].Name)
	}
	if extracted[0].Severity != "info" {
		t.Fatalf("extracted severity = %q, want info", extracted[0].Severity)
	}
	if len(extracted[0].ExtractResult) != 1 || extracted[0].ExtractResult[0] != "zh" {
		t.Fatalf("extract_result = %v, want [zh]", extracted[0].ExtractResult)
	}
}

func TestHTTPLanguageExtractReturnsNilForEmpty(t *testing.T) {
	extracted := HTTPLanguageExtract(HTTPLanguageAttrs{})
	if extracted != nil {
		t.Fatalf("extracted = %v, want nil for empty language", extracted)
	}
}
