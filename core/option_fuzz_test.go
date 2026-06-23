package core

import (
	"testing"
)

func TestContainsMask(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"{$l#3}", true},
		{"{?d#4}", true},
		{"http://example.com/{$l#3}", true},
		{"http://example.com/", false},
		{"no mask here", false},
		{"{normal}", false},
		{"", false},
		{"{", false},
	}
	for _, tt := range tests {
		if got := containsMask(tt.input); got != tt.want {
			t.Errorf("containsMask(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestExtractMaskFromString(t *testing.T) {
	tests := []struct {
		input        string
		wantReplaced string
		wantMask     string
	}{
		{
			input:        "Token: {$d#6}",
			wantReplaced: "Token: {{FUZZ}}",
			wantMask:     "{$d#6}",
		},
		{
			input:        "/api/{?l#4}/test",
			wantReplaced: "/api/{{FUZZ}}/test",
			wantMask:     "{?l#4}",
		},
		{
			input:        "{$l#3}",
			wantReplaced: "{{FUZZ}}",
			wantMask:     "{$l#3}",
		},
		{
			input:        "no mask here",
			wantReplaced: "no mask here",
			wantMask:     "",
		},
		{
			input:        "{$hex#16}.example.com",
			wantReplaced: "{{FUZZ}}.example.com",
			wantMask:     "{$hex#16}",
		},
		{
			input:        "sid={?d#8}",
			wantReplaced: "sid={{FUZZ}}",
			wantMask:     "{?d#8}",
		},
	}
	for _, tt := range tests {
		replaced, mask := extractMaskFromString(tt.input)
		if replaced != tt.wantReplaced {
			t.Errorf("extractMaskFromString(%q) replaced = %q, want %q", tt.input, replaced, tt.wantReplaced)
		}
		if mask != tt.wantMask {
			t.Errorf("extractMaskFromString(%q) mask = %q, want %q", tt.input, mask, tt.wantMask)
		}
	}
}

func TestExtractMask_URL(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com/api/{$l#3}/test"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "{$l#3}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$l#3}")
	}
	if opt.URL[0] != "http://example.com" {
		t.Errorf("URL = %q, want %q", opt.URL[0], "http://example.com")
	}
	if opt.Path != "/api/{{FUZZ}}/test" {
		t.Errorf("Path = %q, want %q", opt.Path, "/api/{{FUZZ}}/test")
	}
}

func TestExtractMask_Header(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Headers = []string{"Authorization: Bearer {$d#6}"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "{$d#6}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$d#6}")
	}
	if opt.Headers[0] != "Authorization: Bearer {{FUZZ}}" {
		t.Errorf("Header = %q, want %q", opt.Headers[0], "Authorization: Bearer {{FUZZ}}")
	}
}

func TestExtractMask_Host(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Host = "{$l#3}.internal.com"
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "{$l#3}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$l#3}")
	}
	if opt.Host != "{{FUZZ}}.internal.com" {
		t.Errorf("Host = %q, want %q", opt.Host, "{{FUZZ}}.internal.com")
	}
}

func TestExtractMask_Cookie(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Cookie = []string{"sid={$d#8}"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "{$d#8}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$d#8}")
	}
	if opt.Cookie[0] != "sid={{FUZZ}}" {
		t.Errorf("Cookie = %q, want %q", opt.Cookie[0], "sid={{FUZZ}}")
	}
}

func TestExtractMask_Path(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Path = "/v1/{$l#3}/info"
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "{$l#3}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$l#3}")
	}
	if opt.Path != "/v1/{{FUZZ}}/info" {
		t.Errorf("Path = %q, want %q", opt.Path, "/v1/{{FUZZ}}/info")
	}
}

func TestExtractMask_ConflictError(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Word = "{$d#4}"
	opt.Headers = []string{"Token: {$l#3}"}
	err := opt.ExtractMask()
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
}

func TestExtractMask_SameMaskMultipleFields(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com/{$l#3}"}
	opt.Headers = []string{"X-Path: {$l#3}"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatalf("same mask in multiple fields should not error: %v", err)
	}
	if opt.Word != "{$l#3}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$l#3}")
	}
}

func TestExtractMask_ExplicitWordWithFuzzPlaceholder(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com"}
	opt.Word = "{$d#6}"
	opt.Headers = []string{"Token: {{FUZZ}}"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	// {{FUZZ}} is not a mask pattern, so it should be left as-is
	if opt.Word != "{$d#6}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$d#6}")
	}
	if opt.Headers[0] != "Token: {{FUZZ}}" {
		t.Errorf("Header = %q, want %q", opt.Headers[0], "Token: {{FUZZ}}")
	}
}

func TestExtractMask_NoMask(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"http://example.com/path"}
	opt.Headers = []string{"Authorization: Bearer token123"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.Word != "" {
		t.Errorf("Word = %q, want empty", opt.Word)
	}
}

func TestExtractMask_URLWithPort(t *testing.T) {
	opt := &Option{}
	opt.URL = []string{"https://example.com:8443/api/{$l#3}"}
	err := opt.ExtractMask()
	if err != nil {
		t.Fatal(err)
	}
	if opt.URL[0] != "https://example.com:8443" {
		t.Errorf("URL = %q, want %q", opt.URL[0], "https://example.com:8443")
	}
	if opt.Word != "{$l#3}" {
		t.Errorf("Word = %q, want %q", opt.Word, "{$l#3}")
	}
	if opt.Path != "/api/{{FUZZ}}" {
		t.Errorf("Path = %q, want %q", opt.Path, "/api/{{FUZZ}}")
	}
}
