package pkg

import (
	"strings"
	"testing"

	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

func mustLoadTemplates(t *testing.T) {
	t.Helper()
	data := LoadEmbeddedConfig("proton_rules")
	if len(data) == 0 {
		t.Fatal("proton_rules embedded data is empty")
	}

	var templates []interface{}
	if err := yaml.Unmarshal(data, &templates); err != nil {
		t.Fatalf("unmarshal proton_rules: %v", err)
	}
	docs := make([][]byte, 0, len(templates))
	for _, tmpl := range templates {
		doc, err := yaml.Marshal(tmpl)
		if err != nil {
			continue
		}
		docs = append(docs, doc)
	}

	if err := LoadProtonTemplates(docs); err != nil {
		t.Fatalf("LoadProtonTemplates: %v", err)
	}
}

func TestProtonTemplatesLoad(t *testing.T) {
	mustLoadTemplates(t)

	names := ProtonExtractorNames()
	if len(names) == 0 {
		t.Fatal("no proton templates loaded")
	}

	want := []string{
		"spray-ipv4-address",
		"spray-jwt-token",
		"spray-js-file",
		"spray-email-address",
		"spray-aws-access-key",
		"spray-password-leak",
	}
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, w := range want {
		if !nameSet[w] {
			t.Errorf("missing template: %s", w)
		}
	}
}

func TestProtonTagMapping(t *testing.T) {
	mustLoadTemplates(t)

	tests := []struct {
		tag       string
		wantMatch string
	}{
		{"ip", "spray-ipv4-address"},
		{"jwt", "spray-jwt-token"},
		{"js", "spray-js-file"},
		{"mail", "spray-email-address"},
		{"phone", "spray-phone-number"},
		{"idcard", "spray-id-card"},
		{"password", "spray-password-leak"},
		{"username", "spray-username-leak"},
		{"inter-ip", "spray-internal-ip"},
		{"oss", "spray-oss-key"},
		{"s3", "spray-s3-bucket"},
		{"aws-ak", "spray-aws-access-key"},
		{"rsa-key", "spray-rsa-private-key"},
		{"jdbc", "spray-jdbc-connection"},
		{"swagger", "spray-swagger-endpoint"},
		{"lfi", "spray-lfi-indicator"},
		{"upload", "spray-upload-form"},
		{"ssrf", "spray-url-as-value"},
		{"redirect", "spray-location-redirect"},
		{"mac", "spray-mac-address"},
		{"sensitive-field", "spray-sensitive-field"},
		{"linkfinder", "spray-linkfinder"},
		{"url-schemes", "spray-url-schemes"},
		{"auth-header", "spray-auth-header"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if !IsProtonExtractor(tt.tag) {
				t.Fatalf("IsProtonExtractor(%q) = false, want true", tt.tag)
			}
			protonMu.RLock()
			ids := protonTagMap[tt.tag]
			protonMu.RUnlock()
			found := false
			for _, id := range ids {
				if id == tt.wantMatch {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("tag %q -> got %v, want to include %s", tt.tag, ids, tt.wantMatch)
			}
		})
	}
}

func TestProtonCategoryTags(t *testing.T) {
	mustLoadTemplates(t)

	categories := []struct {
		tag      string
		minCount int
	}{
		{"cloud", 7},
		{"token", 9},
		{"credential", 9},
		{"pentest", 20},
		{"info", 10},
		{"crawl", 6},
	}

	for _, cat := range categories {
		t.Run(cat.tag, func(t *testing.T) {
			if !IsProtonExtractor(cat.tag) {
				t.Fatalf("IsProtonExtractor(%q) = false", cat.tag)
			}
			protonMu.RLock()
			ids := protonTagMap[cat.tag]
			protonMu.RUnlock()
			if len(ids) < cat.minCount {
				t.Errorf("tag %q has %d templates, want >= %d", cat.tag, len(ids), cat.minCount)
			}
		})
	}
}

func TestEnableExtractorsByTag(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ip"})

	protonMu.RLock()
	scanner := ProtonScanner
	protonMu.RUnlock()

	if scanner == nil || len(scanner.Groups) == 0 {
		t.Fatal("scanner is empty after EnableExtractors([ip])")
	}

	EnableExtractors(nil)
}

func TestEnableExtractorsByID(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"spray-jwt-token"})

	protonMu.RLock()
	scanner := ProtonScanner
	protonMu.RUnlock()

	if scanner == nil || len(scanner.Groups) == 0 {
		t.Fatal("scanner is empty after EnableExtractors([spray-jwt-token])")
	}

	EnableExtractors(nil)
}

func TestEnableExtractorsShortName(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ipv4-address"})

	protonMu.RLock()
	scanner := ProtonScanner
	protonMu.RUnlock()

	if scanner == nil || len(scanner.Groups) == 0 {
		t.Fatal("scanner is empty after EnableExtractors([ipv4-address]) — spray- prefix resolution failed")
	}

	EnableExtractors(nil)
}

func TestProtonExtractIP(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ip"})
	defer EnableExtractors(nil)

	body := []byte(`{"origin": "192.168.1.100", "host": "example.com"}`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("ProtonExtract returned no results for body containing IP")
	}

	found := false
	for _, r := range results {
		for _, v := range r.ExtractResult {
			if strings.Contains(v, "192.168.1.100") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected to extract 192.168.1.100, got %v", results)
	}
}

func TestProtonExtractJWT(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"jwt"})
	defer EnableExtractors(nil)

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	body := []byte(`<html><body>token: ` + jwt + `</body></html>`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("ProtonExtract returned no results for body containing JWT")
	}

	found := false
	for _, r := range results {
		for _, v := range r.ExtractResult {
			if strings.Contains(v, "eyJ") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected to extract JWT, got %v", results)
	}
}

func TestProtonExtractEmail(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"mail"})
	defer EnableExtractors(nil)

	body := []byte(`<html><body>Contact us at admin@example.com for support</body></html>`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("ProtonExtract returned no results for body containing email")
	}

	found := false
	for _, r := range results {
		for _, v := range r.ExtractResult {
			if strings.Contains(v, "admin@example.com") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected to extract admin@example.com, got %v", results)
	}
}

func TestProtonExtractPassword(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"password"})
	defer EnableExtractors(nil)

	body := []byte(`config.password = "s3cretP@ss"`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("ProtonExtract returned no results for body containing password leak")
	}
}

func TestProtonExtractNoMatch(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ip"})
	defer EnableExtractors(nil)

	body := []byte(`<html><body>Hello World, nothing interesting here</body></html>`)
	results := ProtonExtract(body)

	if len(results) != 0 {
		t.Errorf("expected no extracts for clean body, got %v", results)
	}
}

func TestProtonExtractMultipleTags(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ip", "mail"})
	defer EnableExtractors(nil)

	body := []byte(`server=192.168.0.1 contact=test@example.com`)
	results := ProtonExtract(body)

	nameSet := make(map[string]bool)
	for _, r := range results {
		nameSet[r.Name] = true
	}

	if !nameSet["ipv4-address"] {
		t.Error("missing ipv4-address extraction")
	}
	if !nameSet["email-address"] {
		t.Error("missing email-address extraction")
	}
}

func TestAddCustomExtractor(t *testing.T) {
	mustLoadTemplates(t)

	AddCustomExtractor("version", `version[:\s]+(\d+\.\d+\.\d+)`)
	defer EnableExtractors(nil)

	if !IsProtonExtractor("custom-version") {
		t.Error("custom extractor not found by ID")
	}

	body := []byte(`<html>version: 2.1.0</html>`)
	EnableExtractors([]string{"custom-version"})
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("custom extractor returned no results")
	}
}

func TestProtonExtractSeverity(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"ip"})
	defer EnableExtractors(nil)

	body := []byte(`{"origin": "192.168.1.100"}`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.Severity == "" {
			t.Errorf("Severity is empty for %s", r.Name)
		}
	}
}

func TestProtonExtractContext(t *testing.T) {
	mustLoadTemplates(t)

	oldCtx := ExtractContextSize
	ExtractContextSize = 20
	defer func() { ExtractContextSize = oldCtx }()

	EnableExtractors([]string{"ip"})
	defer EnableExtractors(nil)

	body := []byte(`server_addr = "192.168.1.100" # internal`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if len(r.Items) == 0 {
			t.Fatal("Items is empty when ExtractContextSize > 0")
		}
		item := r.Items[0]
		if item.Value == "" {
			t.Error("item.Value is empty")
		}
		if item.Ctx == "" {
			t.Error("item.Ctx is empty — context capture failed")
		}
		if !strings.Contains(item.Ctx, "192.168.1.100") {
			t.Errorf("context should contain the value, got: %s", item.Ctx)
		}
	}
}

func TestProtonExtractContextDisabled(t *testing.T) {
	mustLoadTemplates(t)

	oldCtx := ExtractContextSize
	ExtractContextSize = 0
	defer func() { ExtractContextSize = oldCtx }()

	EnableExtractors([]string{"ip"})
	defer EnableExtractors(nil)

	body := []byte(`{"origin": "192.168.1.100"}`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if len(r.Items) != 0 {
			t.Error("Items should be empty when ExtractContextSize=0")
		}
	}
}

func TestProtonExtractLFI(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"lfi"})
	defer EnableExtractors(nil)

	body := []byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("LFI indicator not detected")
	}
}

func TestProtonExtractAuthHeader(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"auth-header"})
	defer EnableExtractors(nil)

	body := []byte("HTTP/1.1 200 OK\r\nAuthorization: Bearer eyJhbGciOiJSUzI1NiJ9.test\r\n\r\n")
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("Authorization header not extracted")
	}
}

func TestProtonExtractSensitiveField(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"sensitive-field"})
	defer EnableExtractors(nil)

	body := []byte(`{"api_key": "sk-1234567890abcdef", "name": "test"}`)
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("sensitive field not extracted")
	}
}

func TestProtonExtractLocationRedirect(t *testing.T) {
	mustLoadTemplates(t)

	EnableExtractors([]string{"redirect"})
	defer EnableExtractors(nil)

	body := []byte("HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n")
	results := ProtonExtract(body)

	if len(results) == 0 {
		t.Fatal("Location redirect not extracted")
	}
}

func TestIsProtonExtractor(t *testing.T) {
	mustLoadTemplates(t)

	tests := []struct {
		name string
		want bool
	}{
		{"ip", true},
		{"cloud", true},
		{"spray-jwt-token", true},
		{"jwt-token", true},
		{"nonexistent-xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProtonExtractor(tt.name); got != tt.want {
				t.Errorf("IsProtonExtractor(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
