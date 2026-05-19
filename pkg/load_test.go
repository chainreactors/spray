package pkg

import (
	"testing"

	"github.com/chainreactors/words/mask"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

func TestLoadKeyword_MalformedYAML(t *testing.T) {
	old := mask.SpecialWords
	mask.SpecialWords = make(map[string][]string)
	t.Cleanup(func() { mask.SpecialWords = old })

	badYAML := []byte(`
key_as_string: "not_a_list"
key_as_int: 42
valid_key:
  - "a"
  - "b"
`)
	var keywords map[string]interface{}
	if err := yaml.Unmarshal(badYAML, &keywords); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on malformed keyword: %v", r)
		}
	}()

	for k, v := range keywords {
		items, ok := v.([]interface{})
		if !ok {
			continue
		}
		result := make([]string, len(items))
		for i, vv := range items {
			result[i] = vv.(string)
		}
		mask.SpecialWords[k] = result
	}

	if _, ok := mask.SpecialWords["valid_key"]; !ok {
		t.Fatal("valid_key should have been loaded")
	}
	if _, ok := mask.SpecialWords["key_as_string"]; ok {
		t.Fatal("key_as_string should have been skipped")
	}
	if _, ok := mask.SpecialWords["key_as_int"]; ok {
		t.Fatal("key_as_int should have been skipped")
	}
}

func TestLoadKeyword_ValidYAML(t *testing.T) {
	old := mask.SpecialWords
	mask.SpecialWords = make(map[string][]string)
	t.Cleanup(func() { mask.SpecialWords = old })

	validYAML := []byte(`
admin:
  - "admin"
  - "root"
  - "administrator"
pass:
  - "password"
  - "123456"
`)
	var keywords map[string]interface{}
	if err := yaml.Unmarshal(validYAML, &keywords); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for k, v := range keywords {
		items, ok := v.([]interface{})
		if !ok {
			continue
		}
		result := make([]string, len(items))
		for i, vv := range items {
			result[i] = vv.(string)
		}
		mask.SpecialWords[k] = result
	}

	if got := len(mask.SpecialWords["admin"]); got != 3 {
		t.Fatalf("admin has %d words, want 3", got)
	}
	if got := len(mask.SpecialWords["pass"]); got != 2 {
		t.Fatalf("pass has %d words, want 2", got)
	}
}
