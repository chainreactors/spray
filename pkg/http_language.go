package pkg

import (
	"bytes"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/chainreactors/utils/parsers"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

const maxLanguageBodyBytes = 200_000

var (
	htmlTagRe     = regexp.MustCompile(`(?is)<html\b[^>]*>`)
	metaTagRe     = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	attrRe        = regexp.MustCompile(`(?is)([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))`)
	scriptStyleRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<noscript\b[^>]*>.*?</noscript>`)
	tagRe         = regexp.MustCompile(`(?is)<[^>]+>`)
	spaceRe       = regexp.MustCompile(`\s+`)
	wordRe        = regexp.MustCompile(`[a-zA-Z]{2,}`)
)

var languageAliases = map[string]string{
	"chinese":  "zh",
	"cn":       "zh-cn",
	"english":  "en",
	"french":   "fr",
	"german":   "de",
	"japanese": "ja",
	"korean":   "ko",
	"spanish":  "es",
}

var englishStopwords = map[string]struct{}{
	"and":  {},
	"are":  {},
	"for":  {},
	"from": {},
	"have": {},
	"not":  {},
	"that": {},
	"the":  {},
	"this": {},
	"with": {},
	"you":  {},
	"your": {},
}

type HTTPLanguageAttrs struct {
	ContentLanguage  string
	HTMLLang         string
	MetaLanguage     string
	DetectedLanguage string
	Language         string
	LanguageSource   string
}

func ExtractHTTPLanguage(rawHeaders, body []byte) HTTPLanguageAttrs {
	bodyText := decodeLanguageBody(rawHeaders, body)

	attrs := HTTPLanguageAttrs{
		ContentLanguage:  normalizeLanguageTag(headerValue(rawHeaders, "content-language")),
		HTMLLang:         htmlLanguage(bodyText),
		MetaLanguage:     metaLanguage(bodyText),
		DetectedLanguage: detectBodyLanguage(bodyText),
	}

	attrs.Language, attrs.LanguageSource = chooseLanguage(
		attrs.DetectedLanguage,
		attrs.HTMLLang,
		attrs.ContentLanguage,
		attrs.MetaLanguage,
	)

	return attrs
}

func HTTPLanguageExtract(attrs HTTPLanguageAttrs) parsers.Extracteds {
	if attrs.Language == "" {
		return nil
	}
	return parsers.Extracteds{
		&parsers.Extracted{
			Name:          "language",
			Severity:      "info",
			ExtractResult: []string{attrs.Language},
		},
	}
}

func decodeLanguageBody(rawHeaders, body []byte) string {
	if len(body) == 0 {
		return ""
	}

	sample := body
	if len(sample) > maxLanguageBodyBytes {
		sample = sample[:maxLanguageBodyBytes]
	}

	if utf8.Valid(sample) {
		return string(sample)
	}

	contentType := headerValue(rawHeaders, "content-type")
	encoding, _, _ := charset.DetermineEncoding(sample, contentType)
	reader := transform.NewReader(bytes.NewReader(sample), encoding.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(sample)
	}
	return string(decoded)
}

func headerValue(rawHeaders []byte, name string) string {
	target := strings.ToLower(name)
	for _, line := range strings.Split(string(rawHeaders), "\n") {
		line = strings.TrimRight(line, "\r")
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:i])) == target {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func normalizeLanguageTag(value string) string {
	text := strings.Trim(strings.TrimSpace(value), `"'`)
	if text == "" {
		return ""
	}
	if i := strings.IndexAny(text, ",;"); i >= 0 {
		text = text[:i]
	}
	text = strings.ToLower(strings.ReplaceAll(strings.Trim(strings.TrimSpace(text), `"'`), "_", "-"))
	if alias, ok := languageAliases[text]; ok {
		text = alias
	}
	if !validLanguageTag(text) {
		return ""
	}
	return text
}

func validLanguageTag(text string) bool {
	if text == "" {
		return false
	}
	parts := strings.Split(text, "-")
	if len(parts[0]) < 2 || len(parts[0]) > 3 || !allLowerASCII(parts[0]) {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) < 2 || len(part) > 8 || !allLowerAlphaNum(part) {
			return false
		}
	}
	return true
}

func allLowerASCII(s string) bool {
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func allLowerAlphaNum(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func htmlLanguage(body string) string {
	match := htmlTagRe.FindString(body)
	if match == "" {
		return ""
	}
	attrs := parseTagAttrs(match)
	if value := normalizeLanguageTag(attrs["lang"]); value != "" {
		return value
	}
	return normalizeLanguageTag(attrs["xml:lang"])
}

func metaLanguage(body string) string {
	for _, match := range metaTagRe.FindAllString(body, -1) {
		attrs := parseTagAttrs(match)
		content := attrs["content"]
		if content == "" {
			continue
		}

		if strings.EqualFold(attrs["http-equiv"], "content-language") {
			if language := normalizeLanguageTag(content); language != "" {
				return language
			}
		}

		switch strings.ToLower(attrs["name"]) {
		case "content-language", "dc.language", "dc.language.iso", "language":
			if language := normalizeLanguageTag(content); language != "" {
				return language
			}
		}

		switch strings.ToLower(attrs["property"]) {
		case "og:locale", "og:locale:alternate":
			if language := normalizeLanguageTag(content); language != "" {
				return language
			}
		}
	}
	return ""
}

func parseTagAttrs(tag string) map[string]string {
	attrs := make(map[string]string)
	for _, match := range attrRe.FindAllStringSubmatch(tag, -1) {
		value := ""
		for _, group := range match[2:] {
			if group != "" {
				value = group
				break
			}
		}
		attrs[strings.ToLower(match[1])] = html.UnescapeString(strings.TrimSpace(value))
	}
	return attrs
}

func detectBodyLanguage(body string) string {
	text := visibleText(body)
	if text == "" {
		return ""
	}

	counts := map[string]int{
		"zh":      countRuneRanges(text, [][2]rune{{0x4E00, 0x9FFF}, {0x3400, 0x4DBF}}),
		"ja_kana": countRuneRanges(text, [][2]rune{{0x3040, 0x30FF}, {0x31F0, 0x31FF}}),
		"ko":      countRuneRanges(text, [][2]rune{{0xAC00, 0xD7AF}, {0x1100, 0x11FF}}),
		"ar":      countRuneRanges(text, [][2]rune{{0x0600, 0x06FF}, {0x0750, 0x077F}}),
		"he":      countRuneRanges(text, [][2]rune{{0x0590, 0x05FF}}),
		"el":      countRuneRanges(text, [][2]rune{{0x0370, 0x03FF}}),
		"th":      countRuneRanges(text, [][2]rune{{0x0E00, 0x0E7F}}),
	}

	if counts["ja_kana"] >= 3 {
		return "ja"
	}
	for _, language := range []string{"ko", "zh", "ar", "he", "el", "th"} {
		if counts[language] >= 4 {
			return language
		}
	}

	return detectEnglish(text)
}

func visibleText(body string) string {
	withoutScripts := scriptStyleRe.ReplaceAllString(body, " ")
	withoutTags := tagRe.ReplaceAllString(withoutScripts, " ")
	return strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(withoutTags), " "))
}

func countRuneRanges(text string, ranges [][2]rune) int {
	count := 0
	for _, r := range text {
		for _, item := range ranges {
			if r >= item[0] && r <= item[1] {
				count++
				break
			}
		}
	}
	return count
}

func detectEnglish(text string) string {
	words := wordRe.FindAllString(text, -1)
	if len(words) < 12 {
		return ""
	}

	hits := 0
	for _, word := range words {
		if _, ok := englishStopwords[strings.ToLower(word)]; ok {
			hits++
		}
	}

	ratio := float64(hits) / float64(len(words))
	if hits < 5 || ratio < 0.08 {
		return ""
	}
	return "en"
}

func chooseLanguage(detected, htmlLang, contentLanguage, metaLanguage string) (string, string) {
	if detected != "" {
		return detected, "body"
	}
	if htmlLang != "" {
		return htmlLang, "html"
	}
	if contentLanguage != "" {
		return contentLanguage, "header"
	}
	if metaLanguage != "" {
		return metaLanguage, "meta"
	}
	return "", ""
}
