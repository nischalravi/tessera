package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

// A credentialed URL hidden behind zero-width or fullwidth separators is left out of the export, never exported in
// clear; ordinary values with such characters are exported as written (issue #932).
func TestCleanStringFoldsInvisibleAndFullwidthSeparators(t *testing.T) {
	risky := []string{
		"https\u200b://u:SECRET@h.example",
		"https\u200d://u:SECRET@h.example/x",
		"see https\u200e://u:SECRET@h.example now",
		"https\uff1a//u:SECRET@h.example",
		"https:\uff0f\uff0fu:SECRET@h.example",
		"https://ghp_SECRET\uff20h.example",
		"https://u:SECRET\uff20h.example",
		"\uff48\uff54\uff54\uff50\uff53\uff1a\uff0f\uff0fu:SECRET@h.example",
		"https\ufe55//u:SECRET\ufe6bh.example",
		"https://h.example/x\uff1ftoken\uff1dSECRET",
	}
	for _, s := range risky {
		if out, v := cleanString(s); v != verdictExcluded || strings.Contains(out, "SECRET") {
			t.Errorf("cleanString(%q) = %q, %v; want excluded", s, out, v)
		}
		if overlayExportable(s) {
			t.Errorf("overlayExportable(%q) = true", s)
		}
		raw, _ := json.Marshal(map[string]any{"owner": s, "name": "ok"})
		out, _, excluded := cleanConfig(raw)
		if strings.Contains(string(out), "SECRET") || len(excluded) != 1 || excluded[0] != "owner" {
			t.Errorf("cleanConfig(%q) = %s, excluded %v", s, out, excluded)
		}
	}
	plain := []string{
		"Ops <ops@larkspur.example>",
		"ops\uff20larkspur.example",
		"(&(objectClass=user)(mail=*@x.example))",
		"0 3 * * *",
		"Thandiwe\u200b Mokoena",
		"\uff08\u682a\uff09\u30e9\u30fc\u30af\u30b9\u30d1\u30fc\uff1a\u55b6\u696d\u90e8",
		"https://h.example/docs",
		"https://h.example/\u30c9\u30ad\u30e5\u30e1\u30f3\u30c8",
	}
	for _, s := range plain {
		if out, v := cleanString(s); v != verdictKeep || out != s {
			t.Errorf("cleanString(%q) = %q, %v; want kept as written", s, out, v)
		}
	}
}
