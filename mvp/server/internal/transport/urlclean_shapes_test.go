package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

// Issue #921: URL values without a "//" authority, with backslash separators or with tabs and line breaks in the
// separators carry credentials for a WHATWG URL parser. The export cleans or leaves them out like the "://" form.
func TestCleanString_SchemeShapes(t *testing.T) {
	for _, c := range []struct {
		in, out string
		verdict cleanVerdict
	}{
		{"https:u:pwSECRET@a.okta.com", "https://a.okta.com", verdictCleaned},
		{"HTTPS:u:pwSECRET@a.okta.com/x?q=1", "https://a.okta.com/x", verdictCleaned},
		{`https:\\u:pwSECRET@a.okta.com`, "https://a.okta.com", verdictCleaned},
		{`https:\/u:pwSECRET@a.okta.com\v2`, "https://a.okta.com/v2", verdictCleaned},
		{"https:\t//u:pwSECRET@a.okta.com", "https://a.okta.com", verdictCleaned},
		{" https:/\n/u:pwSECRET@a.okta.com ", "https://a.okta.com", verdictCleaned},
		{`\\u:pwSECRET@a.okta.com`, "", verdictExcluded},
		{"u:pwSECRET@a.okta.com", "", verdictExcluded},
		{"ldap:u:pwSECRET@h.example", "", verdictExcluded},
		// no credential: kept as written
		{`https:\\a.okta.com`, `https:\\a.okta.com`, verdictKeep},
		{"ingrid@corp.example", "ingrid@corp.example", verdictKeep},
	} {
		got, v := cleanString(c.in)
		if v != c.verdict || got != c.out {
			t.Errorf("cleanString(%q) = %q, %d; want %q, %d", c.in, got, v, c.out, c.verdict)
		}
		if strings.Contains(got, "SECRET") {
			t.Errorf("cleanString(%q) leaks %q", c.in, got)
		}
	}
}

func TestCleanConfig_SchemeShapes(t *testing.T) {
	in := json.RawMessage(`{"org_url":"https:u:pwSECRET@a.okta.com","settings":{"feed":"https:\\\\u:pwSECRET@b.example"},"base_url":"\\\\u:pwSECRET@c.example"}`)
	out, cleaned, left := cleanConfig(in)
	if !cleaned || strings.Join(left, ",") != "base_url" || strings.Contains(string(out), "SECRET") {
		t.Fatalf("cleaned=%v left=%v out=%s", cleaned, left, out)
	}
	if !strings.Contains(string(out), `"https://a.okta.com"`) || !strings.Contains(string(out), `"https://b.example"`) {
		t.Errorf("URLs not cleaned in place: %s", out)
	}
}

func TestOverlayExportable_SchemeShapes(t *testing.T) {
	for _, body := range []string{"hook: https:u:pwSECRET@h.example/x", `hook: https:\\u:pwSECRET@h.example/x`, `{"hook":"https:u:pwSECRET@h.example"}`} {
		if overlayExportable(body) {
			t.Errorf("overlayExportable(%q) = true", body)
		}
	}
}
