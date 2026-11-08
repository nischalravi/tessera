package readiness

import (
	"errors"
	"strings"
	"testing"
)

// A zero-width character between the scheme and "://", or a fullwidth colon or solidus, must not hide a credentialed
// URL in a free-text field (issue #932); plain values stay accepted.
func TestTextFieldsFoldInvisibleAndFullwidthSeparators(t *testing.T) {
	cases := []struct {
		name, v string
		risky   bool
	}{
		{"zero-width before ://", "https\u200b://u:pwSECRET@h.example", true},
		{"zero-width joiner", "https\u200d://u:pwSECRET@h.example/x", true},
		{"bidi mark", "Ops <https\u200e://u:pwSECRET@h.example>", true},
		{"fullwidth colon", "https\uff1a//u:pwSECRET@h.example", true},
		{"fullwidth solidus", "https:\uff0f\uff0fu:pwSECRET@h.example", true},
		{"embedded in text", "owner: see https\u200b://u:pwSECRET@h.example.", true},
		{"email", "Ops <ops@larkspur.example>", false},
		{"ldap filter", "(&(objectClass=user)(mail=*@x.example))", false},
		{"cron", "0 3 * * *", false},
		{"zero-width in plain text", "Thandiwe\u200b Mokoena", false},
		{"plain https", "https://h.example/docs", false},
	}
	for name := range textFieldPtrs(&ConnConfig{}) {
		for _, c := range cases {
			cfg := ConnConfig{}
			*textFieldPtrs(&cfg)[name] = c.v
			err := urlCredentialError(ConnConfig{}, cfg)
			var e *Error
			switch {
			case c.risky && (!errors.As(err, &e) || e.Code != CodeURLCredentialsRefused):
				t.Errorf("%s/%s: got %v, want url_credentials_refused", name, c.name, err)
			case c.risky && strings.Contains(e.Error(), "SECRET"):
				t.Errorf("%s/%s: the error echoes the value", name, c.name)
			case !c.risky && err != nil:
				t.Errorf("%s/%s: refused a plain value: %v", name, c.name, err)
			}
			if got := MaskText(c.v); c.risky && strings.Contains(got, "SECRET") {
				t.Errorf("%s/%s: MaskText kept the secret: %q", name, c.name, got)
			} else if !c.risky && got != c.v {
				t.Errorf("%s/%s: MaskText changed a plain value: %q", name, c.name, got)
			}
		}
	}
}

// More separator lookalikes NFKC reads as ASCII (fullwidth "@", fullwidth letters, small forms), in typed text, URL
// fields and URL settings; the mask never shows the secret, and plain fullwidth text is left alone (issue #932).
func TestURLChecksFoldCompatibilityForms(t *testing.T) {
	risky := []string{
		"https://ghp_SECRET\uff20h.example",
		"https://u:SECRET\uff20h.example",
		"\uff48\uff54\uff54\uff50\uff53\uff1a\uff0f\uff0fu:SECRET@h.example",
		"https\ufe55//u:SECRET\ufe6bh.example",
		"https\u200b://u:SECRET@h.example",
	}
	for _, v := range risky {
		if !textRisk(v) {
			t.Errorf("textRisk(%q) = false", v)
		}
		for _, strict := range []bool{false, true} {
			if !urlRisk(v, strict) {
				t.Errorf("urlRisk(%q, %v) = false", v, strict)
			}
		}
		for name, got := range map[string]string{"MaskText": MaskText(v), "MaskURL": MaskURL(v)} {
			if strings.Contains(got, "SECRET") {
				t.Errorf("%s(%q) = %q keeps the secret", name, v, got)
			}
		}
		cfg := ConnConfig{BaseURL: v, Settings: map[string]string{"endpoint": v}}
		err := urlCredentialError(ConnConfig{}, cfg)
		var e *Error
		if !errors.As(err, &e) || len(e.Fields) != 2 || strings.Contains(e.Error(), "SECRET") {
			t.Errorf("urlCredentialError(%q) = %v", v, err)
		}
		masked, _ := MaskedConfig(cfg)
		if strings.Contains(masked.BaseURL+masked.Settings["endpoint"], "SECRET") {
			t.Errorf("MaskedConfig(%q) keeps the secret: %+v", v, masked)
		}
	}
	// a second credentialed URL after the first: MaskURL masks only the first userinfo, so the value is masked whole
	if got := MaskText("https://a:b@h.example/x https://u:SECRET@x.example"); got != URLMask {
		t.Errorf("MaskText of two credentialed URLs = %q", got)
	}
	for _, v := range []string{
		"ops\uff20larkspur.example",
		"\uff08\u682a\uff09\u30e9\u30fc\u30af\u30b9\u30d1\u30fc\uff1a\u55b6\u696d\u90e8",
		"https://h.example/\u30c9\u30ad\u30e5\u30e1\u30f3\u30c8",
		"https://h\u3002example/docs",
	} {
		if textRisk(v) || urlRisk(v, true) || MaskText(v) != v || MaskURL(v) != v {
			t.Errorf("plain value %q refused or masked", v)
		}
	}
}
