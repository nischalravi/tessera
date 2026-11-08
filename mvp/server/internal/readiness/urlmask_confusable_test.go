package readiness

import (
	"strings"
	"testing"
)

// Look-alike separators in base_url / org_url (issue #936): refused, masked and not echoed.
func TestConfusableURLSeparators(t *testing.T) {
	colons := []string{"∶", "꞉", "։", "׃", "܃", "܄", "᛬", "፡", "˸"}
	var bad []string
	for _, c := range colons {
		bad = append(bad, "https"+c+"//u:p@h.example/x", "https"+c+"//h.example/x", "https://u"+c+"p@h.example")
	}
	for _, sl := range []string{"⁄", "∕", "⧸", "╱", "〳"} {
		bad = append(bad, "https:"+sl+sl+"u:p@h.example", "https://h.example"+sl+"x@y")
	}
	bad = append(bad, "https://u:p＠h.example", "https://u:p﹫h.example", "https://bücher.example/")
	for _, v := range bad {
		for _, f := range []string{"org_url", "base_url"} {
			cfg := ConnConfig{}
			if f == "org_url" {
				cfg.OrgURL = v
			} else {
				cfg.BaseURL = v
			}
			err := urlCredentialError(ConnConfig{}, cfg)
			e, ok := err.(*Error)
			if !ok || (e.Code != CodeURLNonASCIIAuthority && e.Code != CodeURLCredentialsRefused) || e.Status != 400 || len(e.Fields) != 1 || e.Fields[0].Field != f {
				t.Errorf("%s=%q: err = %v", f, v, err)
			} else if contains(e.Msg+e.Fields[0].Msg, v) {
				t.Errorf("error echoes %q", v)
			}
			// a stored value is not refused again unchanged
			if err := urlCredentialError(cfg, cfg); err != nil {
				t.Errorf("unchanged %s=%q refused: %v", f, v, err)
			}
		}
	}
	// stored credentialed values behind a look-alike separator are masked whole
	for _, c := range colons {
		if m := MaskURL("https" + c + "//u:p@h.example/x"); m != URLMask {
			t.Errorf("MaskURL with U+%04X = %q", []rune(c)[0], m)
		}
	}
	if !textRisk("see https∶//u:p@h.example now") {
		t.Error("textRisk misses a look-alike colon")
	}
	if m := maskText("Ops <https꞉//u:p@h.example>"); m != URLMask {
		t.Errorf("maskText = %q", m)
	}
}

func TestASCIIURLsStillAccepted(t *testing.T) {
	for _, v := range []string{"https://api.example.com/v2", "https://xn--bcher-kva.example", "https://api.example.com/café", "https://api.example.com:8443"} {
		for _, cfg := range []ConnConfig{{OrgURL: v}, {BaseURL: v}} {
			if err := urlCredentialError(ConnConfig{}, cfg); err != nil && !strings.Contains(v, "@") {
				t.Errorf("%q refused: %v", v, err)
			}
			if err := urlASCIIError(ConnConfig{}, cfg); err != nil {
				t.Errorf("%q refused as non-ASCII: %v", v, err)
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// URL-valued settings follow the same ASCII-authority rule; plain text settings and legitimate URLs do not trip it.
func TestConfusableURLSettings(t *testing.T) {
	for _, v := range []string{"https∶//h.example/token", "https://bücher.example/token", "https:̸//h.example",
		"https://h%E2%88%95x.example/token", "httpsː//h.example", "https:ノノh.example"} {
		cfg := ConnConfig{Settings: map[string]string{"token_url": v}}
		err := urlCredentialError(ConnConfig{}, cfg)
		e, ok := err.(*Error)
		if !ok || e.Code != CodeURLNonASCIIAuthority || len(e.Fields) != 1 || e.Fields[0].Field != "settings.token_url" {
			t.Errorf("token_url=%q: err = %v", v, err)
			continue
		}
		if contains(e.Msg+e.Fields[0].Msg, v) {
			t.Errorf("error echoes %q", v)
		}
		if err := urlCredentialError(cfg, cfg); err != nil {
			t.Errorf("unchanged token_url=%q refused: %v", v, err)
		}
	}
	// a combining mark between the colon and the slashes still hides no credential
	cfg := ConnConfig{Settings: map[string]string{"token_url": "https:̸//u:p@h.example"}}
	if err := urlCredentialError(ConnConfig{}, cfg); err == nil {
		t.Error("combining-mark credential URL accepted")
	}
	for _, s := range []map[string]string{
		{"token_url": "https://xn--bcher-kva.example/t"},
		{"token_url": "https://[2001:db8::1]:8443/t"},
		{"token_url": "https://h.example:8443/a@b/café"},
		{"display_name": "Bücher GmbH"},
		{"endpoint_note": "Büro"},
	} {
		if err := urlCredentialError(ConnConfig{}, ConnConfig{Settings: s}); err != nil {
			t.Errorf("%v refused: %v", s, err)
		}
	}
}
