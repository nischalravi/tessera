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
