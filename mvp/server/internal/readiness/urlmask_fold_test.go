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
