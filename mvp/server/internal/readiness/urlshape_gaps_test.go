package readiness

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Issue #921: URL values written without a "//" authority, with backslash separators, or with tabs and line breaks
// in the separators are read by WHATWG URL parsers as URLs with credentials. Refusal, masking and the credential
// drop must see them as the "://" form.
var shapeGaps = []string{
	"https:u:pwSECRET@a.okta.com",
	"HTTPS:u:pwSECRET@a.okta.com/x",
	`https:\\u:pwSECRET@a.okta.com`,
	`https:\/u:pwSECRET@a.okta.com`,
	`https:/u:pwSECRET@a.okta.com`,
	"https:///u:pwSECRET@a.okta.com",
	"https:\t//u:pwSECRET@a.okta.com",
	"https:/\n/u:pwSECRET@a.okta.com",
	" \x00https:u:pwSECRET@a.okta.com ",
	`\\u:pwSECRET@a.okta.com`,
	`/\u:pwSECRET@a.okta.com`,
	"wss:u:pwSECRET@a.okta.com",
	"ftp:u:pwSECRET@a.okta.com",
}

func TestURLCredentialError_SchemeShapes(t *testing.T) {
	for _, v := range shapeGaps {
		for name, cfg := range map[string]ConnConfig{
			"org_url":          {OrgURL: v},
			"base_url":         {BaseURL: v},
			"settings.api_url": {Settings: map[string]string{"api_url": v}},
			"settings.feed":    {Settings: map[string]string{"feed": v}},
		} {
			err := urlCredentialError(ConnConfig{}, cfg)
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeURLCredentialsRefused || len(e.Fields) != 1 || e.Fields[0].Field != name {
				t.Errorf("%s=%q: got %v, want %s refused", name, v, err, name)
				continue
			}
			if strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Fields[0].Msg, "SECRET") {
				t.Errorf("%s=%q: error echoes the value", name, v)
			}
		}
	}
}

func TestURLCredentialError_OpaqueStrict(t *testing.T) {
	// base_url and org_url refuse an "@" in any value with a scheme prefix, whatever reads it
	for _, v := range []string{"u:pwSECRET@a.okta.com", "ldap:u:pwSECRET@h.example.com"} {
		if err := urlCredentialError(ConnConfig{}, ConnConfig{OrgURL: v}); err == nil {
			t.Errorf("org_url=%q accepted", v)
		}
	}
	// a plain value with an "@" in a setting is not a URL
	for _, v := range []string{"a@b", "mailto:help@example.com"} {
		if err := urlCredentialError(ConnConfig{}, ConnConfig{Settings: map[string]string{"contact": v}}); err != nil {
			t.Errorf("settings.contact=%q refused: %v", v, err)
		}
	}
	// a clean URL in another shape is not refused
	for _, v := range []string{`https:\\a.okta.com`, "https:a.okta.com/x", "a.okta.com:443"} {
		if err := urlCredentialError(ConnConfig{}, ConnConfig{OrgURL: v}); err != nil {
			t.Errorf("org_url=%q refused: %v", v, err)
		}
	}
}

func TestMaskURL_SchemeShapes(t *testing.T) {
	for _, v := range append(slices.Clone(shapeGaps), "u:pwSECRET@a.okta.com", "ldap:u:pwSECRET@h.example.com") {
		got := MaskURL(v)
		if got == v || strings.Contains(got, "SECRET") || strings.Contains(got, "pw") {
			t.Errorf("MaskURL(%q) = %q, want masked", v, got)
		}
		// round trip: the mask sent back keeps the stored value (a setting is masked only when it is URL-valued)
		cur := ConnConfig{OrgURL: v, Settings: map[string]string{"api_url": v}}
		next := ConnConfig{OrgURL: got, Settings: map[string]string{"api_url": got}}
		keepMaskedURLs(&cur, &next)
		if next.OrgURL != v || next.Settings["api_url"] != v {
			t.Errorf("round trip of %q lost the stored value", v)
		}
		cfg, masked := MaskedConfig(ConnConfig{OrgURL: v, Settings: map[string]string{"feed": v}})
		if !slices.Contains(masked, "org_url") || strings.Contains(cfg.OrgURL, "SECRET") {
			t.Errorf("MaskedConfig(org_url=%q) = %q, %v", v, cfg.OrgURL, masked)
		}
		if strings.HasPrefix(v, "https:") && (!slices.Contains(masked, "settings.feed") || strings.Contains(cfg.Settings["feed"], "SECRET")) {
			t.Errorf("MaskedConfig(settings.feed=%q) = %q, %v", v, cfg.Settings["feed"], masked)
		}
		m := map[string]any{"base_url": v}
		if MaskConfigMap(m); strings.Contains(m["base_url"].(string), "SECRET") {
			t.Errorf("MaskConfigMap(base_url=%q) leaks", v)
		}
	}
	for _, v := range []string{`https:\\a.okta.com`, "a.okta.com:443", "https:\ta.okta.com"} {
		if got := MaskURL(v); got != v {
			t.Errorf("MaskURL(%q) = %q, want unchanged", v, got)
		}
	}
}

// The credential drop and the approver's endpoint list use the same URL-setting classifier as refusal and masking.
func TestEndpointSetting_SharedClassifier(t *testing.T) {
	for _, tc := range []struct{ k, a, b string }{
		{"API_URL", "https://a.example.com", "https://b.example.com"},
		{"Token_Endpoint", "https://a.example.com", "https://b.example.com"},
		{"redirect_uri", "https://a.example.com", "https://b.example.com"},
		{"feed", "https://a.example.com", "https://b.example.com"},
		{"feed", "https:a.example.com", "https:b.example.com"},
		{"feed", "https://a.example.com", "plain"},
	} {
		a := ConnConfig{Settings: map[string]string{tc.k: tc.a}}
		b := ConnConfig{Settings: map[string]string{tc.k: tc.b}}
		if got := endpointChanged(a, b); !slices.Contains(got, "settings."+tc.k) {
			t.Errorf("endpointChanged(%s: %q -> %q) = %v, want the setting listed", tc.k, tc.a, tc.b, got)
		}
		if !slices.Contains(a.Endpoints(), "settings."+tc.k+"="+tc.a) {
			t.Errorf("Endpoints() of %s=%q = %v, want it listed", tc.k, tc.a, a.Endpoints())
		}
	}
	if got := endpointChanged(ConnConfig{Settings: map[string]string{"label": "x"}}, ConnConfig{Settings: map[string]string{"label": "y"}}); len(got) != 0 {
		t.Errorf("a plain setting moved the endpoint: %v", got)
	}
}
