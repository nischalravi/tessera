package readiness

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// A preset adds its vendor's URL shape to the generic https check; a
// connection with no preset keeps only the generic check.
func TestConfig_SCIMPresetBaseURL(t *testing.T) {
	scimT, ok := template.MustDefault().Get("scim_app")
	if !ok {
		t.Fatal("no scim_app template")
	}
	tests := []struct {
		name      string
		preset    string
		url       string
		wantField string // "" means valid
	}{
		{"no preset, any https", "", "https://example.com/scim/v2", ""},
		{"slack ok", "slack", "https://api.slack.com/scim/v2", ""},
		{"slack wrong host", "slack", "https://example.com/scim/v2", "base_url"},
		{"atlassian ok", "atlassian", "https://api.atlassian.com/scim/directory/abc-123", ""},
		{"auth0 wrong path", "auth0", "https://acme.auth0.com/scim/v2", "base_url"},
		{"unverified vendor, https only", "zoom", "https://example.com/anything", ""},
		{"unknown preset", "nope", "https://example.com/scim/v2", "preset"},
		{"preset, http url", "slack", "http://api.slack.com/scim/v2", "base_url"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := Validate(ConnConfig{BaseURL: tc.url, Preset: tc.preset, CorrelationKey: "userName"}, scimT)
			got := ""
			if len(errs) > 0 {
				got = errs[0].Field
			}
			if got != tc.wantField {
				t.Fatalf("errors = %v, want field %q", errs, tc.wantField)
			}
		})
	}
}

func TestConfig_PresetOnlyForSCIM(t *testing.T) {
	errs := Validate(ConnConfig{Host: "ldap.lab.example", Port: 636, BaseDNs: []string{"dc=x"}, CorrelationKey: "entryUUID", Preset: "slack"}, ldapTmpl(t))
	if len(errs) != 1 || errs[0].Field != "preset" {
		t.Fatalf("errors = %v", errs)
	}
}
