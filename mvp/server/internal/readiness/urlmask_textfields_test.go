package readiness

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Issue #926: a URL with credentials typed into a free-text field of the config (owners, correlation key, tenant
// host, schedule...) is refused on save and masked in views, like the same value under settings.
func TestTextFieldsRefuseAndMaskURLCredentials(t *testing.T) {
	values := append([]string{"https://u:pwSECRET@h.example/x?token=abc", "https://h.example/?token=abc"}, shapeGaps...)
	for name, field := range textFieldPtrs(&ConnConfig{}) {
		_ = field
		for _, v := range values {
			cfg := ConnConfig{}
			*textFieldPtrs(&cfg)[name] = v
			risky := urlRisk(v, false)

			err := urlCredentialError(ConnConfig{}, cfg)
			var e *Error
			switch {
			case risky && (!errors.As(err, &e) || e.Code != CodeURLCredentialsRefused || len(e.Fields) != 1 || e.Fields[0].Field != name):
				t.Errorf("%s=%q: got %v, want %s refused", name, v, err, name)
			case risky && strings.Contains(e.Error(), "SECRET"):
				t.Errorf("%s=%q: the error echoes the value", name, v)
			case !risky && err != nil:
				t.Errorf("%s=%q: refused without credentials: %v", name, v, err)
			}

			// a value already stored (before the rule) is shown masked, and kept when the client sends the mask back
			m, masked := MaskedConfig(cfg)
			got := *textFieldPtrs(&m)[name]
			if risky && (strings.Contains(got, "SECRET") || strings.Contains(got, "pw") || !slices.Contains(masked, name)) {
				t.Errorf("%s=%q: view shows %q, masked=%v", name, v, got, masked)
			}
			if risky {
				next := m
				keepMaskedURLs(&cfg, &next)
				if *textFieldPtrs(&next)[name] != v {
					t.Errorf("%s=%q: the masked value sent back replaced the stored one", name, v)
				}
				// an unchanged stored value is not refused again (only a change is)
				if err := urlCredentialError(cfg, cfg); err != nil {
					t.Errorf("%s=%q: an unchanged stored value was refused: %v", name, v, err)
				}
			}
		}
	}
}

// Plain text in those fields is never touched, whatever it looks like.
func TestTextFieldsLeavePlainValuesAlone(t *testing.T) {
	for _, v := range []string{"", "id", "employeeNumber", "owner@example.com", "Platform team: a@b", "(mail=*@example.com)", "0 3 * * *", "https://h.example/path", "host:443", "Europe/Berlin"} {
		cfg := ConnConfig{CorrelationKey: v, TechnicalOwner: v, TenantHost: v, UserFilter: v, SyncSchedule: v}
		if err := urlCredentialError(ConnConfig{}, cfg); err != nil && !urlRisk(v, false) {
			t.Errorf("%q refused: %v", v, err)
		}
		if m, masked := MaskedConfig(cfg); m.CorrelationKey != v || len(masked) != 0 {
			t.Errorf("%q masked to %q (%v)", v, m.CorrelationKey, masked)
		}
	}
}

func TestMaskConfigMapMasksTextFields(t *testing.T) {
	m := map[string]any{"technical_owner": "https://u:pwSECRET@h.example", "correlation_key": "id", "base_url": "https://h.example"}
	masked := MaskConfigMap(m)
	if !slices.Equal(masked, []string{"technical_owner"}) || strings.Contains(m["technical_owner"].(string), "SECRET") || m["correlation_key"] != "id" {
		t.Errorf("masked=%v map=%v", masked, m)
	}
}
