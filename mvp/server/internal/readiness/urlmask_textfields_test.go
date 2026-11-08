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

// A credentialed URL inside longer text (quoted, bracketed, after a label, without "//") is refused and masked whole:
// a typed text field is never a URL, so a URL anywhere in it counts.
func TestTextFieldsEmbeddedURLs(t *testing.T) {
	for _, v := range []string{
		"Ops team https://u:pwSECRET@h.example", "owner:https://u:pwSECRET@h.example", "see https:u:pwSECRET@h.example",
		"​https://u:pwSECRET@h.example", "​https:u:pwSECRET@h.example", `"https://u:pwSECRET@h.example"`,
		"<https://u:pwSECRET@h.example>", "Ops (ldap://u:pwSECRET@h.example)", "a\thttps:\\\\u:pwSECRET@h.example",
	} {
		for name := range textFieldPtrs(&ConnConfig{}) {
			cfg := ConnConfig{}
			*textFieldPtrs(&cfg)[name] = v
			err := urlCredentialError(ConnConfig{}, cfg)
			var e *Error
			if !errors.As(err, &e) || len(e.Fields) != 1 || e.Fields[0].Field != name || strings.Contains(e.Error()+e.Fields[0].Msg, "SECRET") {
				t.Errorf("%s=%q: got %v, want refused without the value", name, v, err)
			}
			m, masked := MaskedConfig(cfg)
			if got := *textFieldPtrs(&m)[name]; got != URLMask || !slices.Equal(masked, []string{name}) {
				t.Errorf("%s=%q: view %q masked=%v", name, v, got, masked)
			}
			next := m
			keepMaskedURLs(&cfg, &next)
			if *textFieldPtrs(&next)[name] != v {
				t.Errorf("%s=%q: the mask sent back did not keep the stored value", name, v)
			}
		}
		cm := map[string]any{"business_owner": v}
		if MaskConfigMap(cm); cm["business_owner"] != URLMask {
			t.Errorf("%q: change-request payload shows %q", v, cm["business_owner"])
		}
		if got := MaskOwner(&v); got == nil || *got != URLMask {
			t.Errorf("%q: owner shown as %v", v, got)
		}
	}
	// text with a URL but no credential, or an address, is left alone
	for _, v := range []string{"see https://wiki.example/x?id=1", "bob@example.com, https://wiki.example", "Ops <https://h.example/a>"} {
		cfg := ConnConfig{TechnicalOwner: v}
		if err := urlCredentialError(ConnConfig{}, cfg); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
		if m, masked := MaskedConfig(cfg); m.TechnicalOwner != v || len(masked) != 0 {
			t.Errorf("%q masked to %q", v, m.TechnicalOwner)
		}
	}
}

// The list fields (base DNs, OUs, write scope, check ids), attr_map and privileged_expected get the same refusal; the
// lists are masked entry by entry and a masked entry sent back keeps the stored one.
func TestTextListsRefuseAndMask(t *testing.T) {
	const bad = "https://u:pwSECRET@h.example"
	for name := range textListPtrs(&ConnConfig{}) {
		cfg := ConnConfig{}
		*textListPtrs(&cfg)[name] = []string{"ou=a", bad}
		var e *Error
		if err := urlCredentialError(ConnConfig{}, cfg); !errors.As(err, &e) || len(e.Fields) != 1 || e.Fields[0].Field != name || strings.Contains(e.Error(), "SECRET") {
			t.Errorf("%s: got %v", name, err)
		}
		if err := urlCredentialError(cfg, cfg); err != nil {
			t.Errorf("%s: an unchanged stored list was refused: %v", name, err)
		}
		m, masked := MaskedConfig(cfg)
		if got := *textListPtrs(&m)[name]; !slices.Equal(got, []string{"ou=a", "https://masked@h.example"}) || !slices.Equal(masked, []string{name}) {
			t.Errorf("%s: view %v masked=%v", name, got, masked)
		}
		if (*textListPtrs(&cfg)[name])[1] != bad {
			t.Errorf("%s: MaskedConfig modified the stored list", name)
		}
		next := m
		*textListPtrs(&next)[name] = slices.Clone(*textListPtrs(&m)[name])
		keepMaskedURLs(&cfg, &next)
		if got := *textListPtrs(&next)[name]; !slices.Equal(got, []string{"ou=a", bad}) {
			t.Errorf("%s: round trip gave %v", name, got)
		}
		cm := map[string]any{name: []any{"ou=a", bad}}
		if got := MaskConfigMap(cm); !slices.Equal(got, []string{name}) || cm[name].([]any)[1] != "https://masked@h.example" {
			t.Errorf("%s: change-request payload %v %v", name, got, cm)
		}
	}
	for _, cfg := range []ConnConfig{
		{AttrMap: []AttrMapping{{LDAP: bad, Target: "x", Scope: "account"}}},
		{PrivilegedExpected: map[string][]string{bad: nil}},
		{PrivilegedExpected: map[string][]string{"Domain Admins": {"alice", bad}}},
	} {
		if err := urlCredentialError(ConnConfig{}, cfg); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%+v: got %v", cfg, err)
		}
	}
}

// The mask round trip keeps a stored value in its own field and position only: it never moves a stored secret to
// another field or entry, and never restores a value the client did not echo.
func TestMaskRoundTripCannotMoveASecret(t *testing.T) {
	const bad = "https://u:pwSECRET@h.example"
	cur := ConnConfig{TechnicalOwner: bad, BaseDNs: []string{bad}}
	next := ConnConfig{BusinessOwner: MaskURL(bad), BaseDNs: []string{"ou=a", MaskURL(bad)}, WriteScope: []string{MaskURL(bad)}}
	keepMaskedURLs(&cur, &next)
	if next.BusinessOwner == bad || next.BaseDNs[1] == bad || next.WriteScope[0] == bad {
		t.Fatalf("a stored secret moved: %+v", next)
	}
	// and the mask is refused as a new value where it would be stored (it names "masked" as userinfo)
	if err := urlCredentialError(cur, next); err == nil {
		t.Errorf("the mask was accepted as a new value: %+v", next)
	}
}
