package requests

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
)

// An organization's request settings overrides only tighten the tenant's (issue #298).
func TestSettingsWithOrg_OnlyTightens(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	n := func(v int) *int { return &v }
	b := func(v bool) *bool { return &v }
	base := Settings{JustificationRequired: false, JustificationMin: 10, DefaultHours: f(8), MaxHours: f(24)}
	for _, tc := range []struct {
		name string
		p    orgs.Policies
		want Settings
	}{
		{"no override", orgs.Policies{}, base},
		{"requires a justification", orgs.Policies{JustificationRequired: b(true)}, Settings{JustificationRequired: true, JustificationMin: 10, DefaultHours: f(8), MaxHours: f(24)}},
		{"longer minimum", orgs.Policies{JustificationMinLength: n(40)}, Settings{JustificationMin: 40, DefaultHours: f(8), MaxHours: f(24)}},
		{"a shorter minimum changes nothing", orgs.Policies{JustificationMinLength: n(2)}, base},
		{"shorter maximum", orgs.Policies{MaxHours: f(12)}, Settings{JustificationMin: 10, DefaultHours: f(8), MaxHours: f(12)}},
		{"a longer maximum changes nothing", orgs.Policies{MaxHours: f(100)}, base},
		{"shorter default", orgs.Policies{DefaultHours: f(2)}, Settings{JustificationMin: 10, DefaultHours: f(2), MaxHours: f(24)}},
		{"default follows a shorter maximum", orgs.Policies{MaxHours: f(4)}, Settings{JustificationMin: 10, DefaultHours: f(4), MaxHours: f(4)}},
		{"a maximum where the tenant has none", orgs.Policies{MaxHours: f(6)}, Settings{JustificationMin: 10, DefaultHours: f(6), MaxHours: f(6)}},
	} {
		in := base
		if tc.name == "a maximum where the tenant has none" {
			in.MaxHours = nil
		}
		got := in.WithOrg(tc.p)
		if got.JustificationRequired != tc.want.JustificationRequired || got.JustificationMin != tc.want.JustificationMin ||
			!sameHours(got.DefaultHours, tc.want.DefaultHours) || !sameHours(got.MaxHours, tc.want.MaxHours) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// the base settings are never changed through a copy
	if *base.MaxHours != 24 || *base.DefaultHours != 8 {
		t.Errorf("base changed: %v %v", *base.MaxHours, *base.DefaultHours)
	}
}

func sameHours(a, b *float64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// The organization settings keep their own copies of these limits (orgs cannot import requests).
func TestOrgLimitsMatchRequests(t *testing.T) {
	if orgs.MaxStages != MaxStages || orgs.MaxHours != MaxHours || orgs.MaxJustification != MaxJustification {
		t.Errorf("orgs limits %d/%d/%d differ from requests %d/%d/%d", orgs.MaxStages, orgs.MaxHours, orgs.MaxJustification,
			MaxStages, MaxHours, MaxJustification)
	}
	if int(24*30) != orgs.MaxEscalateHours {
		t.Errorf("escalation hours cap = %d", orgs.MaxEscalateHours)
	}
}
