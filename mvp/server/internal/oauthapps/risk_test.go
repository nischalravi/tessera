package oauthapps

import (
	"testing"
	"time"
)

func TestAssess(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	old := now.Add(-100 * 24 * time.Hour)
	recent := now.Add(-5 * 24 * time.Hour)
	cases := []struct {
		name     string
		in       Subject
		score    int
		severity string
	}{
		{"low verified", Subject{Provider: Google, Scopes: []string{"openid"}, Verified: true, LastUsed: &recent}, 5, SevLow},
		{"unknown scope is low", Subject{Provider: GitHub, Scopes: []string{"new:thing"}, Verified: true}, 5, SevLow},
		{"high verified", Subject{Provider: Google, Scopes: []string{"https://mail.google.com/"}, Verified: true}, 60, SevCritical},
		{"unverified adds 15", Subject{Provider: Entra, Scopes: []string{"Mail.Read"}}, 55, SevHigh},
		{"admin consent adds 10", Subject{Provider: Entra, Scopes: []string{"Mail.Read"}, Verified: true, AdminGrant: true}, 50, SevHigh},
		{"unused adds 10", Subject{Provider: Salesforce, Scopes: []string{"api"}, Verified: true, LastUsed: &old}, 50, SevHigh},
		{"ten users add 5", Subject{Provider: GitHub, Scopes: []string{"repo"}, Verified: true, Users: 10}, 45, SevHigh},
		{"hundred users add 10", Subject{Provider: GitHub, Scopes: []string{"repo"}, Verified: true, Users: 100}, 50, SevHigh},
		{"capped at 100", Subject{Provider: Entra, Scopes: []string{"Directory.ReadWrite.All"}, AdminGrant: true, LastUsed: &old, Users: 500}, 100, SevCritical},
		{"worst scope wins", Subject{Provider: GitHub, Scopes: []string{"read:user", "admin:org"}, Verified: true}, 60, SevCritical},
		{"no scopes", Subject{Provider: Google, Verified: true}, 5, SevLow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := Assess(c.in, now)
			if a.Score != c.score || a.Severity != c.severity {
				t.Fatalf("got %d %s, want %d %s", a.Score, a.Severity, c.score, c.severity)
			}
		})
	}
}

func TestAssessReasonsSorted(t *testing.T) {
	a := Assess(Subject{Provider: Entra, Scopes: []string{"Mail.Read", "Mail.Read"}, AdminGrant: true}, time.Now())
	if len(a.Reasons) != 3 {
		t.Fatalf("reasons: %v", a.Reasons)
	}
	for i := 1; i < len(a.Reasons); i++ {
		if a.Reasons[i-1] > a.Reasons[i] {
			t.Fatalf("not sorted: %v", a.Reasons)
		}
	}
}

func TestCatalogCoversEveryProvider(t *testing.T) {
	if CatalogVersion == "" {
		t.Fatal("catalog version empty")
	}
	for _, p := range Providers {
		found := map[string]bool{}
		for k, r := range catalog {
			if len(k) > len(p) && k[:len(p)+1] == p+"|" {
				found[r.Severity] = true
				if r.Reason == "" {
					t.Fatalf("%s has no reason", k)
				}
			}
		}
		if !found[SevLow] || !found[SevHigh] && !found[SevCritical] {
			t.Fatalf("provider %s lacks a low or a high entry: %v", p, found)
		}
	}
}
