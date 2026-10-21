package oauthapps

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Policy flags (issue #107): what an app shows for a reviewer to act on.
const (
	// FlagHighRiskNonAdmin: a high or critical scope was granted by a user who
	// is not an administrator, on their own consent.
	FlagHighRiskNonAdmin = "high_risk_non_admin"
	// FlagUnused: the app was last used N or more days ago (see DefaultUnusedDays).
	FlagUnused = "unused"
	// FlagUnverified: the provider does not vouch for the publisher.
	FlagUnverified = "unverified"
)

// DefaultUnusedDays is N of the unused flag when a caller names none.
const DefaultUnusedDays = 90

// Flags returns the policy flags of an app from its live grants. An app whose
// provider reports no last use is never flagged unused: unknown is not unused.
func Flags(app *store.OAuthApp, grants []*store.OAuthGrant, now time.Time, unusedDays int) []string {
	out := []string{}
	for _, g := range grants {
		if !live(g) || g.GranterAdmin || g.ConsentType != ConsentUser {
			continue
		}
		if worst(app.Provider, g.Scopes) {
			out = append(out, FlagHighRiskNonAdmin)
			break
		}
	}
	used := app.LastUsed
	for _, g := range grants {
		if live(g) {
			used = later(used, g.LastUsed)
		}
	}
	if unusedDays > 0 && used != nil && now.Sub(*used) >= time.Duration(unusedDays)*24*time.Hour {
		out = append(out, FlagUnused)
	}
	if !app.Verified {
		out = append(out, FlagUnverified)
	}
	return out
}

func worst(provider string, scopes []string) bool {
	for _, s := range scopes {
		if IsHighRisk(LookupScope(provider, s).Severity) {
			return true
		}
	}
	return false
}

// ScopeView is one scope with its catalog risk, for the side panel.
type ScopeView struct {
	Scope    string `json:"scope"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// Scopes rates each scope, worst first.
func Scopes(provider string, scopes []string) []ScopeView {
	out := make([]ScopeView, 0, len(scopes))
	for _, s := range scopes {
		r := LookupScope(provider, s)
		out = append(out, ScopeView{Scope: s, Severity: r.Severity, Reason: r.Reason})
	}
	for i := 1; i < len(out); i++ { // insertion sort: scope lists are short, and it is stable
		for j := i; j > 0 && sevWeight[out[j].Severity] > sevWeight[out[j-1].Severity]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// MatchesVendor reports whether an app belongs to a vendor: the publisher or
// the app name equals it, ignoring case and surrounding space. Providers that
// name no publisher (Google, Salesforce) match on the app name.
func MatchesVendor(app *store.OAuthApp, vendor string) bool {
	v := NormalizeVendor(vendor)
	return v != "" && (NormalizeVendor(app.Publisher) == v || NormalizeVendor(app.Name) == v)
}

// NormalizeVendor lower-cases and trims a vendor name.
func NormalizeVendor(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
