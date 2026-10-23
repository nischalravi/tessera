package ghtokens

import (
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Thresholds of the risk flags, in days. They match the NHI inventory's stale
// secret rule (internal/nhi.StaleDays).
const (
	StaleDays  = 90
	UnusedDays = 90
)

// Flags a credential can carry. orphaned, owner_left and stale_secret are the
// names the NHI inventory uses for the same findings.
const (
	FlagOrphaned      = "orphaned"        // the owner login matches no identity
	FlagOwnerLeft     = "owner_left"      // the owner identity is not active
	FlagStale         = "stale_secret"    // not rotated or re-authorized for StaleDays or more
	FlagNoExpiry      = "no_expiry"       // a personal access token that never expires
	FlagExpired       = "expired"         // past its expiry: harmless unless GitHub still honors it
	FlagUnused        = "unused"          // last used UnusedDays or more ago (unknown is not unused)
	FlagHighRiskScope = "high_risk_scope" // a high or critical scope or permission
	FlagOrgWideSecret = "org_wide_secret" // an Actions secret every repository can read
	FlagCLIToken      = "cli_token"       // a token of the GitHub CLI, held on a developer machine
	FlagClassic       = "classic_pat"     // a classic personal access token: broad scopes, no repository limit
)

var weights = map[string]int{
	FlagOrphaned: 25, FlagOwnerLeft: 30, FlagStale: 15, FlagNoExpiry: 20, FlagUnused: 10,
	FlagHighRiskScope: 20, FlagOrgWideSecret: 10, FlagCLIToken: 5, FlagClassic: 10, FlagExpired: 0,
}

// Owner is the state of the identity a credential's owner login maps to.
type Owner int

// Owner states.
const (
	OwnerNone     Owner = iota // no identity (or an Actions secret, which the organization owns)
	OwnerActive                // the identity is active
	OwnerInactive              // the identity has left or is disabled
)

// Assessment is the risk of one credential.
type Assessment struct {
	Score   int // 0-100
	Flags   []string
	AgeDays int // since it was last rotated, or created
}

// Assess scores a credential from what GitHub reported and the owner's state.
// Unknown is never risky: a missing date adds no flag.
func Assess(t *store.GitHubToken, owner Owner, now time.Time) Assessment {
	flags := map[string]bool{}
	ref := t.CreatedAt
	if t.RotatedAt != nil {
		ref = t.RotatedAt
	}
	age := 0
	if ref != nil {
		age = timeutil.Days(now, *ref)
		if age >= StaleDays {
			flags[FlagStale] = true
		}
	}
	isPAT := t.Kind == store.GHClassicPAT || t.Kind == store.GHFineGrainedPAT
	expired := t.ExpiresAt != nil && !t.ExpiresAt.After(now)
	switch {
	case expired:
		flags[FlagExpired] = true
	case isPAT && t.ExpiresAt == nil:
		flags[FlagNoExpiry] = true
	}
	if t.LastUsedAt != nil && now.Sub(*t.LastUsedAt) >= UnusedDays*24*time.Hour {
		flags[FlagUnused] = true
	}
	for _, s := range t.Scopes {
		if oauthapps.IsHighRisk(oauthapps.LookupScope(oauthapps.GitHub, s).Severity) {
			flags[FlagHighRiskScope] = true
			break
		}
	}
	if t.Kind == store.GHActionsSecret {
		if t.Visibility == "all" {
			flags[FlagOrgWideSecret] = true
		}
	} else {
		switch owner {
		case OwnerNone:
			flags[FlagOrphaned] = true
		case OwnerInactive:
			flags[FlagOwnerLeft] = true
		}
	}
	if t.Kind == store.GHClassicPAT {
		flags[FlagClassic] = true
	}
	if t.Kind == store.GHOAuthAppToken && strings.Contains(strings.ToLower(t.Name), "github cli") {
		flags[FlagCLIToken] = true
	}
	out := make([]string, 0, len(flags))
	score := 0
	for f := range flags {
		out = append(out, f)
		score += weights[f]
	}
	sort.Strings(out)
	return Assessment{Score: min(score, 100), Flags: out, AgeDays: age}
}
