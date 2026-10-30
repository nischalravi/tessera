package jit

import (
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// JIT eligibility as code (issue #651, AC-5; design docs/design/access-as-code-repo.md section 3.3). Until a tenant
// applies eligibility rules from its policy repository (jit_settings.enabled), groups.requestable decides what may
// be requested and any jit.decide holder approves. Once enabled it is deny by default: a request must match an
// active rule (the person in one of its principal groups, the group among its entitlements, the duration within
// max_hours) and an approval must come from a person in one of the matching rules' approver groups (a rule with no
// approver groups lets any jit.decide holder approve). Only standing access counts as membership, so a JIT grant
// cannot be used to ask for or approve more. Every lookup error denies.

// Codes of the eligibility refusals.
const (
	CodeNotEligible = "not_eligible"
	CodeNotApprover = "not_approver"
)

// Enforced reports whether the tenant decides JIT requests by eligibility rules.
func Enforced(c *store.TenantTx) (bool, error) {
	s, err := c.JITSettings()
	if err != nil {
		return false, err
	}
	return s.Enabled, nil
}

// standingGroups is the set of group ids the identity holds through an unexpired, non-JIT edge of one of its active
// accounts.
func standingGroups(c *store.TenantTx, identityID int64, now time.Time) (map[int64]bool, error) {
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, a := range accts {
		if a.Status != "active" {
			continue
		}
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if e.Relation != "member_of" || e.Source == "jit" || (e.ExpiresAt != nil && !e.ExpiresAt.After(now)) {
				continue
			}
			if kind, id, err := graph.ParseKey(e.Dst); err == nil && kind == "group" {
				out[id] = true
			}
		}
	}
	return out, nil
}

func anyIn(set map[int64]bool, ids []int64) bool {
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

func hasGroup(ids []int64, id int64) bool {
	for _, g := range ids {
		if g == id {
			return true
		}
	}
	return false
}

// rulesFor returns the active rules that let identityID ask for groupID, whatever the duration, and the longest
// duration among them (0 when there is none).
func rulesFor(c *store.TenantTx, now time.Time, identityID, groupID int64) ([]*store.JITEligibility, int, error) {
	all, err := c.JITEligibilities()
	if err != nil {
		return nil, 0, err
	}
	var held map[int64]bool
	var out []*store.JITEligibility
	longest := 0
	for _, e := range all {
		if e.Status != store.JITEligibilityActive || !hasGroup(e.Entitlements, groupID) {
			continue
		}
		if held == nil {
			if held, err = standingGroups(c, identityID, now); err != nil {
				return nil, 0, err
			}
		}
		if !anyIn(held, e.Principals) {
			continue
		}
		out = append(out, e)
		longest = max(longest, e.MaxHours)
	}
	return out, longest, nil
}

// checkEligible refuses a request that no active rule allows.
func checkEligible(c *store.TenantTx, now time.Time, ident *store.Identity, g *store.Group, hours float64) error {
	rules, longest, err := rulesFor(c, now, ident.ID, g.ID)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return &Error{Code: CodeNotEligible,
			Msg: fmt.Sprintf("%s is not eligible to request %s: no JIT eligibility rule covers it", ident.Name, g.Name)}
	}
	if hours > float64(longest) {
		return &Error{Code: CodeNotEligible,
			Msg: fmt.Sprintf("%s may request %s for at most %d hours", ident.Name, g.Name, longest)}
	}
	return nil
}

// checkApprover refuses an approval when the rules that still allow the request name approver groups and the
// approver is in none of them. A rule that no longer allows the request (retired, or the person left its
// principals) denies it: eligibility is checked again at approval.
func checkApprover(c *store.TenantTx, now time.Time, req *store.AccessRequest, approverIdentity int64) error {
	rules, _, err := rulesFor(c, now, req.IdentityID, req.GroupID)
	if err != nil {
		return err
	}
	var allowing []*store.JITEligibility
	for _, e := range rules {
		if req.DurationHours <= float64(e.MaxHours) {
			allowing = append(allowing, e)
		}
	}
	if len(allowing) == 0 {
		return &Error{Code: CodeNotEligible, Kind: KindConflict,
			Msg: "no JIT eligibility rule allows this request any more; deny it or ask again"}
	}
	var held map[int64]bool
	for _, e := range allowing {
		if len(e.Approvers) == 0 {
			return nil
		}
		if held == nil {
			if held, err = standingGroups(c, approverIdentity, now); err != nil {
				return err
			}
		}
		if anyIn(held, e.Approvers) {
			return nil
		}
	}
	keys := make([]string, len(allowing))
	for i, e := range allowing {
		keys[i] = e.Key
	}
	return &Error{Code: CodeNotApprover, Kind: KindForbidden,
		Msg: "you are not an approver for this request under JIT eligibility " + strings.Join(keys, ", ")}
}
