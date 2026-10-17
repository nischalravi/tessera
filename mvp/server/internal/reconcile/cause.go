package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Cause analysers (§6.5). Each states a probable cause with the numbers it
// used, so a reader can check it, and names the item that fixes it.

// unmappedKey (RF-01, RF-10): the HR id attribute is empty on most unmatched
// accounts; email_would_match adds how many would match by email.
func (a *analysis) unmappedKey(unmatched []*store.StagedAccount, proposalsOnly bool) *Cause {
	attr := a.snap.Meta.HRAttribute
	if len(unmatched) == 0 || attr == "" {
		return nil
	}
	empty, proposals := 0, 0
	for _, x := range unmatched {
		if strings.TrimSpace(x.Attributes[attr]) == "" {
			empty++
		}
		if x.Correlation == Proposed {
			proposals++
		}
	}
	matchedEmpty, matched := 0, 0
	for _, x := range a.snap.Accounts {
		if x.Correlation == Correlated {
			matched++
			if strings.TrimSpace(x.Attributes[attr]) == "" {
				matchedEmpty++
			}
		}
	}
	share := percent(empty, len(unmatched))
	if share < 50 {
		return nil
	}
	s := fmt.Sprintf("%s uncorrelated because %s is empty on %d%% of them.", plural(len(unmatched), "account", "accounts"), attr, share)
	analyser := "unmapped_key"
	if proposalsOnly {
		s = fmt.Sprintf("%s match a person only by email because %s is empty on %d%% of them. Map %s to correlate them by HR id.",
			plural(len(unmatched), "account", "accounts"), attr, share, attr)
	} else if proposals > 0 {
		s += fmt.Sprintf(" %d of them match a person by email: map %s, or review the proposals.", proposals, attr)
		analyser = "unmapped_key+email_would_match"
	}
	return &Cause{Analyser: analyser, Sentence: s, FixItem: a.snap.Meta.HRItem, Probable: true,
		Numbers: map[string]any{"unmatched": len(unmatched), "unmatched_without_key": empty, "matched": matched,
			"matched_without_key": matchedEmpty, "email_proposals": proposals}}
}

// scopeConcentration (RF-02): one department or title holds most of the
// people with no account, which points at a missing OU or population.
func scopeConcentration(missing, all []Person) *Cause {
	if len(missing) < 3 {
		return nil
	}
	for _, dim := range []struct {
		name string
		key  func(Person) string
	}{{"department", func(p Person) string { return p.Department }}, {"title", func(p Person) string { return p.Title }}} {
		counts, totals := map[string]int{}, map[string]int{}
		for _, p := range missing {
			counts[dim.key(p)]++
		}
		for _, p := range all {
			totals[dim.key(p)]++
		}
		for v, n := range counts {
			if v == "" || float64(n)/float64(len(missing)) <= 0.6 {
				continue
			}
			return &Cause{Analyser: "scope_concentration", Probable: true,
				Sentence: fmt.Sprintf("%d%% of people with no account are in %s %q (%d of %d people there). Check that its OU or population is in scope.",
					percent(n, len(missing)), dim.name, v, n, totals[v]),
				Numbers: map[string]any{"dimension": dim.name, "value": v, "missing": n, "population": totals[v]}}
		}
	}
	return nil
}

// leaverProcess (RF-06b): how long ago people left, and whether this system
// is the only one the leaver process missed.
func (a *analysis) leaverProcess(hits []*store.StagedAccount) *Cause {
	if len(hits) == 0 {
		return nil
	}
	grace := int(a.threshold("leaver_grace_days", 14))
	old, onlyHere := 0, 0
	var first Person
	firstDays := -1
	for i, x := range hits {
		p := a.in.People[*x.IdentityID]
		d := a.daysSince(p.TerminatedAt)
		if i == 0 {
			first, firstDays = p, d
		}
		if d > grace {
			old++
		}
		if a.in.Elsewhere[p.ID] == 0 {
			onlyHere++
		}
	}
	sys := a.snap.Meta.SystemName
	var s string
	if len(hits) == 1 {
		s = fmt.Sprintf("%s left %d days ago and is still active in %s.", first.Name, firstDays, sys)
		if onlyHere == 1 {
			s += " Every other account was disabled: the leaver process does not cover this system."
		}
	} else {
		// Count accounts (what the finding counts), not the subset past the
		// grace period, so the sentence and the finding agree.
		if old == len(hits) {
			s = fmt.Sprintf("%s belong to people who left more than %d days ago and are still enabled in %s",
				plural(len(hits), "account", "accounts"), grace, sys)
		} else {
			s = fmt.Sprintf("%s belong to people who left and are still enabled in %s (%d left more than %d days ago)",
				plural(len(hits), "account", "accounts"), sys, old, grace)
		}
		if onlyHere == len(hits) {
			s += ", and only here: the leaver process does not cover this system."
		} else {
			s += "."
		}
	}
	return &Cause{Analyser: "leaver_process", Sentence: s, Probable: true,
		Numbers: map[string]any{"leavers": len(hits), "older_than_grace": old, "grace_days": grace, "enabled_only_here": onlyHere}}
}

// scopeExclusion (RF-05): the out-of-scope groups share a DN suffix.
func scopeExclusion(groups []string) *Cause {
	if len(groups) == 0 {
		return nil
	}
	parent := func(dn string) string {
		_, rest, ok := strings.Cut(dn, ",")
		if !ok {
			return ""
		}
		return rest
	}
	counts := map[string]int{}
	for _, g := range groups {
		if p := parent(g); p != "" {
			counts[p]++
		}
	}
	best, n := "", 0
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if counts[k] > n {
			best, n = k, counts[k]
		}
	}
	if best == "" || float64(n)/float64(len(groups)) < 0.5 {
		return nil
	}
	return &Cause{Analyser: "scope_exclusion", Probable: true,
		Sentence: fmt.Sprintf("%s under %s %s outside the base DNs.", plural(n, "group", "groups"), best, map[bool]string{true: "is", false: "are"}[n == 1]),
		Numbers:  map[string]any{"groups": n, "container": best}}
}

// privilegedPolicyGap (RF-08): the unexpected members share a nesting path.
func (a *analysis) privilegedPolicyGap(accts []*store.StagedAccount, groups []string) *Cause {
	if len(accts) < 2 {
		return nil
	}
	direct := map[string]map[string]bool{}
	for _, m := range a.snap.Memberships {
		if m.MemberKind == "account" {
			if direct[m.MemberXID] == nil {
				direct[m.MemberXID] = map[string]bool{}
			}
			direct[m.MemberXID][m.GroupXID] = true
		}
	}
	// A non-privileged group that every unexpected member is directly in.
	common := map[string]int{}
	for _, x := range accts {
		for g := range direct[x.ExternalID] {
			if sg, ok := a.snap.Group(g); ok && !sg.Privileged {
				common[g]++
			}
		}
	}
	keys := make([]string, 0, len(common))
	for g := range common {
		keys = append(keys, g)
	}
	sort.Strings(keys)
	for _, g := range keys {
		if common[g] == len(accts) {
			sg, _ := a.snap.Group(g)
			return &Cause{Analyser: "privileged_policy_gap", Probable: true,
				Sentence: fmt.Sprintf("All %d reach %s through %s.", len(accts), groups[0], sg.Name),
				Numbers:  map[string]any{"members": len(accts), "via": sg.Name}}
		}
	}
	return nil
}
