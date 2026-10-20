// Package leastpriv produces usage-based least-privilege recommendations.
package leastpriv

import (
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// SensitiveTags are resource tags that raise a recommendation's score.
var SensitiveTags = map[string]bool{"pii": true, "payments": true, "financial": true, "payroll": true}

// Recommendation is one grant-level or role-level suggestion.
type Recommendation struct {
	ID               string   `json:"id"`
	EdgeID           int64    `json:"edge_id"`
	Kind             string   `json:"kind"` // remove | right_size | redundant | role_trim
	IdentityID       *int64   `json:"identity_id"`
	IdentityName     string   `json:"identity_name"`
	IdentityType     string   `json:"identity_type"`
	Department       *string  `json:"department"`
	Grant            string   `json:"grant"`
	Target           string   `json:"target"`
	TargetPrivileged bool     `json:"target_privileged"`
	PermissionsVia   int      `json:"permissions_via"`
	PermissionsLost  int      `json:"permissions_lost"`
	UnusedLost       int      `json:"unused_lost"`
	UsedLost         int      `json:"used_lost"`
	PrivilegedUnused int      `json:"privileged_unused"`
	SensitiveTags    []string `json:"sensitive_tags"`
	LastUsed         *string  `json:"last_used"`
	DaysSinceUsed    *int     `json:"days_since_used"`
	UnusedExamples   []string `json:"unused_examples"`
	UsedExamples     []string `json:"used_examples"`
	Holders          []string `json:"holders,omitempty"`
	Score            int      `json:"score"`
	Rationale        string   `json:"rationale"`
}

func anyWeak(eps []*graph.EffectivePermission) bool {
	for _, ep := range eps {
		if ep.Weak() {
			return true
		}
	}
	return false
}

func examples(eps []*graph.EffectivePermission) []string {
	out := []string{}
	for i, ep := range eps {
		if i == 5 {
			break
		}
		out = append(out, ep.Action+" on "+ep.ResourceName)
	}
	return out
}

func daysSince(now time.Time, last *time.Time) *int {
	if last == nil {
		return nil
	}
	d := timeutil.Days(now, *last)
	return &d
}

// SortByScore orders recommendations by descending score (stable).
func SortByScore(recs []Recommendation) {
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Score > recs[j].Score })
}

// GrantRecommendations evaluates each standing grant leaving an identity's
// active accounts. identityID nil means every active identity.
func GrantRecommendations(g *graph.Snapshot, u *usage.Index, unusedDays int, identityID *int64) []Recommendation {
	recs := []Recommendation{}
	ids := g.Identities(false)
	if identityID != nil {
		ids = []int64{*identityID}
	}
	for _, iid := range ids {
		inode := g.Node(graph.Key("identity", iid))
		eff := g.EffectivePermissions(iid)
		if eff.Len() == 0 {
			continue
		}
		for _, ag := range g.GrantEdgesFromAccounts(iid) {
			if ag.Edge.EdgeID == nil || ag.Edge.Source == "jit" {
				continue
			}
			if g.Node(ag.Acct).Status != "active" {
				continue
			}
			edge := [2]string{ag.Acct, ag.Dst}
			via := graph.PermsViaEdge(eff, edge)
			if len(via) == 0 {
				continue
			}
			if ag.Edge.Weak() || anyWeak(via) {
				// a grant the evaluator found conditional, approximate or unsupported is
				// not a basis for a recommendation (design §11.5, spec R2)
				continue
			}
			lost := graph.PermsLostIfRemoved(eff, edge)
			var unused, used []*graph.EffectivePermission
			for _, ep := range lost {
				if u.Unused(iid, ep.PermID, unusedDays) {
					unused = append(unused, ep)
				} else {
					used = append(used, ep)
				}
			}
			var kind string
			switch {
			case len(lost) > 0 && len(used) == 0:
				kind = "remove"
			case len(lost) > 0 && float64(len(unused))/float64(len(lost)) >= 0.5:
				kind = "right_size"
			case len(lost) == 0:
				kind = "redundant"
			default:
				continue
			}
			var last *time.Time
			for _, ep := range via {
				if l := u.Get(iid, ep.PermID).LastUsed; l != nil && (last == nil || l.After(*last)) {
					last = l
				}
			}
			privUnused := 0
			sens := map[string]bool{}
			for _, ep := range unused {
				if ep.Privileged {
					privUnused++
				}
				for _, t := range ep.Tags {
					if SensitiveTags[t] {
						sens[t] = true
					}
				}
			}
			sensitive := sortedKeys(sens)
			score := len(unused) + 5*privUnused + 4*len(sensitive)
			if kind == "remove" {
				score += 6
			}
			if inode.Type != "human" {
				score += 3
			}
			if kind == "redundant" {
				score = 1
			}
			id := iid
			recs = append(recs, Recommendation{
				ID: fmt.Sprint(*ag.Edge.EdgeID), EdgeID: *ag.Edge.EdgeID, Kind: kind, IdentityID: &id,
				IdentityName: inode.Label, IdentityType: inode.Type, Department: inode.Department,
				Grant: g.Label(ag.Acct) + " → " + g.Label(ag.Dst), Target: g.Label(ag.Dst),
				TargetPrivileged: g.Node(ag.Dst).Privileged, PermissionsVia: len(via), PermissionsLost: len(lost),
				UnusedLost: len(unused), UsedLost: len(used), PrivilegedUnused: privUnused, SensitiveTags: sensitive,
				LastUsed: timeutil.ISOPtr(last), DaysSinceUsed: daysSince(u.Now, last),
				UnusedExamples: examples(unused), UsedExamples: examples(used), Score: score,
				Rationale: rationale(kind, len(unused), len(lost), unusedDays, last, u.Now),
			})
		}
	}
	SortByScore(recs)
	return recs
}

func rationale(kind string, nUnused, nLost, days int, last *time.Time, now time.Time) string {
	switch kind {
	case "remove":
		when := "never used"
		if last != nil {
			when = fmt.Sprintf("last used %d days ago", timeutil.Days(now, *last))
		}
		return fmt.Sprintf("None of the %d permissions only this grant provides were used in %d days (%s).", nLost, days, when)
	case "right_size":
		return fmt.Sprintf("%d of %d permissions from this grant are unused for %d+ days; replace with a narrower role.", nUnused, nLost, days)
	}
	return "Every permission from this grant is also granted through another path."
}

// UnusedPermissions lists perm keys an identity has not used for days.
func UnusedPermissions(g *graph.Snapshot, u *usage.Index, identityID int64, days int) []string {
	var out []string
	for _, ep := range g.EffectivePermissions(identityID).Values() {
		if u.Unused(identityID, ep.PermID, days) {
			out = append(out, ep.PermKey)
		}
	}
	return out
}

type roleKey struct{ group, perm string }

// RoleTrimRecommendations flags permissions inside a role/group that no
// holder has used: trim them from the role itself.
func RoleTrimRecommendations(g *graph.Snapshot, u *usage.Index, unusedDays, minHolders int) []Recommendation {
	var order []roleKey
	holders := map[roleKey]map[int64]bool{}
	users := map[roleKey]bool{}
	lastSeen := map[roleKey]time.Time{}
	for _, iid := range g.Identities(false) {
		for _, ep := range g.EffectivePermissions(iid).Values() {
			for _, p := range ep.Paths {
				a, b := p[len(p)-2], p[len(p)-1]
				if g.Node(a).Kind != "group" {
					continue
				}
				k := roleKey{a, b}
				if _, ok := holders[k]; !ok {
					holders[k] = map[int64]bool{}
					order = append(order, k)
				}
				holders[k][iid] = true
				st := u.Get(iid, ep.PermID)
				if st.LastUsed != nil && timeutil.Days(u.Now, *st.LastUsed) < unusedDays {
					users[k] = true
				}
				if st.LastUsed != nil {
					if cur, ok := lastSeen[k]; !ok || st.LastUsed.After(cur) {
						lastSeen[k] = *st.LastUsed
					}
				}
			}
		}
	}
	recs := []Recommendation{}
	for _, k := range order {
		who := holders[k]
		if len(who) < minHolders || users[k] {
			continue
		}
		ed := g.EdgeData(k.group, k.perm)
		if ed.EdgeID == nil || ed.Weak() {
			continue
		}
		pn := g.Node(k.perm)
		var last *time.Time
		if t, ok := lastSeen[k]; ok {
			last = &t
		}
		names := make([]string, 0, len(who))
		for i := range who {
			names = append(names, g.Node(graph.Key("identity", i)).Label)
		}
		sort.Strings(names)
		sens := map[string]bool{}
		for _, t := range pn.Tags {
			if SensitiveTags[t] {
				sens[t] = true
			}
		}
		score := len(who) + 5
		if pn.Privileged {
			score += 8
		}
		if len(sens) > 0 {
			score += 6
		}
		privUnused := 0
		if pn.Privileged {
			privUnused = len(who)
		}
		if len(names) > 12 {
			names = names[:12]
		}
		recs = append(recs, Recommendation{
			ID: fmt.Sprintf("role-%d", *ed.EdgeID), EdgeID: *ed.EdgeID, Kind: "role_trim",
			IdentityName: fmt.Sprintf("%d holders", len(who)), IdentityType: "role",
			Grant: g.Label(k.group) + " → " + pn.Label, Target: g.Label(k.group),
			TargetPrivileged: g.Node(k.group).Privileged, PermissionsVia: 1, PermissionsLost: len(who),
			UnusedLost: len(who), PrivilegedUnused: privUnused, SensitiveTags: sortedKeys(sens),
			LastUsed: timeutil.ISOPtr(last), DaysSinceUsed: daysSince(u.Now, last),
			UnusedExamples: []string{pn.Label}, UsedExamples: []string{}, Holders: names, Score: score,
			Rationale: fmt.Sprintf("None of the %d identities that hold %s through %s used it in %d days. Remove it from the role.",
				len(who), pn.Label, g.Label(k.group), unusedDays),
		})
	}
	SortByScore(recs)
	return recs
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
