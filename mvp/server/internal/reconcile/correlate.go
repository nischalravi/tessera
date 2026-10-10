package reconcile

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Correlation outcomes (§6.2).
const (
	Correlated    = "correlated"    // tier 1 or 2: linked
	Proposed      = "proposed"      // tier 3: goes to review, never linked automatically
	Service       = "service"       // non-human: needs an owner, not a person
	Ambiguous     = "ambiguous"     // never auto-resolved
	Uncorrelated  = "uncorrelated"  // no match
	Authoritative = "authoritative" // the HR source itself
)

// Person is an identity of the authoritative source (the live HR identities).
type Person struct {
	ID           int64
	ExternalID   string
	Name         string
	Email        string
	Status       string
	Department   string
	Title        string
	TerminatedAt *string
}

// LiveLink is an already-correlated account in another live connection
// (for tier-2 immutable links).
type LiveLink struct {
	System, ExternalID string
	IdentityID         int64
}

// Result is the correlation of one staged account.
type Result struct {
	System, ExternalID string
	Outcome            string
	Tier               int // 1, 2, 3, or 0
	IdentityID         *int64
	ProposedID         *int64
}

// normID normalizes an HR id: trimmed, case-insensitive.
func normID(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// emails returns the self-asserted addresses of an account (tier 3 only).
func emails(a *store.StagedAccount) []string {
	var out []string
	for _, k := range []string{"mail", "email", "userPrincipalName", "login", "primaryEmail"} {
		if v := strings.ToLower(strings.TrimSpace(a.Attributes[k])); strings.Contains(v, "@") {
			out = append(out, v)
		}
	}
	if u := strings.ToLower(a.Username); strings.Contains(u, "@") {
		out = append(out, u)
	}
	return out
}

// Correlate runs the deterministic tiers over staged accounts.
//
//	tier 1  exact HR id (the template's HR attribute) → correlated
//	tier 2  immutable link ("immutable_link" = system:external_id of a live,
//	        already-correlated account) → correlated
//	tier 3  case-insensitive email, UPN or login → proposed (review queue only)
//	—       non-human kind → service; nothing → uncorrelated
//
// Two people matching at the same tier, or one person matching two
// non-service accounts of the same kind in this system, is ambiguous.
func Correlate(accts []*store.StagedAccount, hrAttr, role string, people []Person, links []LiveLink) []Result {
	byID, byEmail := map[string][]int64{}, map[string][]int64{}
	for _, p := range people {
		byID[normID(p.ExternalID)] = append(byID[normID(p.ExternalID)], p.ID)
		if p.Email != "" {
			byEmail[strings.ToLower(p.Email)] = append(byEmail[strings.ToLower(p.Email)], p.ID)
		}
	}
	linked := map[string]int64{}
	for _, l := range links {
		linked[l.System+":"+l.ExternalID] = l.IdentityID
	}
	out := make([]Result, len(accts))
	for i, a := range accts {
		r := Result{System: a.System, ExternalID: a.ExternalID, Outcome: Uncorrelated}
		switch {
		case role == "authoritative":
			r.Outcome = Authoritative
		case IsService(a):
			r.Outcome = Service
		default:
			if key := normID(a.Attributes[hrAttr]); key != "" && len(byID[key]) > 0 {
				if len(byID[key]) > 1 {
					r.Outcome = Ambiguous
				} else {
					id := byID[key][0]
					r.Outcome, r.Tier, r.IdentityID = Correlated, 1, &id
				}
				break
			}
			if l := a.Attributes["immutable_link"]; l != "" {
				if id, ok := linked[l]; ok {
					r.Outcome, r.Tier, r.IdentityID = Correlated, 2, &id
					break
				}
			}
			matches := map[int64]bool{}
			for _, e := range emails(a) {
				for _, id := range byEmail[e] {
					matches[id] = true
				}
			}
			switch len(matches) {
			case 0:
			case 1:
				for id := range matches {
					id := id
					r.Outcome, r.Tier, r.ProposedID = Proposed, 3, &id
				}
			default:
				r.Outcome = Ambiguous
			}
		}
		out[i] = r
	}
	// One person, several non-service accounts of the same kind here: ambiguous.
	byPerson := map[int64][]int{}
	for i, r := range out {
		if r.Outcome == Correlated && r.IdentityID != nil {
			byPerson[*r.IdentityID] = append(byPerson[*r.IdentityID], i)
		}
	}
	ids := make([]int64, 0, len(byPerson))
	for id := range byPerson {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		idx := byPerson[id]
		if len(idx) < 2 {
			continue
		}
		kinds := map[string]int{}
		for _, i := range idx {
			kinds[accts[i].Kind]++
		}
		for _, i := range idx {
			if kinds[accts[i].Kind] > 1 {
				out[i].Outcome, out[i].Tier = Ambiguous, 0
				out[i].ProposedID, out[i].IdentityID = out[i].IdentityID, nil
			}
		}
	}
	return out
}
