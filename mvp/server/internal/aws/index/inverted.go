package index

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// docActions is a document and the actions of some of its statements.
type docActions struct {
	doc     string
	actions Bitset
}

// stmtRef names one statement of a document.
type stmtRef struct {
	Doc string
	Idx int
}

// inverted holds the inverted indexes of §12.3: from the things a query starts
// with (a requester, a resource) to the statements and atoms that can matter.
type inverted struct {
	// rbpByKey maps a principal key (see principalKeys) to the Allow statements of
	// resource-based policies whose Principal names it.
	rbpByKey map[string][]stmtRef
	// kmsByGrantee maps a lower-cased grantee or retiring principal to the keys
	// that have a grant naming it; kmsByRoot does the same for "root of account".
	kmsByGrantee map[string][]string
	kmsByRoot    map[string][]string
	// idDocsByPat maps a resource pattern id to the identity documents with an
	// Allow statement that names it, with the actions of those statements;
	// idDocsAny maps the documents that can reach any resource (Resource "*" or
	// NotResource) to the actions of those statements.
	idDocsByPat map[int32][]docActions
	idDocsAny   map[string]Bitset
	// prinByValue maps an identity string (ARN, entity ARN, unique id, provider,
	// lower-cased) to the principal atoms that carry it.
	prinByValue map[string][]int32
	prinByLower map[string][]int32
	// aclAtoms are the resource atoms with an S3 ACL grant; poisoned the ones
	// whose documents cannot be trusted.
	aclAtoms []int32
	poisoned []int32
}

// principalKeys are the keys under which resource-policy statements can name p.
func principalKeys(p *model.Principal) []string {
	ks := []string{"*"}
	if p.AccountID != "" {
		ks = append(ks, "acct:"+p.AccountID)
	}
	for _, v := range []string{p.ARN, p.EntityARN, p.UniqueID, p.FederatedProvider} {
		if v != "" {
			ks = append(ks, "v:"+v)
		}
	}
	return ks
}

// entryKeys are the keys a Principal entry is filed under.
func entryKeys(e model.PrincipalEntry, canon map[string]string) []string {
	switch e.Kind {
	case model.PrincipalWildcard:
		return []string{"*"}
	case model.PrincipalAccount:
		return []string{"acct:" + e.AccountID}
	case model.PrincipalCanonicalUser:
		if a := canon[e.Value]; a != "" {
			return []string{"acct:" + a}
		}
		return nil
	}
	return []string{"v:" + e.Value}
}

func buildInverted(ix *Index) *inverted {
	snap := ix.Snap
	inv := &inverted{rbpByKey: map[string][]stmtRef{}, kmsByGrantee: map[string][]string{}, kmsByRoot: map[string][]string{},
		idDocsByPat: map[int32][]docActions{}, idDocsAny: map[string]Bitset{}, prinByValue: map[string][]int32{}, prinByLower: map[string][]int32{}}

	// Resource-based policies.
	docIDs := map[string]bool{}
	for _, rps := range snap.ResourcePolicies {
		for _, rp := range rps {
			docIDs[rp.PolicyID] = true
		}
	}
	for _, id := range keys(docIDs) {
		d := snap.Policies[id]
		if d == nil {
			continue
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			if st.Effect != model.EffectAllow || st.Principals == nil {
				continue
			}
			seen := map[string]bool{}
			for _, e := range st.Principals.Entries {
				for _, k := range entryKeys(e, snap.CanonicalIDs) {
					if !seen[k] {
						seen[k] = true
						inv.rbpByKey[k] = append(inv.rbpByKey[k], stmtRef{id, i})
					}
				}
			}
		}
	}

	// KMS grants.
	for key, gs := range snap.KMSGrants {
		for _, g := range gs {
			for _, s := range []string{g.GranteePrincipal, g.GranteeServicePrincipal, g.RetiringPrincipal} {
				if s == "" {
					continue
				}
				inv.kmsByGrantee[asciiLower(s)] = append(inv.kmsByGrantee[asciiLower(s)], key)
				if parts := strings.SplitN(s, ":", 6); len(parts) == 6 && parts[2] == "iam" && parts[5] == "root" && parts[4] != "" {
					inv.kmsByRoot[parts[4]] = append(inv.kmsByRoot[parts[4]], key)
				}
			}
		}
	}
	for k, v := range inv.kmsByGrantee {
		inv.kmsByGrantee[k] = uniqueSorted(v)
	}
	for k, v := range inv.kmsByRoot {
		inv.kmsByRoot[k] = uniqueSorted(v)
	}

	// Identity documents by the resource patterns they name.
	rs := ix.Resources
	nA := len(ix.Actions.Atoms)
	docs := make([]string, 0, len(ix.Principals.byDoc))
	for doc := range ix.Principals.byDoc {
		docs = append(docs, doc)
	}
	sort.Strings(docs)
	for _, doc := range docs {
		d := snap.Policies[doc]
		if d == nil {
			continue
		}
		byPat := map[int32]Bitset{}
		anyActs := func(set Bitset) {
			if inv.idDocsAny[doc] == nil {
				inv.idDocsAny[doc] = NewBitset(nA)
			}
			inv.idDocsAny[doc].Or(set)
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			if st.Effect != model.EffectAllow {
				continue
			}
			set, exact := ix.stmtActionSet(st)
			if !exact {
				set = FullBitset(nA)
			}
			if st.NotResources != nil {
				anyActs(set)
				continue
			}
			if st.Resources == nil {
				continue
			}
			for _, t := range append(append([]string(nil), st.Resources.Patterns...), st.Resources.Completed...) {
				if t == "*" {
					anyActs(set)
					continue
				}
				if strings.Contains(t, "${") {
					t = skeleton(t)
				}
				id, ok := rs.pats.ids[t]
				if !ok || !rs.pats.live[id] {
					anyActs(set) // unreadable pattern: the document may reach anything
					continue
				}
				if byPat[id] == nil {
					byPat[id] = NewBitset(nA)
				}
				byPat[id].Or(set)
			}
		}
		for id, acts := range byPat {
			inv.idDocsByPat[id] = append(inv.idDocsByPat[id], docActions{doc: doc, actions: acts})
		}
	}

	// Principals by identity string.
	for _, at := range ix.Principals.Atoms {
		p := ix.Principals.Info[at.ID].P
		for _, v := range []string{p.ARN, p.EntityARN, p.UniqueID, p.FederatedProvider} {
			if v != "" {
				inv.prinByValue[v] = append(inv.prinByValue[v], at.ID)
				inv.prinByLower[asciiLower(v)] = append(inv.prinByLower[asciiLower(v)], at.ID)
			}
		}
	}
	// Only the representative's strings are indexed: a string some policy names is
	// a probe, and a probe match is part of the atom's signature, so every
	// member of the atom carries the same named strings.
	for k, v := range inv.prinByValue {
		inv.prinByValue[k] = uniqueSortedInt32(v)
	}
	for k, v := range inv.prinByLower {
		inv.prinByLower[k] = uniqueSortedInt32(v)
	}

	for id, info := range rs.Info {
		if info.HasACL {
			inv.aclAtoms = append(inv.aclAtoms, int32(id))
		}
		if info.Poisoned {
			inv.poisoned = append(inv.poisoned, int32(id))
		}
	}
	return inv
}

func uniqueSortedInt32(in []int32) []int32 {
	out := append([]int32(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	w := 0
	for i, v := range out {
		if i == 0 || v != out[w-1] {
			out[w] = v
			w++
		}
	}
	return out[:w]
}
