package index

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// prefixOf is the service prefix of an action atom.
func (a *Actions) prefixOf(id int32) string {
	p, _, _ := strings.Cut(a.lower[a.Atoms[id].Rep], ":")
	return p
}

// Applies reports whether the cell (action atom, resource atom) is part of the
// universe (see Config.Applies).
func (ix *Index) Applies(aa, ra int32) bool {
	return ix.applies(ix.Actions.prefixOf(aa), ix.Resources.Info[ra].Service)
}

func (ix *Index) applies(prefix, service string) bool {
	return ix.cfg.Applies == nil || service == "" || ix.cfg.Applies(prefix, service)
}

// AppliesToAction reports whether an action name can be asked of a resource
// with the given info; used for actions and resources outside the universe.
func (ix *Index) AppliesToAction(action string, info ResAtomInfo) bool {
	p, _, _ := strings.Cut(asciiLower(action), ":")
	return ix.applies(p, info.Service)
}

// ApplicableResources returns the resource atoms the actions of a service prefix
// apply to, or nil when every resource does.
func (ix *Index) ApplicableResources(prefix string) Bitset {
	if ix.cfg.Applies == nil {
		return nil
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if b, ok := ix.appRes[prefix]; ok {
		return b
	}
	b := NewBitset(len(ix.Resources.Atoms))
	for id, info := range ix.Resources.Info {
		if ix.applies(prefix, info.Service) {
			b.Set(id)
		}
	}
	ix.appRes[prefix] = b
	return b
}

// ActionPrefix is the service prefix of an action atom.
func (ix *Index) ActionPrefix(aa int32) string { return ix.Actions.prefixOf(aa) }

// Config returns the configuration the index was built with.
func (ix *Index) Config() Config { return ix.cfg }

// PrincipalsWithAction is the set of principal atoms whose envelope holds the
// action atom: the inverted index "action atom to Allow statements" of §12.3,
// lifted to requesters. It is built once, from every envelope.
func (ix *Index) PrincipalsWithAction(aa int) Bitset {
	ix.whoOnce.Do(func() {
		nA, nP := len(ix.Actions.Atoms), len(ix.Principals.Atoms)
		ix.whoIndex = make([]Bitset, nA)
		for a := range ix.whoIndex {
			ix.whoIndex[a] = NewBitset(nP)
		}
		for p := 0; p < nP; p++ {
			env := ix.Envelope(int32(p)) // #nosec G115 -- p < the number of principal atoms, under 2^31
			env.ForEach(func(a int) { ix.whoIndex[a].Set(p) })
		}
	})
	return ix.whoIndex[aa]
}

// PrincipalsReaching is a superset of the principal atoms that can have a
// decision other than a clean deny on the resource atom: those with an identity
// document with an Allow statement that names both the resource and the action
// atom aa (any action when aa < 0), those a resource policy, KMS grant or ACL
// names, root users, and requesters whose own documents cannot be trusted
// (§12.3, "who can do Y on Z").
func (ix *Index) PrincipalsReaching(ra, aa int32) Bitset {
	nP := len(ix.Principals.Atoms)
	info := ix.Resources.Info[ra]
	if info.HasACL || info.Poisoned {
		return FullBitset(nP)
	}
	set := NewBitset(nP)
	add := func(ids []int32) {
		for _, p := range ids {
			set.Set(int(p))
		}
	}
	// Identity documents that can name the resource.
	// A document counts only if one statement names both the action and the
	// resource; aa < 0 means any action.
	for doc, acts := range ix.inv.idDocsAny {
		if aa < 0 || acts.Has(int(aa)) {
			add(ix.Principals.byDoc[doc])
		}
	}
	for _, pid := range ix.Resources.match[ix.Resources.Atoms[ra].Rep] {
		for _, da := range ix.inv.idDocsByPat[pid] {
			if aa < 0 || da.actions.Has(int(aa)) {
				add(ix.Principals.byDoc[da.doc])
			}
		}
	}
	// Principals a resource policy names.
	for _, doc := range info.RBPDocs {
		d := ix.Snap.Policies[doc]
		if d == nil {
			continue
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			if st.Effect != model.EffectAllow || st.Principals == nil {
				continue
			}
			for _, e := range st.Principals.Entries {
				for _, k := range entryKeys(e, ix.Snap.CanonicalIDs) {
					ix.addNamed(set, k)
				}
			}
		}
	}
	// Principals a KMS grant names.
	if info.KMSKey {
		for _, g := range ix.Snap.KMSGrants[ix.Resources.RepARN(ra)] {
			for _, s := range []string{g.GranteePrincipal, g.GranteeServicePrincipal, g.RetiringPrincipal} {
				if s != "" {
					add(ix.inv.prinByLower[asciiLower(s)])
				}
			}
			for _, s := range []string{g.GranteePrincipal, g.RetiringPrincipal} {
				if acct := rootAccount(s); acct != "" {
					add(ix.Principals.byAccount[acct])
				}
			}
		}
	}
	add(ix.Principals.byKind[model.Root])
	for id, i := range ix.Principals.Info {
		if i.Unprunable {
			set.Set(id)
		}
	}
	return set
}

// addNamed adds the principal atoms a principal key stands for.
func (ix *Index) addNamed(set Bitset, key string) {
	switch {
	case key == "*":
		set.Or(FullBitset(len(ix.Principals.Atoms)))
	case len(key) > 5 && key[:5] == "acct:":
		for _, p := range ix.Principals.byAccount[key[5:]] {
			set.Set(int(p))
		}
	case len(key) > 2 && key[:2] == "v:":
		for _, p := range ix.inv.prinByValue[key[2:]] {
			set.Set(int(p))
		}
	}
}

// rootAccount returns the account of an account-root ARN, or "".
func rootAccount(s string) string {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) == 6 && parts[2] == "iam" && parts[5] == "root" {
		return parts[4]
	}
	return ""
}

// ExternalAccounts lists the accounts the resource's policies name that have no
// principal in the snapshot: for each, "any principal in the account, subject to
// the account's own policies" can reach the resource (§12.3).
func (ix *Index) ExternalAccounts(ra int32) []string {
	set := map[string]bool{}
	for _, doc := range ix.Resources.Info[ra].RBPDocs {
		d := ix.Snap.Policies[doc]
		if d == nil {
			continue
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			if st.Effect != model.EffectAllow || st.Principals == nil {
				continue
			}
			for _, e := range st.Principals.Entries {
				if e.AccountID != "" && len(ix.Principals.byAccount[e.AccountID]) == 0 {
					set[e.AccountID] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// NamesAnyone reports whether an Allow statement of the resource's policies
// names "*" as principal.
func (ix *Index) NamesAnyone(ra int32) bool {
	for _, doc := range ix.Resources.Info[ra].RBPDocs {
		d := ix.Snap.Policies[doc]
		if d == nil {
			continue
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			if st.Effect == model.EffectAllow && st.Principals.HasWildcard() {
				return true
			}
		}
	}
	return false
}
