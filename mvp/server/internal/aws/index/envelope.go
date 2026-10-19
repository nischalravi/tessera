package index

import (
	"sort"
	"strings"
	"sync"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// ---------------------------------------------------------------- statements

// stmtActionSet is the set of action atoms a statement's Action or NotAction
// names (NotAction is the complement). exact is false when a pattern is not in
// the action table (it failed to compile): the statement cannot be read, so an
// Allow must count as naming everything and a Deny as naming nothing.
func (ix *Index) stmtActionSet(st *model.Statement) (set Bitset, exact bool) {
	a := ix.Actions
	n := len(a.Atoms)
	ps, negate := st.Actions, false
	if ps == nil {
		ps, negate = st.NotActions, true
	}
	set = NewBitset(n)
	if ps == nil {
		return set, true
	}
	exact = true
	for _, t := range ps.Patterns {
		atoms, ok := a.PatternAtoms(asciiLower(t))
		if !ok {
			exact = false
			continue
		}
		for _, id := range atoms {
			set.Set(int(id))
		}
	}
	if negate {
		full := FullBitset(n)
		full.AndNot(set)
		set = full
	}
	return set, exact
}

// docAct is the actions a policy document can allow, and the ones it denies
// whatever the request (§12.3).
type docAct struct {
	allow Bitset
	// denyAlways: actions named by a Deny statement with no condition, no
	// principal element and Resource "*", which matches every request.
	denyAlways Bitset
}

func (ix *Index) docActions(id string) *docAct {
	ix.mu.Lock()
	if d, ok := ix.docAct[id]; ok {
		ix.mu.Unlock()
		return d
	}
	ix.mu.Unlock()
	n := len(ix.Actions.Atoms)
	out := &docAct{allow: NewBitset(n), denyAlways: NewBitset(n)}
	if d := ix.Snap.Policies[id]; d != nil {
		for i := range d.Statements {
			st := &d.Statements[i]
			set, exact := ix.stmtActionSet(st)
			switch st.Effect {
			case model.EffectAllow:
				if !exact {
					set = FullBitset(n)
				}
				out.allow.Or(set)
			case model.EffectDeny:
				if exact && len(st.Condition) == 0 && st.Principals == nil && st.NotPrincipals == nil &&
					st.NotResources == nil && st.Resources != nil && containsStar(st.Resources.Patterns) {
					out.denyAlways.Or(set)
				}
			}
		}
	}
	ix.mu.Lock()
	ix.docAct[id] = out
	ix.mu.Unlock()
	return out
}

func containsStar(ps []string) bool {
	for _, p := range ps {
		if p == "*" {
			return true
		}
	}
	return false
}

// allowUnion is the union of the allowed actions of the documents.
func (ix *Index) allowUnion(ids []string) Bitset {
	u := NewBitset(len(ix.Actions.Atoms))
	for _, id := range ids {
		u.Or(ix.docActions(id).allow)
	}
	return u
}

// ---------------------------------------------------------------- envelope

type envSlot struct {
	once sync.Once
	env  Bitset
}

// Envelope is the set of action atoms that can be anything but a clean Deny for
// the requesters of a principal atom (§12.3): what the identity policies allow,
// capped by the boundary and the session policies, plus whatever resource-based
// policies, KMS grants and S3 ACLs can add on their own, capped by every SCP
// level, less the actions an unconditional Deny removes. A condition can only
// take access away, so an action outside the envelope is denied; the envelope
// is a superset of what the engine can allow or leave conditional.
//
// A requester whose own documents cannot be trusted (§3.3) gets every action.
func (ix *Index) Envelope(pa int32) Bitset {
	s := &ix.envSlots[pa]
	s.once.Do(func() { s.env = ix.computeEnvelope(pa) })
	return s.env
}

func (ix *Index) computeEnvelope(pa int32) Bitset {
	info := ix.Principals.Info[pa]
	n := len(ix.Actions.Atoms)
	if info.Unprunable {
		return FullBitset(n)
	}
	p := info.P
	env := NewBitset(n)

	// Identity-based grants, capped by the boundary and the session policies.
	if len(info.IdentityDocs) > 0 {
		id := ix.allowUnion(info.IdentityDocs)
		if p.BoundaryPolicyID != "" {
			id.And(ix.allowUnion([]string{p.BoundaryPolicyID}))
		}
		if (p.Kind == model.RoleSession || p.Kind == model.FederatedUserSession) && len(p.SessionPolicyIDs) > 0 {
			id.And(ix.allowUnion(uniqueSorted(p.SessionPolicyIDs)))
		}
		env.Or(id)
	}
	// Resource-based policies that name the requester, whatever the resource.
	for _, k := range principalKeys(p) {
		for _, ref := range ix.inv.rbpByKey[k] {
			set, exact := ix.stmtActionSet(&ix.Snap.Policies[ref.Doc].Statements[ref.Idx])
			if !exact {
				set = FullBitset(n)
			}
			env.Or(set)
		}
	}
	if len(ix.kmsKeysNaming(p)) > 0 {
		for _, id := range ix.Actions.ByPrefix("kms") {
			env.Set(int(id))
		}
	}
	if ix.r.hasACLs {
		for _, id := range ix.Actions.ByPrefix("s3") {
			env.Set(int(id))
		}
	}
	if p.Kind == model.Root {
		env = FullBitset(n) // root holds every permission of its account (§7.2)
	}

	// Every SCP level must allow.
	denyDocs := append([]string(nil), info.Docs...)
	if info.SCPApplies {
		for _, node := range ix.Snap.Org.PathTo(p.AccountID) {
			env.And(ix.allowUnion(node.SCPIDs))
			denyDocs = append(denyDocs, node.SCPIDs...)
		}
	}
	for _, id := range denyDocs {
		env.AndNot(ix.docActions(id).denyAlways)
	}
	return env
}

// kmsKeysNaming lists the keys that have a grant naming the requester, its
// role, or its account root.
func (ix *Index) kmsKeysNaming(p *model.Principal) []string {
	var out []string
	for _, v := range []string{p.ARN, p.EntityARN} {
		if v != "" {
			out = append(out, ix.inv.kmsByGrantee[asciiLower(v)]...)
		}
	}
	if p.AccountID != "" {
		out = append(out, ix.inv.kmsByRoot[p.AccountID]...)
	}
	return out
}

// ---------------------------------------------------------------- grants

// Grant is a block of cells one source can make something other than a clean
// deny: every action atom of Actions on the resource atoms it names. The
// resources are all atoms (All), the atoms matched by any of the patterns Pats,
// and the atoms in Atoms.
type Grant struct {
	// Actions may be wider than the requester's envelope: the caller keeps the
	// actions that are in Envelope(pa), unless Free is set, which marks a block
	// (an untrusted document) that no policy of the requester bounds.
	Actions Bitset
	Free    bool
	All     bool
	Pats    []int32 // resource pattern ids
	Atoms   []int32 // resource atoms, sorted
}

// Reaches reports whether the grant names the resource atom r.
func (ix *Index) Reaches(g *Grant, r int32) bool {
	if g.All {
		return true
	}
	if i := sort.Search(len(g.Atoms), func(i int) bool { return g.Atoms[i] >= r }); i < len(g.Atoms) && g.Atoms[i] == r {
		return true
	}
	if len(g.Pats) == 0 {
		return false
	}
	// Both lists are sorted pattern ids; r's list is short.
	for _, m := range ix.Resources.match[ix.Resources.Atoms[r].Rep] {
		if i := sort.Search(len(g.Pats), func(i int) bool { return g.Pats[i] >= m }); i < len(g.Pats) && g.Pats[i] == m {
			return true
		}
	}
	return false
}

// ReachList lists the resource atoms the grant names, sorted; ok is false when
// it names all of them.
func (ix *Index) ReachList(g *Grant) (list []int32, ok bool) {
	if g.All {
		return nil, false
	}
	n := len(g.Atoms)
	for _, pid := range g.Pats {
		n += len(ix.Resources.patAtoms[pid])
	}
	out := make([]int32, 0, n)
	out = append(out, g.Atoms...)
	for _, pid := range g.Pats {
		out = append(out, ix.Resources.patAtoms[pid]...)
	}
	return uniqueSortedInt32(out), true
}

// stmtGrant fills the resource part of a grant from a statement's Resource or
// NotResource patterns: All for a "*", a NotResource or a pattern that failed to
// compile. A statement with neither names none.
func (ix *Index) stmtGrant(st *model.Statement, g *Grant) {
	rs := ix.Resources
	if st.NotResources != nil {
		g.All = true
		return
	}
	if st.Resources == nil {
		return
	}
	for _, t := range append(append([]string(nil), st.Resources.Patterns...), st.Resources.Completed...) {
		if t == "*" {
			g.All = true
			return
		}
		if strings.Contains(t, "${") {
			t = skeleton(t)
		}
		pid, ok := rs.pats.ids[t]
		if !ok || !rs.pats.live[pid] {
			g.All = true
			return
		}
		g.Pats = append(g.Pats, pid)
	}
	g.Pats = uniqueSortedInt32(g.Pats)
}

// Grants lists the sources that can give a requester anything but a clean deny
// (§12.3, "all effective permissions of X"), each as a block of cells: the Allow
// statements of its identity policies (their actions by their resources), the
// resource policies that name it, the KMS grants that name it, S3 ACLs, and, for
// the root user, everything. Actions are to be cut to the envelope, which applies
// the boundary, the session policies, the SCPs and the unconditional denies.
//
// Cells that are UNSUPPORTED because a document cannot be trusted (§3.3) are not
// bounded by any statement: every action on a resource whose documents cannot be
// trusted is listed, and a requester whose own documents cannot be trusted gets
// every cell.
func (ix *Index) Grants(pa int32) []Grant {
	info := ix.Principals.Info[pa]
	rs := ix.Resources
	nA := len(ix.Actions.Atoms)
	if info.Unprunable {
		return []Grant{{Actions: FullBitset(nA), All: true, Free: true}}
	}
	p := info.P
	var out []Grant
	add := func(actions Bitset, g Grant) {
		g.Actions = actions
		out = append(out, g)
	}
	for _, doc := range info.IdentityDocs {
		out = append(out, ix.docGrants(doc)...)
	}
	for _, k := range principalKeys(p) {
		for _, ref := range ix.inv.rbpByKey[k] {
			set, exact := ix.stmtActionSet(&ix.Snap.Policies[ref.Doc].Statements[ref.Idx])
			if !exact {
				set = FullBitset(nA)
			}
			add(set, Grant{Atoms: rs.rbpAtoms[ref.Doc]})
		}
	}
	if keys := ix.kmsKeysNaming(p); len(keys) > 0 {
		var atoms []int32
		for _, key := range keys {
			if a := rs.Lookup(key); a >= 0 {
				atoms = append(atoms, a)
			}
		}
		kms := NewBitset(nA)
		for _, id := range ix.Actions.ByPrefix("kms") {
			kms.Set(int(id))
		}
		add(kms, Grant{Atoms: uniqueSortedInt32(atoms)})
	}
	if len(ix.inv.aclAtoms) > 0 {
		s3 := NewBitset(nA)
		for _, id := range ix.Actions.ByPrefix("s3") {
			s3.Set(int(id))
		}
		add(s3, Grant{Atoms: ix.inv.aclAtoms})
	}
	if p.Kind == model.Root {
		add(FullBitset(nA), Grant{All: true})
	}
	if len(ix.inv.poisoned) > 0 {
		out = append(out, Grant{Actions: FullBitset(nA), Atoms: ix.inv.poisoned, Free: true})
	}
	return out
}

// docGrants are the grants of one identity document's Allow statements. They do
// not depend on the requester, so they are worked out once and shared; the
// caller must not change them.
func (ix *Index) docGrants(doc string) []Grant {
	ix.mu.Lock()
	if g, ok := ix.docGrant[doc]; ok {
		ix.mu.Unlock()
		return g
	}
	ix.mu.Unlock()
	var out []Grant
	nA := len(ix.Actions.Atoms)
	d := ix.Snap.Policies[doc]
	for i := range d.Statements {
		st := &d.Statements[i]
		if st.Effect != model.EffectAllow {
			continue
		}
		set, exact := ix.stmtActionSet(st)
		if !exact {
			set = FullBitset(nA)
		}
		g := Grant{Actions: set}
		ix.stmtGrant(st, &g)
		out = append(out, g)
	}
	ix.mu.Lock()
	ix.docGrant[doc] = out
	ix.mu.Unlock()
	return out
}

// PoisonedResources lists the resource atoms whose documents cannot be trusted.
func (ix *Index) PoisonedResources() []int32 { return ix.inv.poisoned }
