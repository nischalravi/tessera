package index

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
)

// An atom is an equivalence class of actions, resources or requesters that no
// policy in the snapshot can tell apart (§12.2). Evaluating the representative
// stands for every member.
//
// The grouping key of an item is its facts (everything the engine reads about it
// other than patterns, as a string) plus the sorted ids of the patterns that
// match it. Atom.Sig is a hash of the facts and the matched pattern TEXTS, so it
// does not depend on pattern ids or on the other items: two snapshots give the
// same Sig to atoms that behave the same, which is what lets the memo (§12.4)
// survive a policy change.
type Atom struct {
	ID      int32
	Rep     int32   // item index of the representative: the first member
	Sig     string  // stable across snapshots
	Members []int32 // item indexes, ascending
}

// patTable is the set of distinct pattern texts of one kind. Ids are stable
// across refinements: a removed pattern keeps its id (live false) until the
// next full rebuild, which is the design's "merged back lazily" (§12.5).
type patTable struct {
	text []string
	ids  map[string]int32
	live []bool
}

func newPatTable() patTable { return patTable{ids: map[string]int32{}} }

func (t patTable) clone() patTable {
	c := patTable{text: append([]string(nil), t.text...), ids: make(map[string]int32, len(t.ids)),
		live: append([]bool(nil), t.live...)}
	for k, v := range t.ids {
		c.ids[k] = v
	}
	return c
}

func (t *patTable) add(s string) int32 {
	if id, ok := t.ids[s]; ok {
		t.live[id] = true
		return id
	}
	id := int32(len(t.text)) // #nosec G115 -- a pattern table is far below 2^31 entries; Build bounds the universes
	t.text = append(t.text, s)
	t.live = append(t.live, true)
	t.ids[s] = id
	return id
}

// scanPrefix calls fn for each index of keys (sorted ascending) that starts with prefix.
func scanPrefix(keys []string, prefix string, fn func(i int)) {
	i := sort.SearchStrings(keys, prefix)
	for ; i < len(keys) && strings.HasPrefix(keys[i], prefix); i++ {
		fn(i)
	}
}

// grouping assigns items to atoms by key. key(i) must be identical for items
// that behave alike.
func group(n int, key func(i int) string, sig func(rep int) string) (atomOf []int32, atoms []Atom, byKey map[string]int32) {
	atomOf = make([]int32, n)
	byKey = make(map[string]int32)
	for i := 0; i < n; i++ {
		k := key(i)
		id, ok := byKey[k]
		if !ok {
			id = int32(len(atoms)) // #nosec G115 -- at most one atom per item, and Build bounds the universes to under 2^31
			byKey[k] = id
			atoms = append(atoms, Atom{ID: id, Rep: int32(i)}) // #nosec G115 -- i < n, bounded as above
		}
		atomOf[i] = id
		atoms[id].Members = append(atoms[id].Members, int32(i))
	}
	for i := range atoms {
		atoms[i].Sig = sig(int(atoms[i].Rep))
	}
	return atomOf, atoms, byKey
}

// matchKey encodes sorted pattern ids for a grouping key.
func matchKey(facts string, ids []int32) string {
	var b strings.Builder
	b.Grow(len(facts) + 1 + len(ids)*3)
	b.WriteString(facts)
	b.WriteByte(0)
	var buf [binary.MaxVarintLen32]byte
	for _, id := range ids {
		n := binary.PutUvarint(buf[:], uint64(id)) // #nosec G115 -- pattern ids are non-negative
		b.Write(buf[:n])
	}
	return b.String()
}

// sigOf hashes facts and the texts of the matched patterns.
func sigOf(facts string, t *patTable, ids []int32) string {
	h := sha256.New()
	h.Write([]byte(facts))
	h.Write([]byte{0})
	texts := make([]string, len(ids))
	for i, id := range ids {
		texts[i] = t.text[id]
	}
	sort.Strings(texts)
	for _, s := range texts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// shortHash hashes parts for use inside a facts string.
func shortHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// ---------------------------------------------------------------- actions

// Actions are the action atoms: the catalog actions grouped by which action
// patterns match them, the catalog facts the engine reads for them (resource-tag
// support, the KMS cross-account allowlist, the S3 ACL map) and, for the few
// actions the engine treats by name, the name.
//
// Deviation from §12.2: there is no "future action of service s" sentinel atom.
// Evaluating one would hit the catalog-miss path and only report UNSUPPORTED.
// Callers who need an action outside the universe use AtomOfAction, which
// computes its atom on the fly.
type Actions struct {
	Names   []string // the universe, sorted by lower-cased name
	lower   []string
	byLower map[string]int32
	pats    patTable
	compile []*glob.Pattern // by pattern id; nil for a removed pattern
	match   [][]int32       // per name: sorted ids of the live patterns that match
	facts   []string
	AtomOf  []int32
	Atoms   []Atom
	byKey   map[string]int32
	// PatAtoms maps a pattern id to the atoms it matches.
	patAtoms [][]int32
	byPrefix map[string][]int32 // service prefix to atoms
}

// RefineStats says how much work a refinement avoided and how local it was.
type RefineStats struct {
	PatternsAdded int
	PatternsGone  int
	ItemsReused   int // items whose match lists were kept
	ItemsRebuilt  int
	AtomsSplit    int // atoms of the previous index whose members now span several atoms
	AtomsMerged   int // atoms of this index that hold members of several previous atoms
	PreviousAtoms int
	AtomsAfter    int
}

type actionEnv struct {
	cat          eval.Catalog
	hasKMSGrants bool
	acl          map[string]string // lower action to its ACL-permission bits
}

func aclBits(cat eval.Catalog) map[string]string {
	perms := []string{"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}
	scopes := []eval.S3ACLScope{eval.S3ACLBucket, eval.S3ACLObject}
	acc := map[string][]byte{}
	for si, s := range scopes {
		for pi, p := range perms {
			for _, a := range cat.S3ACLActions(s, p) {
				la := asciiLower(a)
				if acc[la] == nil {
					acc[la] = []byte("0000000000")
				}
				acc[la][si*5+pi] = '1'
			}
		}
	}
	out := make(map[string]string, len(acc))
	for k, v := range acc {
		out[k] = string(v)
	}
	return out
}

// actionFacts are the non-pattern facts of an action.
func (e *actionEnv) actionFacts(name string) string {
	canon, ok := e.cat.CanonicalAction(name)
	if !ok {
		canon = asciiLower(name)
	}
	lower := asciiLower(canon)
	prefix, _, _ := strings.Cut(lower, ":")
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteByte('|')
	b.WriteString(boolStr(ok))
	b.WriteString(boolStr(e.cat.ResourceTagsSupported(canon)))
	b.WriteString(boolStr(e.cat.KMSCrossAccountOp(canon)))
	if bits, ok := e.acl[lower]; ok {
		b.WriteString("|acl:" + bits)
	}
	if eval.SpecialAction(lower) || (prefix == "kms" && e.hasKMSGrants) {
		b.WriteString("|name:" + lower)
	}
	return b.String()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// buildActions groups names into atoms. prev, when not nil, is the previous
// index's actions: its pattern ids and match lists are reused and only the
// patterns that changed are scanned.
func buildActions(names []string, r *refs, env *actionEnv, prev *Actions) (*Actions, RefineStats) {
	var st RefineStats
	a := &Actions{byLower: map[string]int32{}}
	uniq := map[string]string{}
	for _, n := range names {
		uniq[asciiLower(n)] = n
	}
	a.lower = make([]string, 0, len(uniq))
	for l := range uniq {
		a.lower = append(a.lower, l)
	}
	sort.Strings(a.lower)
	a.Names = make([]string, len(a.lower))
	for i, l := range a.lower {
		a.Names[i] = uniq[l]
		a.byLower[l] = int32(i)
	}

	if prev != nil {
		a.pats = prev.pats.clone()
		a.compile = append([]*glob.Pattern(nil), prev.compile...)
		for id := range a.pats.live {
			a.pats.live[id] = false
		}
	} else {
		a.pats = newPatTable()
	}
	var added []int32
	for _, t := range r.actionPats {
		_, had := a.pats.ids[t]
		id := a.pats.add(t)
		if !had {
			p, err := glob.Compile(t, true)
			if err != nil {
				a.pats.live[id] = false // scanRefs flagged the document
				p = nil
			}
			a.compile = append(a.compile, p)
			added = append(added, id)
			st.PatternsAdded++
		} else if prev != nil && !prev.pats.live[id] {
			added = append(added, id) // was removed earlier, is back: rescan
			st.PatternsAdded++
		}
	}
	var gone []int32
	if prev != nil {
		for id, live := range prev.pats.live {
			if live && !a.pats.live[id] {
				gone = append(gone, int32(id))
				st.PatternsGone++
			}
		}
	}

	a.match = make([][]int32, len(a.lower))
	fresh := make([]bool, len(a.lower))
	for i, l := range a.lower {
		if prev != nil {
			if pi, ok := prev.byLower[l]; ok {
				a.match[i] = prev.match[pi]
				st.ItemsReused++
				continue
			}
		}
		// With no previous index every pattern is "added" and scanned below; only
		// a new item of a refinement is tested against all the patterns.
		fresh[i] = prev != nil
		st.ItemsRebuilt++
	}
	if len(gone) > 0 {
		goneSet := map[int32]bool{}
		for _, id := range gone {
			goneSet[id] = true
		}
		for i := range a.match {
			ids := a.match[i]
			hit := false
			for _, id := range ids {
				if goneSet[id] {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			kept := make([]int32, 0, len(ids))
			for _, id := range ids {
				if !goneSet[id] {
					kept = append(kept, id)
				}
			}
			a.match[i] = kept
		}
	}
	// New items test every live pattern; reused items scan the added patterns.
	for i := range a.lower {
		if !fresh[i] {
			continue
		}
		for id, p := range a.compile {
			if p != nil && a.pats.live[id] && p.Match(a.lower[i]) {
				a.match[i] = append(a.match[i], int32(id))
			}
		}
	}
	for _, id := range added {
		p := a.compile[id]
		if p == nil {
			continue
		}
		scanPrefix(a.lower, literalPrefix(a.pats.text[id]), func(i int) {
			if !fresh[i] && p.Match(a.lower[i]) {
				a.match[i] = insertSorted(a.match[i], id)
			}
		})
	}

	a.facts = make([]string, len(a.lower))
	for i := range a.lower {
		a.facts[i] = env.actionFacts(a.Names[i])
	}
	var byKey map[string]int32
	a.AtomOf, a.Atoms, byKey = group(len(a.lower),
		func(i int) string { return matchKey(a.facts[i], a.match[i]) },
		func(i int) string { return sigOf(a.facts[i], &a.pats, a.match[i]) })
	a.byKey = byKey
	a.patAtoms = make([][]int32, len(a.pats.text))
	a.byPrefix = map[string][]int32{}
	for _, at := range a.Atoms {
		for _, id := range a.match[at.Rep] {
			a.patAtoms[id] = append(a.patAtoms[id], at.ID)
		}
		prefix, _, _ := strings.Cut(a.lower[at.Rep], ":")
		a.byPrefix[prefix] = append(a.byPrefix[prefix], at.ID)
	}
	if prev != nil {
		st.PreviousAtoms, st.AtomsSplit, st.AtomsMerged = refineCounts(prev.Atoms, prev.lower, a.AtomOf, a.byLower, len(a.Atoms))
		st.AtomsAfter = len(a.Atoms)
	}
	return a, st
}

// insertSorted adds id to a sorted list without touching the caller's backing array.
func insertSorted(ids []int32, id int32) []int32 {
	i := sort.Search(len(ids), func(i int) bool { return ids[i] >= id })
	if i < len(ids) && ids[i] == id {
		return ids
	}
	out := make([]int32, 0, len(ids)+1)
	out = append(out, ids[:i]...)
	out = append(out, id)
	return append(out, ids[i:]...)
}

// refineCounts compares the partition of the previous index with the new one over
// the items they share (looked up by key).
func refineCounts(prevAtoms []Atom, prevKeys []string, newAtomOf []int32, newIdx map[string]int32, newAtoms int) (prev, split, merged int) {
	prev = len(prevAtoms)
	back := map[int32]map[int32]bool{} // new atom to the previous atoms of its members
	for _, at := range prevAtoms {
		seen := map[int32]bool{}
		for _, m := range at.Members {
			if ni, ok := newIdx[prevKeys[m]]; ok {
				seen[newAtomOf[ni]] = true
				if back[newAtomOf[ni]] == nil {
					back[newAtomOf[ni]] = map[int32]bool{}
				}
				back[newAtomOf[ni]][at.ID] = true
			}
		}
		if len(seen) > 1 {
			split++
		}
	}
	for _, from := range back {
		if len(from) > 1 {
			merged++
		}
	}
	return prev, split, merged
}

// Lookup returns the atom of a universe action, or -1.
func (a *Actions) Lookup(name string) int32 {
	if i, ok := a.byLower[asciiLower(name)]; ok {
		return a.AtomOf[i]
	}
	return -1
}

// Atom returns the atom with the given id.
func (a *Actions) Atom(id int32) *Atom { return &a.Atoms[id] }

// RepName is the representative's name.
func (a *Actions) RepName(id int32) string { return a.Names[a.Atoms[id].Rep] }

// MemberNames lists the member actions of an atom.
func (a *Actions) MemberNames(id int32) []string {
	out := make([]string, len(a.Atoms[id].Members))
	for i, m := range a.Atoms[id].Members {
		out[i] = a.Names[m]
	}
	return out
}

// AtomOfAction returns the atom id of any action name. An action outside the
// universe gets its atom computed on the fly; the id is -1 when no atom has its
// signature, and then Sig and facts describe it alone.
func (a *Actions) AtomOfAction(env *actionEnv, name string) (id int32, sig string) {
	if i := a.Lookup(name); i >= 0 {
		return i, a.Atoms[i].Sig
	}
	l := asciiLower(name)
	facts := env.actionFacts(name)
	var ids []int32
	for pid, p := range a.compile {
		if p != nil && a.pats.live[pid] && p.Match(l) {
			ids = append(ids, int32(pid))
		}
	}
	if id, ok := a.byKey[matchKey(facts, ids)]; ok {
		return id, a.Atoms[id].Sig
	}
	return -1, sigOf(facts, &a.pats, ids)
}

// PatternAtoms lists the atoms a pattern (lower-cased text) matches.
func (a *Actions) PatternAtoms(text string) ([]int32, bool) {
	id, ok := a.pats.ids[text]
	if !ok || !a.pats.live[id] {
		return nil, false
	}
	return a.patAtoms[id], true
}

// ByPrefix lists the atoms of a service prefix.
func (a *Actions) ByPrefix(prefix string) []int32 { return a.byPrefix[prefix] }
