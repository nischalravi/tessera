// Package query answers the three questions of the design (§11.3, §12.3) over an
// index: what can a principal do (EffectivePermissions), who can do an action on
// a resource (WhoCan), and what does a policy change gain or lose (Diff). Each
// answer is the engine's own decision: the index only decides which cells need
// asking, and one answer stands for every member of an atom.
//
// The package is pure: no I/O, no clock, no SQL. Time arrives inside the
// assumption profile.
package query

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
)

// Options is the request context every cell is evaluated under.
type Options struct {
	// Mode is Concrete or Symbolic (§9.4). Symbolic mode with a profile is the
	// default for "what can X do": keys the profile does not pin stay unknown,
	// and the cell is CONDITIONAL on them.
	Mode eval.Mode
	// Profile pins keys for a symbolic query (eval.Profile, eval.DefaultProfile).
	Profile map[string]eval.ContextValue
	// Context holds supplied keys. Keys that name the requester, the resource or
	// the VPC endpoint are refused: an atom stands for many of those, so pinning
	// one would make the atoms wrong.
	Context map[string]eval.ContextValue
	// Workers is the number of goroutines that evaluate cells; 0 means GOMAXPROCS.
	Workers int
}

// Errors.
var (
	ErrUnknownPrincipal = eval.ErrUnknownPrincipal
	ErrOptions          = errors.New("query: unsupported options")
)

// pinnedPrefixes are context keys the atoms already account for.
var pinnedPrefixes = []string{
	"aws:principal", "aws:resource", "aws:userid", "aws:username", "aws:sourceidentity",
	"aws:federatedprovider", "aws:sourcevpce",
}

// Querier answers queries over one index.
type Querier struct {
	Idx     *index.Index
	Memo    *index.Memo
	opts    Options
	profile string
	workers int
}

// New returns a querier. memo may be shared by several queriers (and across the
// two sides of a Diff); nil makes a private one.
func New(idx *index.Index, memo *index.Memo, opts Options) (*Querier, error) {
	for _, m := range []map[string]eval.ContextValue{opts.Profile, opts.Context} {
		for k, v := range m {
			lk := strings.ToLower(k)
			for _, p := range pinnedPrefixes {
				if strings.HasPrefix(lk, p) && v.State == eval.Present {
					return nil, fmt.Errorf("%w: key %q names the requester, resource or endpoint", ErrOptions, k)
				}
			}
		}
	}
	if memo == nil {
		memo = index.NewMemo(1 << 20)
	}
	w := opts.Workers
	if w <= 0 {
		w = runtime.GOMAXPROCS(0)
	}
	return &Querier{Idx: idx, Memo: memo, opts: opts, profile: profileID(opts), workers: w}, nil
}

// profileID is a canonical string of the context a cell is evaluated under.
func profileID(o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "mode=%d", o.Mode)
	for _, m := range []struct {
		name string
		v    map[string]eval.ContextValue
	}{{"profile", o.Profile}, {"context", o.Context}} {
		ks := make([]string, 0, len(m.v))
		for k := range m.v {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			cv := m.v[k]
			vals := append([]string(nil), cv.Values...)
			fmt.Fprintf(&b, "|%s:%s=%d:%q", m.name, strings.ToLower(k), cv.State, vals)
		}
	}
	return b.String()
}

// Can is a point query: the engine's decision with its full trace (§12.1,
// p99 under 20 ms).
func (q *Querier) Can(ctx context.Context, principalARN, action, resourceARN string) (*authz.Decision, error) {
	return eval.Evaluate(ctx, q.Idx.Snap, q.Idx.Cat, q.request(principalARN, action, resourceARN), eval.Options{})
}

func (q *Querier) request(principal, action, resource string) *eval.EvaluationRequest {
	return &eval.EvaluationRequest{PrincipalARN: principal, Action: action, ResourceARN: resource,
		Mode: q.opts.Mode, Profile: q.opts.Profile, Context: q.opts.Context}
}

// target is one atom, or one item that has no atom (an action or resource
// outside the universe), as a query sees it.
type target struct {
	id  int32 // -1: not an atom of the index
	rep string
	sig string
}

func (q *Querier) principalTarget(pa int32) target {
	at := &q.Idx.Principals.Atoms[pa]
	return target{id: pa, rep: q.Idx.Principals.RepARN(pa), sig: at.Sig}
}

func (q *Querier) actionTarget(aa int32) target {
	return target{id: aa, rep: q.Idx.Actions.RepName(aa), sig: q.Idx.Actions.Atoms[aa].Sig}
}

func (q *Querier) resourceTarget(ra int32) target {
	return target{id: ra, rep: q.Idx.Resources.RepARN(ra), sig: q.Idx.Resources.Atoms[ra].Sig}
}

// cell is the decision for one (requester, action, resource) triple, from the
// memo or the engine in fast mode (§12.6).
func (q *Querier) cell(ctx context.Context, p, a, r target) (*index.Cell, error) {
	key := index.NewMemoKey(q.Idx.Global, q.profile, p.sig, a.sig, r.sig)
	if c, ok := q.Memo.Get(key); ok {
		return c, nil
	}
	res := r.rep
	if res == "*" {
		res = ""
	}
	d, err := eval.Evaluate(ctx, q.Idx.Snap, q.Idx.Cat, q.request(p.rep, a.rep, res), eval.Options{Fast: true})
	if err != nil {
		return nil, err
	}
	c := index.NewCell(d)
	q.Memo.Put(key, c)
	return c, nil
}

// parallel runs fn(0..n-1) on the querier's workers and returns the first error.
func (q *Querier) parallel(ctx context.Context, n int, fn func(ctx context.Context, i int) error) error {
	if n == 0 {
		return nil
	}
	w := q.workers
	if w > n {
		w = n
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next atomic.Int64
	var once sync.Once
	var first error
	var wg sync.WaitGroup
	for k := 0; k < w; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n || ctx.Err() != nil {
					return
				}
				if err := fn(ctx, i); err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
			}
		}()
	}
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

// ---------------------------------------------------------------- effective permissions

// Row is one cell of an effective-permission answer: every action of the action
// atom on every resource of the resource atom.
type Row struct {
	Action, Resource int32 // atom ids
	Cell             *index.Cell
}

// Stats says how much the index pruned.
type Stats struct {
	ActionAtoms, ActionAtomsInEnvelope int
	ResourceAtoms, Grants              int // Grants: the blocks of cells the sources give
	Cells                              int // cells asked of the memo or the engine
}

// Permissions is the effective permissions of one principal, compressed: one
// row per (action atom, resource atom) that is not a clean deny (§12.3). Expand
// turns it into concrete names.
type Permissions struct {
	PrincipalARN  string
	PrincipalAtom int32
	Rows          []Row
	Stats         Stats
	ix            *index.Index
}

// ExpandedRow is one concrete (action, resource) cell.
type ExpandedRow struct {
	Action, Resource string
	Cell             *index.Cell
}

// Expand lists every concrete cell, sorted by action and then resource. The
// result can be very large; the API layer pages it (§12.3).
func (p *Permissions) Expand() []ExpandedRow {
	var out []ExpandedRow
	for _, r := range p.Rows {
		for _, a := range p.ix.Actions.MemberNames(r.Action) {
			for _, res := range p.ix.Resources.MemberARNs(r.Resource) {
				out = append(out, ExpandedRow{a, res, r.Cell})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}

type pair struct{ a, r int32 }

// pairs lists the (action atom, resource atom) cells that can be anything but a
// clean deny for principal atom pa. With restrict, only those whose action atom
// is in ra or whose resource atom is in rr.
func (q *Querier) pairs(pa int32, restrict bool, ra, rr index.Bitset) []pair {
	ix := q.Idx
	var restrictR []int32
	if restrict {
		restrictR = rr.Members()
	}
	var allRes []int32
	var keys []uint64
	grants := ix.Grants(pa)
	env := ix.Envelope(pa)
	for gi := range grants {
		g := &grants[gi]
		if !g.Free && !g.Actions.Intersects(env) {
			continue
		}
		// The resources of this grant, and of those the ones an action prefix
		// applies to; both are worked out only if an action needs them.
		var named []int32
		haveNamed, namesAll := false, false
		perPrefix := map[string][]int32{}
		listFor := func(prefix string) []int32 {
			if l, ok := perPrefix[prefix]; ok {
				return l
			}
			if !haveNamed {
				named, haveNamed = ix.ReachList(g)
				namesAll = !haveNamed
				haveNamed = true
			}
			app := ix.ApplicableResources(prefix)
			var l []int32
			switch {
			case namesAll && app == nil:
				if allRes == nil {
					allRes = index.FullBitset(len(ix.Resources.Atoms)).Members()
				}
				l = allRes
			case namesAll:
				l = app.Members()
			case app == nil:
				l = named
			default:
				for _, r := range named {
					if app.Has(int(r)) {
						l = append(l, r)
					}
				}
			}
			perPrefix[prefix] = l
			return l
		}
		g.Actions.ForEach(func(a int) {
			if !g.Free && !env.Has(a) {
				return
			}
			if !restrict || ra.Has(a) {
				for _, r := range listFor(ix.ActionPrefix(int32(a))) { // #nosec G115 -- atom ids are non-negative and under 2^31
					keys = append(keys, uint64(a)<<32|uint64(r)) // #nosec G115 -- as above
				}
				return
			}
			for _, r := range restrictR {
				if ix.Reaches(g, r) && ix.Applies(int32(a), r) { // #nosec G115 -- as above
					keys = append(keys, uint64(a)<<32|uint64(r)) // #nosec G115 -- as above
				}
			}
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]pair, 0, len(keys))
	for i, k := range keys {
		if i > 0 && k == keys[i-1] {
			continue
		}
		out = append(out, pair{int32(k >> 32), int32(k & 0xffffffff)}) // #nosec G115 -- both halves were int32 atom ids
	}
	return out
}

// rows asks for every pair and keeps the cells that are not a clean deny.
func (q *Querier) rows(ctx context.Context, pa int32, ps []pair) ([]Row, error) {
	p := q.principalTarget(pa)
	cells := make([]*index.Cell, len(ps))
	const chunk = 256
	chunks := (len(ps) + chunk - 1) / chunk
	err := q.parallel(ctx, chunks, func(ctx context.Context, c int) error {
		for i := c * chunk; i < len(ps) && i < (c+1)*chunk; i++ {
			cell, err := q.cell(ctx, p, q.actionTarget(ps[i].a), q.resourceTarget(ps[i].r))
			if err != nil {
				return err
			}
			cells[i] = cell
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []Row
	for i, c := range cells {
		if c.Kept() {
			out = append(out, Row{Action: ps[i].a, Resource: ps[i].r, Cell: c})
		}
	}
	return out, nil
}

// EffectivePermissions returns what a principal of the snapshot can do, on every
// resource of the universe and for every action of the universe: for each action
// atom in its envelope, the resource atoms it can reach (§12.3).
func (q *Querier) EffectivePermissions(ctx context.Context, principalARN string) (*Permissions, error) {
	pa := q.Idx.PrincipalAtom(principalARN)
	if pa < 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownPrincipal, principalARN)
	}
	ps := q.pairs(pa, false, nil, nil)
	rows, err := q.rows(ctx, pa, ps)
	if err != nil {
		return nil, err
	}
	ix := q.Idx
	return &Permissions{PrincipalARN: principalARN, PrincipalAtom: pa, Rows: rows, ix: ix, Stats: Stats{
		ActionAtoms: len(ix.Actions.Atoms), ActionAtomsInEnvelope: ix.Envelope(pa).Count(),
		ResourceAtoms: len(ix.Resources.Atoms), Grants: len(ix.Grants(pa)), Cells: len(ps),
	}}, nil
}

// ---------------------------------------------------------------- who can

// WhoRow is one principal that can, or may, do the action on the resource.
type WhoRow struct {
	PrincipalARN string
	Atom         int32
	Cell         *index.Cell
}

// Who answers "who can do Y on Z".
type Who struct {
	Action, Resource string
	Rows             []WhoRow // principals of the snapshot, sorted by ARN
	// Anonymous is the decision for an unsigned caller, set when a policy names
	// "*" as a principal.
	Anonymous *index.Cell
	// External lists accounts a resource policy names that are not in the
	// snapshot: "any principal in account N, subject to that account's own
	// policies" (§12.3).
	External []string
	// Candidates and AtomsEvaluated say how much the index pruned.
	Candidates, AtomsEvaluated int
}

// WhoCan returns the principals of the snapshot whose decision for the action on
// the resource is not a clean deny. The candidates are the requester atoms whose
// envelope holds the action atom and that can reach the resource: through an
// identity document with a matching Resource pattern, through a resource policy,
// grant or ACL that names them, or as root (§12.3).
func (q *Querier) WhoCan(ctx context.Context, action, resource string) (*Who, error) {
	ix := q.Idx
	aid, asig := ix.ActionAtom(action)
	rid, rsig, rinfo := ix.ResourceAtom(resource)
	at := target{id: aid, rep: action, sig: asig}
	if aid >= 0 {
		at = q.actionTarget(aid)
	}
	rt := target{id: rid, rep: resource, sig: rsig}
	if rid >= 0 {
		rt = q.resourceTarget(rid)
	}
	if rt.rep == "" {
		rt.rep = "*"
	}

	if !ix.AppliesToAction(action, rinfo) {
		return &Who{Action: action, Resource: resource}, nil // not a cell of the universe
	}
	nP := len(ix.Principals.Atoms)
	cands := index.FullBitset(nP)
	if aid >= 0 && !rinfo.Poisoned {
		cands = ix.PrincipalsWithAction(int(aid))
		if rid >= 0 {
			cands = cands.Clone()
			cands.And(ix.PrincipalsReaching(rid, aid))
		}
	}
	who := &Who{Action: action, Resource: resource, Candidates: cands.Count()}
	if rid >= 0 {
		who.External = ix.ExternalAccounts(rid)
	}

	ids := cands.Members()
	cells := make([]*index.Cell, len(ids))
	err := q.parallel(ctx, len(ids), func(ctx context.Context, i int) error {
		c, err := q.cell(ctx, q.principalTarget(ids[i]), at, rt)
		cells[i] = c
		return err
	})
	if err != nil {
		return nil, err
	}
	who.AtomsEvaluated = len(ids)
	for i, c := range cells {
		if !c.Kept() {
			continue
		}
		for _, arn := range ix.Principals.MemberARNs(ids[i]) {
			who.Rows = append(who.Rows, WhoRow{PrincipalARN: arn, Atom: ids[i], Cell: c})
		}
	}
	sort.Slice(who.Rows, func(i, j int) bool { return who.Rows[i].PrincipalARN < who.Rows[j].PrincipalARN })
	if rid >= 0 && ix.NamesAnyone(rid) {
		c, err := q.cell(ctx, target{id: -1, rep: "anonymous", sig: "anonymous"}, at, rt)
		if err != nil {
			return nil, err
		}
		who.Anonymous = c
	}
	return who, nil
}

// ---------------------------------------------------------------- diff

// ChangeKind classifies a change of one cell (§11.3).
type ChangeKind uint8

// The kinds of change.
const (
	Gained ChangeKind = iota + 1
	Lost
	ConditionalChanged
	FidelityChanged
)

var changeNames = []string{"", "gained", "lost", "conditional_changed", "fidelity_changed"}

func (k ChangeKind) String() string {
	if int(k) < len(changeNames) {
		return changeNames[k]
	}
	return "unknown"
}

func cleanDeny(c *index.Cell) bool {
	return c == nil || (c.Outcome == authz.Deny && c.Fidelity != authz.Unsupported)
}

// Classify says how a cell changed. A nil cell is a clean deny: the requester or
// the resource does not exist, or the engine denies and is sure. ok is false when
// nothing changed.
func Classify(before, after *index.Cell) (kind ChangeKind, ok bool) {
	bd, ad := cleanDeny(before), cleanDeny(after)
	switch {
	case bd && ad:
		return 0, false
	case !bd && !ad && before.Equal(after):
		return 0, false
	case bd:
		if after.Outcome == authz.Allow && after.Fidelity != authz.Unsupported {
			return Gained, true
		}
		if after.Outcome == authz.Conditional {
			return ConditionalChanged, true
		}
		return FidelityChanged, true
	case ad:
		if before.Outcome == authz.Allow && before.Fidelity != authz.Unsupported {
			return Lost, true
		}
		if before.Outcome == authz.Conditional {
			return ConditionalChanged, true
		}
		return FidelityChanged, true
	case before.Outcome == authz.Conditional || after.Outcome == authz.Conditional || before.Outcome != after.Outcome:
		return ConditionalChanged, true
	}
	return FidelityChanged, true
}

// Change is one difference between two snapshots, for a group of principals that
// share their atoms on both sides: every action of the joint action class on
// every resource of the joint resource class.
type Change struct {
	Principals []string
	// Actions and Resources are the concrete names, at most MaxExpand each; the
	// counts are the full sizes.
	Actions, Resources         []string
	ActionCount, ResourceCount int
	Before, After              *index.Cell // nil is a clean deny
	Kind                       ChangeKind
}

// DiffOptions tunes Diff.
type DiffOptions struct {
	// MaxExpand bounds the names listed per change (default 100).
	MaxExpand int
	// Progress, when set, is called after each principal group with the number
	// done and the total, so a caller can stream a partial answer (§12.5).
	Progress func(done, total int)
}

// DiffResult is the difference between two snapshots.
type DiffResult struct {
	Changes []Change
	// Groups is the number of principal groups; Recomputed how many needed their
	// whole effective permissions recomputed (their signature changed), against
	// only the cells touched by a changed action or resource.
	Groups, Recomputed int
	// Global is true when something every decision depends on changed (the
	// organization's switches, the canonical-id map, VPC endpoint policies or the
	// catalog): everything is recomputed.
	Global bool
}

type jointClass struct {
	b, h    int32
	changed bool
	members []int32
}

// Diff computes what changed between base and head for the principals,
// actions and resources of both (§11.3, §12.5): the cells whose decision
// differs. Both queriers must use the same Options. Unchanged cells are never
// evaluated: a cell can differ only if the signature of its requester, action or
// resource differs, and the memo makes the old side of the rest free.
func Diff(ctx context.Context, base, head *Querier, opts DiffOptions) (*DiffResult, error) {
	if base.profile != head.profile {
		return nil, fmt.Errorf("%w: base and head must use the same options", ErrOptions)
	}
	if opts.MaxExpand <= 0 {
		opts.MaxExpand = 100
	}
	b, h, err := sameUniverse(base, head)
	if err != nil {
		return nil, err
	}
	bi, hi := b.Idx, h.Idx
	global := bi.Global != hi.Global
	res := &DiffResult{Global: global}

	// Joint classes of actions and resources.
	cls := func(n int, bAtom, hAtom func(i int) int32, bSig, hSig func(a int32) string) (classes []*jointClass, byB, byH map[int32][]int) {
		idx := map[[2]int32]int{}
		byB, byH = map[int32][]int{}, map[int32][]int{}
		for i := 0; i < n; i++ {
			k := [2]int32{bAtom(i), hAtom(i)}
			ci, ok := idx[k]
			if !ok {
				ci = len(classes)
				idx[k] = ci
				classes = append(classes, &jointClass{b: k[0], h: k[1], changed: global || bSig(k[0]) != hSig(k[1])})
				byB[k[0]] = append(byB[k[0]], ci)
				byH[k[1]] = append(byH[k[1]], ci)
			}
			classes[ci].members = append(classes[ci].members, int32(i))
		}
		return
	}
	aCls, aByB, aByH := cls(len(bi.Actions.Names),
		func(i int) int32 { return bi.Actions.AtomOf[i] }, func(i int) int32 { return hi.Actions.AtomOf[i] },
		func(a int32) string { return bi.Actions.Atoms[a].Sig }, func(a int32) string { return hi.Actions.Atoms[a].Sig })
	rCls, rByB, rByH := cls(len(bi.Resources.ARNs),
		func(i int) int32 { return bi.Resources.AtomOf[i] }, func(i int) int32 { return hi.Resources.AtomOf[i] },
		func(a int32) string { return bi.Resources.Atoms[a].Sig }, func(a int32) string { return hi.Resources.Atoms[a].Sig })

	// The atoms of each side that a changed class touches.
	touched := func(classes []*jointClass, n int, side func(c *jointClass) int32) index.Bitset {
		s := index.NewBitset(n)
		for _, c := range classes {
			if c.changed {
				s.Set(int(side(c)))
			}
		}
		return s
	}
	bA := touched(aCls, len(bi.Actions.Atoms), func(c *jointClass) int32 { return c.b })
	hA := touched(aCls, len(hi.Actions.Atoms), func(c *jointClass) int32 { return c.h })
	bR := touched(rCls, len(bi.Resources.Atoms), func(c *jointClass) int32 { return c.b })
	hR := touched(rCls, len(hi.Resources.Atoms), func(c *jointClass) int32 { return c.h })

	// Principal groups.
	type group struct {
		pb, ph  int32
		changed bool
		members []string
	}
	gidx := map[[2]int32]*group{}
	var groups []*group
	names := map[string]bool{}
	for _, a := range bi.Principals.ARNs {
		names[a] = true
	}
	for _, a := range hi.Principals.ARNs {
		names[a] = true
	}
	all := make([]string, 0, len(names))
	for a := range names {
		all = append(all, a)
	}
	sort.Strings(all)
	for _, arn := range all {
		pb, ph := bi.PrincipalAtom(arn), hi.PrincipalAtom(arn)
		k := [2]int32{pb, ph}
		g := gidx[k]
		if g == nil {
			g = &group{pb: pb, ph: ph}
			g.changed = global || pb < 0 || ph < 0 || bi.Principals.Atoms[pb].Sig != hi.Principals.Atoms[ph].Sig
			gidx[k] = g
			groups = append(groups, g)
		}
		g.members = append(g.members, arn)
	}
	res.Groups = len(groups)

	// The groups run in parallel, each evaluating its own cells in turn.
	bs, hs := *b, *h
	bs.workers, hs.workers = 1, 1
	// For a requester whose signature is unchanged, only those that can reach a
	// changed resource, or hold a changed action in their envelope, can differ.
	// The inverted indexes name them, so the rest are never looked at.
	affected := func(ix *index.Index, acts, ress index.Bitset) index.Bitset {
		if acts.Count() > 256 || ress.Count() > 64 {
			return nil // too many to look up one by one: fall back to asking each group
		}
		aff := index.NewBitset(len(ix.Principals.Atoms))
		ress.ForEach(func(r int) { aff.Or(ix.PrincipalsReaching(int32(r), -1)) }) // #nosec G115 -- atom ids are under 2^31
		acts.ForEach(func(a int) { aff.Or(ix.PrincipalsWithAction(a)) })
		return aff
	}
	bAff, hAff := affected(bi, bA, bR), affected(hi, hA, hR)
	results := make([][]Change, len(groups))
	var done atomic.Int64
	var recomputed atomic.Int64
	err = b.parallel(ctx, len(groups), func(ctx context.Context, gi int) error {
		g := groups[gi]
		if g.changed {
			recomputed.Add(1)
		}
		// Both sides are asked or neither: a cell is only compared when each side
		// has been evaluated for it.
		if !g.changed && bAff != nil && hAff != nil && !bAff.Has(int(g.pb)) && !hAff.Has(int(g.ph)) {
			done.Add(1)
			return nil
		}
		side := func(q *Querier, pa int32, restrictA, restrictR index.Bitset, aBy, rBy map[int32][]int) (map[[2]int]*index.Cell, error) {
			out := map[[2]int]*index.Cell{}
			if pa < 0 {
				return out, nil
			}
			// A requester whose signature is unchanged can differ only on a
			// changed action or a changed resource. With no changed resource and
			// no changed action in its envelope there is nothing to ask.
			if !g.changed && restrictR.Count() == 0 && !q.Idx.Envelope(pa).Intersects(restrictA) {
				return out, nil
			}
			ps := q.pairs(pa, !g.changed, restrictA, restrictR)
			rows, err := q.rows(ctx, pa, ps)
			if err != nil {
				return nil, err
			}
			joint(rows, out, g.changed, aCls, rCls, aBy, rBy)
			return out, nil
		}
		cb, err := side(&bs, g.pb, bA, bR, aByB, rByB)
		if err != nil {
			return err
		}
		ch, err := side(&hs, g.ph, hA, hR, aByH, rByH)
		if err != nil {
			return err
		}
		keys := make([][2]int, 0, len(cb)+len(ch))
		for k := range cb {
			keys = append(keys, k)
		}
		for k := range ch {
			if _, dup := cb[k]; !dup {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] != keys[j][0] {
				return keys[i][0] < keys[j][0]
			}
			return keys[i][1] < keys[j][1]
		})
		var changes []Change
		for _, k := range keys {
			before, after := cb[k], ch[k]
			kind, ok := Classify(before, after)
			if !ok {
				continue
			}
			ac, rc := aCls[k[0]], rCls[k[1]]
			changes = append(changes, Change{Principals: g.members, Before: before, After: after, Kind: kind,
				Actions: names2(bi.Actions.Names, ac.members, opts.MaxExpand), ActionCount: len(ac.members),
				Resources: names2(bi.Resources.ARNs, rc.members, opts.MaxExpand), ResourceCount: len(rc.members)})
		}
		results[gi] = changes
		n := int(done.Add(1))
		if opts.Progress != nil {
			opts.Progress(n, len(groups))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, c := range results {
		res.Changes = append(res.Changes, c...)
	}
	res.Recomputed = int(recomputed.Load())
	sort.Slice(res.Changes, func(i, j int) bool {
		x, y := res.Changes[i], res.Changes[j]
		if x.Principals[0] != y.Principals[0] {
			return x.Principals[0] < y.Principals[0]
		}
		if x.Actions[0] != y.Actions[0] {
			return x.Actions[0] < y.Actions[0]
		}
		return x.Resources[0] < y.Resources[0]
	})
	return res, nil
}

// joint files the rows of one side under the joint classes that their atoms
// belong to. Only cells of changed classes are kept when the principal group is
// restricted, since the other side was not evaluated for the rest.
func joint(rows []Row, out map[[2]int]*index.Cell, full bool, aCls, rCls []*jointClass, aBy, rBy map[int32][]int) {
	for _, row := range rows {
		for _, ai := range aBy[row.Action] {
			for _, ri := range rBy[row.Resource] {
				if !full && !aCls[ai].changed && !rCls[ri].changed {
					continue
				}
				out[[2]int{ai, ri}] = row.Cell
			}
		}
	}
}

func names2(all []string, idx []int32, max int) []string {
	n := len(idx)
	if n > max {
		n = max
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = all[idx[i]]
	}
	return out
}

// sameUniverse makes both queriers cover the same actions and resources, by
// refining the index that lacks some (§12.5). A resource only one snapshot
// names is a resource whose atom the other snapshot has to compute.
func sameUniverse(base, head *Querier) (*Querier, *Querier, error) {
	bi, hi := base.Idx, head.Idx
	// Universes are sorted, so equal ones are equal slices; at the target scale
	// this saves building a union of millions of ARNs.
	if slices.Equal(bi.Actions.Names, hi.Actions.Names) && slices.Equal(bi.Resources.ARNs, hi.Resources.ARNs) {
		return base, head, nil
	}
	acts := union(bi.Actions.Names, hi.Actions.Names)
	ress := union(bi.Resources.ARNs, hi.Resources.ARNs)
	fix := func(q *Querier) (*Querier, error) {
		if len(q.Idx.Actions.Names) == len(acts) && len(q.Idx.Resources.ARNs) == len(ress) {
			return q, nil
		}
		cfg := q.Idx.Config()
		cfg.Actions, cfg.Resources = acts, ress
		ix, err := q.Idx.Refine(q.Idx.Snap, cfg)
		if err != nil {
			return nil, err
		}
		return &Querier{Idx: ix, Memo: q.Memo, opts: q.opts, profile: q.profile, workers: q.workers}, nil
	}
	b, err := fix(base)
	if err != nil {
		return nil, nil, err
	}
	h, err := fix(head)
	return b, h, err
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
