package query_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func config(w *awstest.World) index.Config {
	c := index.Config{Catalog: awstest.Catalog{}, Actions: awstest.Actions(), Resources: w.Extra}
	if w.SameService {
		c.Applies = awstest.SameServiceRule
	}
	return c
}

// inUniverse says whether the cell is one the index answers for (Config.Applies).
func inUniverse(b *built, action, resource string) bool {
	apply := b.ix.Config().Applies
	if apply == nil || resource == "*" {
		return true
	}
	parts := strings.SplitN(resource, ":", 4)
	if len(parts) < 4 || parts[0] != "arn" {
		return true
	}
	prefix, _, _ := strings.Cut(strings.ToLower(action), ":")
	return apply(prefix, parts[2])
}

// optionsFor picks the request context of a seed: symbolic with the default
// profile, symbolic with no profile, or concrete with supplied keys.
func optionsFor(seed uint64) query.Options {
	switch seed % 3 {
	case 0:
		return query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(fixedNow), Workers: 3}
	case 1:
		return query.Options{Mode: eval.Symbolic, Workers: 2}
	}
	return query.Options{Mode: eval.Concrete, Workers: 1, Context: map[string]eval.ContextValue{
		"aws:SecureTransport": eval.PresentValues("true"), "aws:SourceIp": eval.PresentValues("10.1.2.3"),
		"aws:CurrentTime": eval.PresentValues("2026-10-01T12:00:00Z"),
	}}
}

type built struct {
	w    *awstest.World
	snap *model.Snapshot
	ix   *index.Index
	q    *query.Querier
}

func buildWorld(t testing.TB, w *awstest.World, opts query.Options, memo *index.Memo) *built {
	t.Helper()
	snap, err := w.Build()
	if err != nil {
		t.Fatal(err)
	}
	ix, err := index.Build(snap, config(w))
	if err != nil {
		t.Fatal(err)
	}
	q, err := query.New(ix, memo, opts)
	if err != nil {
		t.Fatal(err)
	}
	return &built{w, snap, ix, q}
}

// brute asks the engine for a cell directly, the way the index never has to.
func brute(t testing.TB, snap *model.Snapshot, opts query.Options, principal, action, resource string) *index.Cell {
	t.Helper()
	if resource == "*" {
		resource = ""
	}
	d, err := eval.Evaluate(context.Background(), snap, awstest.Catalog{}, &eval.EvaluationRequest{
		PrincipalARN: principal, Action: action, ResourceARN: resource, Mode: opts.Mode, Profile: opts.Profile, Context: opts.Context,
	}, eval.Options{Fast: true})
	if err != nil {
		t.Fatalf("brute force %s %s %s: %v", principal, action, resource, err)
	}
	return index.NewCell(d)
}

func seedCount(def int) int {
	if v, err := strconv.Atoi(os.Getenv("TESSERA_EQUIV_SEEDS")); err == nil && v > 0 {
		return v
	}
	if testing.Short() {
		return def / 4
	}
	return def
}

// checkPermissions compares EffectivePermissions with brute force over every
// action and resource of the universe.
func checkPermissions(t *testing.T, b *built, opts query.Options, principal string) (kept, cells int) {
	t.Helper()
	perms, err := b.q.EffectivePermissions(context.Background(), principal)
	if err != nil {
		t.Fatalf("%s: %v", principal, err)
	}
	got := map[[2]string]*index.Cell{}
	for _, r := range perms.Expand() {
		got[[2]string{r.Action, r.Resource}] = r.Cell
	}
	n := 0
	kept, cells = len(got), len(b.ix.Actions.Names)*len(b.ix.Resources.ARNs)
	for _, a := range b.ix.Actions.Names {
		for _, r := range b.ix.Resources.ARNs {
			if !inUniverse(b, a, r) {
				if got[[2]string{a, r}] != nil {
					t.Errorf("%s %s on %s is outside the universe but listed", principal, a, r)
				}
				continue
			}
			want := brute(t, b.snap, opts, principal, a, r)
			g := got[[2]string{a, r}]
			switch {
			case want.Kept() && g == nil:
				t.Errorf("seed world: %s %s on %s: atoms say deny, engine says %s", principal, a, r, want)
				n++
			case !want.Kept() && g != nil:
				t.Errorf("%s %s on %s: atoms say %s, engine says %s", principal, a, r, g, want)
				n++
			case want.Kept() && !g.Equal(want):
				t.Errorf("%s %s on %s: atoms say %s, engine says %s", principal, a, r, g, want)
				n++
			}
			if n > 5 {
				t.Fatalf("too many mismatches for %s", principal)
			}
		}
	}
	return kept, cells
}

// TestAtomsEqualBruteForce is the equivalence property of §15 PR-10: the cells
// the atoms give equal what the engine says for every concrete cell, on small
// random tenants. The design names the rapid library for this; the module does
// not need it, so the generator is a seeded PCG (awstest.NewWorld) over many
// fixed seeds, and FuzzAtomsEqualBruteForce explores further seeds.
func TestAtomsEqualBruteForce(t *testing.T) {
	n := seedCount(40)
	for seed := uint64(1); seed <= uint64(n); seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			t.Parallel()
			checkSeed(t, seed)
		})
	}
}

func checkSeed(t *testing.T, seed uint64) {
	opts := optionsFor(seed)
	b := buildWorld(t, awstest.NewWorld(seed), opts, nil)
	var kept, cells int
	for _, p := range b.ix.Principals.ARNs {
		k, c := checkPermissions(t, b, opts, p)
		kept, cells = kept+k, cells+c
	}
	t.Logf("%d principals (%d atoms), %d of %d cells are not a clean deny", len(b.ix.Principals.ARNs), len(b.ix.Principals.Atoms), kept, cells)
	if kept == 0 {
		t.Errorf("no principal can do anything in this world; the comparison is vacuous")
	}
	checkWho(t, b, opts, seed)
}

func checkWho(t *testing.T, b *built, opts query.Options, seed uint64) {
	t.Helper()
	g := awstest.NewRand(seed ^ 0xabcdef)
	resources := append(append([]string(nil), b.ix.Resources.ARNs...), "arn:aws:s3:::bkt-a-1/unseen/key", "arn:aws:sqs:us-east-1:111111111111:other")
	actions := append(append([]string(nil), b.ix.Actions.Names...), "s3:GetObjectTagging", "ec2:Unheard")
	for i := 0; i < 8; i++ {
		a, r := actions[g.Intn(len(actions))], resources[g.Intn(len(resources))]
		who, err := b.q.WhoCan(context.Background(), a, r)
		if err != nil {
			t.Fatalf("WhoCan(%s, %s): %v", a, r, err)
		}
		got := map[string]*index.Cell{}
		for _, row := range who.Rows {
			got[row.PrincipalARN] = row.Cell
		}
		for _, p := range b.ix.Principals.ARNs {
			if !inUniverse(b, a, r) {
				if got[p] != nil {
					t.Errorf("WhoCan(%s, %s) lists %s outside the universe", a, r, p)
				}
				continue
			}
			want := brute(t, b.snap, opts, p, a, r)
			switch {
			case want.Kept() && got[p] == nil:
				t.Errorf("WhoCan(%s, %s) misses %s: engine says %s", a, r, p, want)
			case !want.Kept() && got[p] != nil:
				t.Errorf("WhoCan(%s, %s) lists %s as %s; engine says %s", a, r, p, got[p], want)
			case want.Kept() && !got[p].Equal(want):
				t.Errorf("WhoCan(%s, %s): %s is %s; engine says %s", a, r, p, got[p], want)
			}
		}
		if who.Candidates > len(b.ix.Principals.Atoms) {
			t.Errorf("more candidates than atoms")
		}
	}
}

func FuzzAtomsEqualBruteForce(f *testing.F) {
	for _, s := range []uint64{1, 2, 3, 77, 1 << 40} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed uint64) { checkSeed(t, seed) })
}

// show renders a cell for comparison; a missing cell and an exact deny are the
// same thing to a diff.
func show(c *index.Cell) string {
	if c == nil || (c.Outcome == authz.Deny && c.Fidelity != authz.Unsupported) {
		return "deny"
	}
	return c.String()
}

// expectedDiff is the brute-force diff of two worlds.
func expectedDiff(t *testing.T, base, head *built, opts query.Options) map[string]string {
	t.Helper()
	principals := map[string]bool{}
	for _, p := range base.ix.Principals.ARNs {
		principals[p] = true
	}
	for _, p := range head.ix.Principals.ARNs {
		principals[p] = true
	}
	resources := map[string]bool{}
	for _, r := range base.ix.Resources.ARNs {
		resources[r] = true
	}
	for _, r := range head.ix.Resources.ARNs {
		resources[r] = true
	}
	has := func(b *built, p string) bool { return b.ix.PrincipalAtom(p) >= 0 }
	out := map[string]string{}
	for p := range principals {
		for _, a := range base.ix.Actions.Names {
			for r := range resources {
				if !inUniverse(head, a, r) || !inUniverse(base, a, r) {
					continue
				}
				var before, after *index.Cell
				if has(base, p) {
					before = brute(t, base.snap, opts, p, a, r)
				}
				if has(head, p) {
					after = brute(t, head.snap, opts, p, a, r)
				}
				if kind, ok := query.Classify(before, after); ok {
					out[p+"|"+a+"|"+r] = kind.String() + "|" + show(before) + "|" + show(after)
				}
			}
		}
	}
	return out
}

func checkDiff(t *testing.T, seed uint64) {
	opts := optionsFor(seed)
	w := awstest.NewWorld(seed)
	w2 := w.Clone()
	g := awstest.NewRand(seed * 31)
	var what []string
	for i := 0; i <= g.Intn(3); i++ {
		what = append(what, w2.Mutate(g))
	}
	memo := index.NewMemo(1 << 18)
	base := buildWorld(t, w, opts, memo)
	head := buildWorld(t, w2, opts, memo)
	res, err := query.Diff(context.Background(), base.q, head.q, query.DiffOptions{MaxExpand: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range res.Changes {
		for _, p := range c.Principals {
			for _, a := range c.Actions {
				for _, r := range c.Resources {
					k := p + "|" + a + "|" + r
					if _, dup := got[k]; dup {
						t.Errorf("%v: cell %s reported twice", what, k)
					}
					got[k] = c.Kind.String() + "|" + show(c.Before) + "|" + show(c.After)
				}
			}
		}
	}
	want := expectedDiff(t, base, head, opts)
	bad := 0
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v: %s: diff says %q, engine says %q", what, k, got[k], v)
			if bad++; bad > 5 {
				return
			}
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%v: %s: diff reports %q, engine sees no change", what, k, v)
			if bad++; bad > 5 {
				return
			}
		}
	}
}

func TestDiffEqualsBruteForce(t *testing.T) {
	n := seedCount(24)
	for seed := uint64(1); seed <= uint64(n); seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			t.Parallel()
			checkDiff(t, seed+1000)
		})
	}
}

// A change that touches nothing gives an empty diff and recomputes nothing: the
// memo makes the old side free.
func TestDiffOfIdenticalSnapshotsIsEmpty(t *testing.T) {
	opts := optionsFor(0)
	w := awstest.NewWorld(5)
	memo := index.NewMemo(1 << 18)
	base, head := buildWorld(t, w, opts, memo), buildWorld(t, w.Clone(), opts, memo)
	res, err := query.Diff(context.Background(), base.q, head.q, query.DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 0 || res.Recomputed != 0 || res.Global {
		t.Fatalf("identical snapshots: %d changes, %d recomputed, global %v", len(res.Changes), res.Recomputed, res.Global)
	}
}

// Refining an index with a new snapshot gives the same atoms as building it.
func TestRefineEqualsBuild(t *testing.T) {
	n := seedCount(24)
	for seed := uint64(1); seed <= uint64(n); seed++ {
		w := awstest.NewWorld(seed)
		w2 := w.Clone()
		g := awstest.NewRand(seed * 7)
		var what []string
		for i := 0; i <= g.Intn(3); i++ {
			what = append(what, w2.Mutate(g))
		}
		base := buildWorld(t, w, optionsFor(0), nil)
		snap2, err := w2.Build()
		if err != nil {
			t.Fatal(err)
		}
		refined, err := base.ix.Refine(snap2, config(w2))
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := index.Build(snap2, config(w2))
		if err != nil {
			t.Fatal(err)
		}
		sameSigs(t, fmt.Sprintf("seed %d %v", seed, what), refined, fresh)
		if st := refined.ActionStats; st.ItemsReused == 0 {
			t.Errorf("seed %d: refinement reused nothing: %+v", seed, st)
		}
	}
}

// sameSigs checks that two indexes give every item the same atom signature and
// that items share an atom in one exactly when they do in the other.
func sameSigs(t *testing.T, name string, a, b *index.Index) {
	t.Helper()
	check := func(kind string, n int, atomA, atomB func(i int) int32, sigA, sigB func(id int32) string, nameOf func(i int) string) {
		sa, sb := map[int32]int32{}, map[int32]int32{}
		for i := 0; i < n; i++ {
			x, y := atomA(i), atomB(i)
			if sigA(x) != sigB(y) {
				t.Errorf("%s: %s %s: signature differs between refine and build", name, kind, nameOf(i))
				return
			}
			if prev, ok := sa[x]; ok && prev != y {
				t.Errorf("%s: %s %s: atoms split differently", name, kind, nameOf(i))
				return
			}
			if prev, ok := sb[y]; ok && prev != x {
				t.Errorf("%s: %s %s: atoms merged differently", name, kind, nameOf(i))
				return
			}
			sa[x], sb[y] = y, x
		}
	}
	if len(a.Actions.Names) != len(b.Actions.Names) || len(a.Resources.ARNs) != len(b.Resources.ARNs) || len(a.Principals.ARNs) != len(b.Principals.ARNs) {
		t.Fatalf("%s: universes differ", name)
	}
	check("action", len(a.Actions.Names), func(i int) int32 { return a.Actions.AtomOf[i] }, func(i int) int32 { return b.Actions.AtomOf[i] },
		func(id int32) string { return a.Actions.Atoms[id].Sig }, func(id int32) string { return b.Actions.Atoms[id].Sig },
		func(i int) string { return a.Actions.Names[i] })
	check("resource", len(a.Resources.ARNs), func(i int) int32 { return a.Resources.AtomOf[i] }, func(i int) int32 { return b.Resources.AtomOf[i] },
		func(id int32) string { return a.Resources.Atoms[id].Sig }, func(id int32) string { return b.Resources.Atoms[id].Sig },
		func(i int) string { return a.Resources.ARNs[i] })
	check("principal", len(a.Principals.ARNs), func(i int) int32 { return a.Principals.AtomOf[i] }, func(i int) int32 { return b.Principals.AtomOf[i] },
		func(id int32) string { return a.Principals.Atoms[id].Sig }, func(id int32) string { return b.Principals.Atoms[id].Sig },
		func(i int) string { return a.Principals.ARNs[i] })
	if a.Global != b.Global {
		t.Errorf("%s: global signature differs", name)
	}
}

// The same inputs give the same answers whatever the worker count and run.
func TestAnswersAreDeterministic(t *testing.T) {
	w := awstest.NewWorld(9)
	var first []string
	for _, workers := range []int{1, 4, 1} {
		opts := optionsFor(0)
		opts.Workers = workers
		b := buildWorld(t, w, opts, nil)
		var lines []string
		for _, p := range b.ix.Principals.ARNs {
			perms, err := b.q.EffectivePermissions(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range perms.Rows {
				lines = append(lines, fmt.Sprintf("%s %d %d %s", p, r.Action, r.Resource, r.Cell))
			}
		}
		if first == nil {
			first = lines
		} else if strings.Join(first, "\n") != strings.Join(lines, "\n") {
			t.Fatalf("workers=%d: answers differ", workers)
		}
	}
	if len(first) == 0 {
		t.Fatal("the world allows nothing; the test proves nothing")
	}
}

func TestAtomsCompress(t *testing.T) {
	w := awstest.NewWorld(3)
	for i := 0; i < 100; i++ { // queues nothing names: one atom per account and type
		w.Extra = append(w.Extra, fmt.Sprintf("arn:aws:sqs:us-east-1:111111111111:bulk-%d", i))
	}
	b := buildWorld(t, w, optionsFor(0), nil)
	c := b.ix.Counts()
	if c.ActionAtoms >= c.Actions || c.ResourceAtoms >= c.Resources-90 {
		t.Fatalf("atoms do not compress: %+v", c)
	}
	// Every member of an atom is listed once and maps back to it.
	seen := 0
	for _, at := range b.ix.Actions.Atoms {
		for _, m := range at.Members {
			if b.ix.Actions.AtomOf[m] != at.ID {
				t.Fatalf("action %s is listed under atom %d but maps to %d", b.ix.Actions.Names[m], at.ID, b.ix.Actions.AtomOf[m])
			}
			seen++
		}
	}
	if seen != c.Actions {
		t.Fatalf("%d members for %d actions", seen, c.Actions)
	}
}

func TestPointDecisionHasTrace(t *testing.T) {
	b := buildWorld(t, awstest.NewWorld(3), optionsFor(1), nil)
	d, err := b.q.Can(context.Background(), b.ix.Principals.ARNs[0], "s3:GetObject", "arn:aws:s3:::bkt-a-1/obj1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Steps) == 0 || d.EngineVersion == "" || d.SnapshotID != b.snap.ID {
		t.Fatalf("a point decision carries its trace and versions: %+v", d)
	}
}

func TestQueryErrors(t *testing.T) {
	b := buildWorld(t, awstest.NewWorld(3), optionsFor(1), nil)
	if _, err := b.q.EffectivePermissions(context.Background(), "arn:aws:iam::111111111111:user/ghost"); err == nil {
		t.Error("an unknown principal must be an error")
	}
	for _, key := range []string{"aws:PrincipalArn", "aws:ResourceAccount", "aws:SourceVpce", "aws:username"} {
		_, err := query.New(b.ix, nil, query.Options{Context: map[string]eval.ContextValue{key: eval.PresentValues("x")}})
		if err == nil {
			t.Errorf("pinning %s must be refused: atoms stand for many requesters and resources", key)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.q.EffectivePermissions(ctx, b.ix.Principals.ARNs[0]); err == nil {
		if _, err := b.q.WhoCan(ctx, "s3:GetObject", "arn:aws:s3:::bkt-a-1"); err == nil {
			t.Error("a cancelled context must stop the query")
		}
	}
	other, _ := query.New(b.ix, nil, optionsFor(0))
	if _, err := query.Diff(context.Background(), b.q, other, query.DiffOptions{}); err == nil {
		t.Error("diffing under different options must be refused")
	}
}

// A policy that cannot be read is never skipped: every cell it can touch is
// UNSUPPORTED (§3.3), and the index must not prune it away.
func TestUnparseablePolicyIsNeverPruned(t *testing.T) {
	for seed := uint64(1); seed < 200; seed++ {
		w := awstest.NewWorld(seed)
		hasBroken := false
		for _, d := range w.Docs {
			hasBroken = hasBroken || strings.HasSuffix(d.Src, "policy/broken")
		}
		if !hasBroken {
			continue
		}
		b := buildWorld(t, w, optionsFor(0), nil)
		found := false
		for _, p := range b.snap.Principals {
			for _, id := range p.IdentityPolicyIDs {
				if d := b.snap.Policies[id]; d != nil && d.Unparseable != "" {
					perms, err := b.q.EffectivePermissions(context.Background(), p.ARN)
					if err != nil {
						continue
					}
					for _, r := range perms.Rows {
						found = found || r.Cell.Fidelity == authz.Unsupported
					}
					if !found {
						t.Fatalf("seed %d: %s has an unparseable policy but no UNSUPPORTED cell", seed, p.ARN)
					}
				}
			}
		}
		if found {
			return
		}
	}
	t.Skip("no seed attached the broken policy to a requester the engine can answer for")
}

func TestPrunesSomething(t *testing.T) {
	b := buildWorld(t, awstest.NewWorld(4), optionsFor(0), nil)
	pruned := false
	for _, p := range b.ix.Principals.ARNs {
		perms, err := b.q.EffectivePermissions(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		s := perms.Stats
		if s.Cells < s.ActionAtoms*s.ResourceAtoms {
			pruned = true
		}
	}
	if !pruned {
		t.Fatal("no principal was pruned: the envelope and candidate index do nothing")
	}
}
