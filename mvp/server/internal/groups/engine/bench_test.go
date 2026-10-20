package engine_test

import (
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A benchmark tenant shaped like the design's reference tenant (§6.7: 150,000
// groups, 600,000 identities, 3,000,000 direct memberships, dependency depth
// up to 12, a reference group of 45,000 used by 400 policy groups), at a
// percentage of its size: TESSERA_GROUPS_BENCH_SCALE, default 10. Building it
// takes minutes at 10%, so it is built once per `go test -bench` run.
//
//	go test -run '^$' -bench . -benchtime 1x ./internal/groups/engine

type benchTenant struct {
	x       *harness
	ident   []int64
	tail    store.GroupID   // the bottom of a chain of 12 nested groups
	chain   []store.GroupID // top first
	ref     store.GroupID   // the "ref:student:enrolled" group
	target  store.GroupID   // used by the policy groups
	members store.GroupID   // a group with some members, for hasMember
	scale   float64
	stats   string
}

var (
	benchOnce sync.Once
	bench     *benchTenant
)

func benchScale() float64 {
	if v, err := strconv.ParseFloat(os.Getenv("TESSERA_GROUPS_BENCH_SCALE"), 64); err == nil && v > 0 {
		return v / 100
	}
	return 0.10
}

func buildBench(b *testing.B) *benchTenant {
	benchOnce.Do(func() {
		start := time.Now()
		s := benchScale()
		nG, nI, nD := int(150000*s), int(600000*s), int(3000000*s)
		nRef, nPolicy := int(45000*s), max(1, int(400*s))
		eng := engine.New(1 << 40) // build inline, whatever the size
		x := newHarness(b, 0, 0, eng)
		t := &benchTenant{x: x, scale: s}
		rng := rand.New(rand.NewSource(1))
		var groups [4][]store.GroupID // levels 0..3
		x.must(func(e model.Env) error {
			root, err := e.EnsureRoot()
			if err != nil {
				return err
			}
			for i := 0; i < nI; i++ {
				id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: "u" + strconv.Itoa(i), Name: "User " + strconv.Itoa(i),
					Type: "person", Status: "active", CreatedAt: t0})
				if err != nil {
					return err
				}
				t.ident = append(t.ident, id)
			}
			mk := func(name string) (store.GroupID, error) {
				g := &store.NativeGroup{FolderID: root.ID, Extension: name, DisplayExtension: name, Name: name, DisplayName: name,
					CreatedAt: t0}
				return g.ID, e.Tx.InsertGrpGroup(g)
			}
			share := [4]float64{0.90, 0.06, 0.03, 0.01}
			for lv := range groups {
				for i := 0; i < int(float64(nG)*share[lv]); i++ {
					id, err := mk(fmt.Sprintf("l%d_%d", lv, i))
					if err != nil {
						return err
					}
					groups[lv] = append(groups[lv], id)
				}
			}
			return nil
		})
		list := store.MembersListID(tid)
		// direct identity rows on level 0, nesting above it
		x.must(func(e model.Env) error {
			if err := engine.Touch(e.Tx, t0); err != nil {
				return err
			}
			per := max(1, nD/len(groups[0]))
			for _, g := range groups[0] {
				seen := map[int64]bool{}
				for len(seen) < min(per, len(t.ident)) {
					id := t.ident[rng.Intn(len(t.ident))]
					if seen[id] {
						continue
					}
					seen[id] = true
					if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: g, ListID: list, MemberType: store.MemberIdentity,
						MemberIdentity: &id, Source: "bench", CreatedAt: t0}); err != nil {
						return err
					}
				}
			}
			fan := [4]int{0, 10, 5, 5}
			for lv := 1; lv < 4; lv++ {
				for _, g := range groups[lv] {
					for _, k := range rng.Perm(len(groups[lv-1]))[:min(fan[lv], len(groups[lv-1]))] {
						child := groups[lv-1][k]
						if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: g, ListID: list, MemberType: store.MemberGroup,
							MemberGroup: &child, Source: "bench", CreatedAt: t0}); err != nil {
							return err
						}
						if err := eng.AddEdge(e.Tx, store.GrpDep{Parent: g, Child: child, Kind: store.DepNest, List: list}); err != nil {
							return err
						}
					}
				}
			}
			// a chain of 12 nested groups (depth up to 12) for the single-change numbers
			for i := 0; i < 12; i++ {
				g := &store.NativeGroup{FolderID: mustRoot(e), Extension: fmt.Sprint("chain", i), DisplayExtension: "c", Name: fmt.Sprint("chain", i),
					DisplayName: "c", CreatedAt: t0}
				if err := e.Tx.InsertGrpGroup(g); err != nil {
					return err
				}
				t.chain = append(t.chain, g.ID)
			}
			slices.Reverse(t.chain) // chain[0] is the top
			for i := 0; i+1 < len(t.chain); i++ {
				child := t.chain[i+1]
				if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: t.chain[i], ListID: list, MemberType: store.MemberGroup,
					MemberGroup: &child, Source: "bench", CreatedAt: t0}); err != nil {
					return err
				}
				if err := eng.AddEdge(e.Tx, store.GrpDep{Parent: t.chain[i], Child: child, Kind: store.DepNest, List: list}); err != nil {
					return err
				}
			}
			t.tail = t.chain[len(t.chain)-1]
			// the reference group and the policy groups that use "target"
			mkg := func(name string) (store.GroupID, error) {
				g := &store.NativeGroup{FolderID: mustRoot(e), Extension: name, DisplayExtension: name, Name: name, DisplayName: name, CreatedAt: t0}
				return g.ID, e.Tx.InsertGrpGroup(g)
			}
			var err error
			if t.ref, err = mkg("ref_student_enrolled"); err != nil {
				return err
			}
			if t.target, err = mkg("target"); err != nil {
				return err
			}
			for _, id := range t.ident[:min(nRef, len(t.ident))] {
				if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: t.ref, ListID: list, MemberType: store.MemberIdentity,
					MemberIdentity: &id, Source: "bench", CreatedAt: t0}); err != nil {
					return err
				}
			}
			for i := 0; i < nPolicy; i++ {
				pg := &store.NativeGroup{FolderID: mustRoot(e), Extension: fmt.Sprint("policy", i), DisplayExtension: "p", Name: fmt.Sprint("policy", i),
					DisplayName: "p", Definition: store.DefinitionComposite, CompositeOp: ptr(store.CompUnion), CreatedAt: t0}
				if err := e.Tx.InsertGrpGroup(pg); err != nil {
					return err
				}
				if err := eng.SetFactors(e.Tx, t0, pg.ID, []store.GroupID{t.target, groups[0][rng.Intn(len(groups[0]))]}); err != nil {
					return err
				}
			}
			t.members = groups[0][0]
			return nil
		})
		// materialize: recomputing the leaves carries every change up through the graph
		x.must(func(e model.Env) error {
			todo := append(slices.Clone(groups[0]), t.ref)
			for _, g := range todo {
				if _, err := eng.RecomputeGroup(e.Tx, t0, g); err != nil {
					return err
				}
			}
			return nil
		})
		x.eng = engine.New(0) // from here on, the production budget
		var eff int64
		x.read(func(e model.Env) error {
			for _, lv := range groups {
				for _, g := range lv {
					n, _ := e.Tx.GrpEffectiveCount(g, list)
					eff += int64(n)
				}
			}
			return nil
		})
		t.stats = fmt.Sprintf("%d%% of the reference tenant: %d groups, %d identities, %d direct rows, %d effective rows, %d policy groups; built in %s",
			int(s*100+0.5), nG, nI, nD, eff, nPolicy, time.Since(start).Round(time.Second))
		bench = t
	})
	if bench == nil {
		b.Skip("the benchmark tenant failed to build")
	}
	b.Log(bench.stats)
	return bench
}

func mustRoot(e model.Env) store.FolderID {
	r, err := e.Tx.GrpRootFolder()
	if err != nil {
		panic(err)
	}
	return r.ID
}

func ptr[T any](v T) *T { return &v }

func pct(ds []time.Duration, p float64) float64 {
	slices.Sort(ds)
	return float64(ds[int(float64(len(ds)-1)*p)]) / float64(time.Millisecond)
}

// BenchmarkEngine_SingleChange: one direct add and one remove at the bottom
// of a chain of 12 groups, effective state visible on return (target p95 <= 75 ms).
func BenchmarkEngine_SingleChange(b *testing.B) {
	t := buildBench(b)
	var lat []time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := t.ident[i%len(t.ident)]
		for _, add := range []bool{true, false} {
			start := time.Now()
			t.x.must(func(e model.Env) error {
				if add {
					_, err := e.AddMember(t.tail, model.MemberInput{Identity: &id})
					return err
				}
				_, err := e.RemoveMember(t.tail, strconv.FormatInt(id, 10))
				return err
			})
			lat = append(lat, time.Since(start))
		}
	}
	b.StopTimer()
	b.ReportMetric(pct(lat, 0.95), "p95-ms")
}

// BenchmarkEngine_HasMember: IsMember on materialized rows (target p99 <= 5 ms).
func BenchmarkEngine_HasMember(b *testing.B) {
	t := buildBench(b)
	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := t.ident[i%len(t.ident)]
		start := time.Now()
		t.x.read(func(e model.Env) error { _, err := e.IsMember(t.members, id); return err })
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	b.ReportMetric(pct(lat, 0.99), "p99-ms")
}

// BenchmarkEngine_NestReferenceGroup: the reference group nested into the group
// every policy group uses, with the budget raised so it runs in one call
// (target: 45,000 members and 400 policy groups in <= 5 minutes).
func BenchmarkEngine_NestReferenceGroup(b *testing.B) {
	t := buildBench(b)
	t.x.eng = engine.New(1 << 40)
	defer func() { t.x.eng = engine.New(0) }()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		t.x.must(func(e model.Env) error {
			_, err := e.AddMember(t.target, model.MemberInput{Group: t.ref})
			return err
		})
		b.ReportMetric(time.Since(start).Seconds(), "s/nest")
		b.StopTimer()
		t.x.must(func(e model.Env) error { _, err := e.RemoveMember(t.target, string(t.ref)); return err })
		b.StartTimer()
	}
}
