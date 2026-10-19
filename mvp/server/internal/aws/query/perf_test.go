//go:build slow

package query_test

import (
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
)

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s))*p+0.9999999) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

func heapMB() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc >> 20
}

// TestPerf runs the §12.1 SLOs against a synthetic tenant at twice the design's
// target scale (TESSERA_PERF_SCALE=1 for the target itself). It runs nightly:
//
//	go test -tags slow -run TestPerf -timeout 60m ./internal/aws/query
//
// TESSERA_PERF_PROFILE=<dir> writes CPU and heap profiles there (keep the
// directory out of the repository). The SLOs are for a 16 vCPU worker; the
// log line says how many this machine has.
func TestPerf(t *testing.T) {
	scale := 2
	if v, err := strconv.Atoi(os.Getenv("TESSERA_PERF_SCALE")); err == nil && v > 0 {
		scale = v
	}
	cfg := awstest.TargetScale().Times(scale)
	t0 := time.Now()
	sc, err := awstest.GenerateScale(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scale x%d on %d CPUs: %d accounts, %d principals, %d policies, %d resources, %d actions; generated in %s, heap %d MB",
		scale, runtime.NumCPU(), cfg.Accounts, len(sc.Snap.Principals), len(sc.Snap.Policies), len(sc.Snap.Resources), len(sc.Actions), time.Since(t0).Round(time.Second), heapMB())

	icfg := index.Config{Catalog: awstest.Catalog{}, Actions: sc.Actions, Applies: awstest.SameServiceRule}
	t0 = time.Now()
	ix, err := index.Build(sc.Snap, icfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("index built in %s: %+v, heap %d MB", time.Since(t0).Round(time.Millisecond), ix.Counts(), heapMB())

	memo := index.NewMemo(12 << 20)
	opts := query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(fixedNow)}
	q, err := query.New(ix, memo, opts)
	if err != nil {
		t.Fatal(err)
	}
	g := awstest.NewRand(99)
	ctx := context.Background()

	if dir := os.Getenv("TESSERA_PERF_PROFILE"); dir != "" {
		f, err := os.Create(dir + "/cpu.pprof") // #nosec G304 -- a path the operator chose
		if err == nil {
			_ = pprof.StartCPUProfile(f)
			defer func() {
				pprof.StopCPUProfile()
				_ = f.Close()
				if h, err := os.Create(dir + "/heap.pprof"); err == nil { // #nosec G304
					_ = pprof.WriteHeapProfile(h)
					_ = h.Close()
				}
			}()
		}
	}

	// Point decision with full trace: p99 < 20 ms.
	var point []time.Duration
	for i := 0; i < 500; i++ {
		p := sc.Principals[g.Intn(len(sc.Principals))]
		a := sc.Actions[g.Intn(len(sc.Actions))]
		r := sc.Buckets[g.Intn(len(sc.Buckets))]
		s := time.Now()
		if _, err := q.Can(ctx, p, a, r); err != nil {
			t.Fatal(err)
		}
		point = append(point, time.Since(s))
	}
	t.Logf("point decision with trace: p50 %s p99 %s (SLO p99 < 20ms)", pct(point, .5), pct(point, .99))
	if pct(point, .99) > 20*time.Millisecond {
		t.Errorf("point decision p99 %s over the 20 ms SLO", pct(point, .99))
	}

	// All effective permissions of one principal: p95 < 3 s.
	var ep, epWarm []time.Duration
	var cells, rows int
	n := 100
	if v, err := strconv.Atoi(os.Getenv("TESSERA_PERF_SAMPLE")); err == nil && v > 0 {
		n = v
	}
	sample := make([]string, n)
	for i := range sample {
		sample[i] = sc.Principals[g.Intn(len(sc.Principals))]
	}
	for i, p := range sample {
		s := time.Now()
		perms, err := q.EffectivePermissions(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		ep = append(ep, time.Since(s))
		cells += perms.Stats.Cells
		rows += len(perms.Rows)
		if i < 5 {
			t.Logf("  effective permissions of %s: %s, %+v, %d rows", p, ep[i].Round(time.Millisecond), perms.Stats, len(perms.Rows))
		}
	}
	for _, p := range sample {
		s := time.Now()
		if _, err := q.EffectivePermissions(ctx, p); err != nil {
			t.Fatal(err)
		}
		epWarm = append(epWarm, time.Since(s))
	}
	t.Logf("effective permissions (cold memo): p50 %s p95 %s max %s; warm memo p95 %s; %d cells, %d rows per principal on average (SLO p95 < 3s)",
		pct(ep, .5), pct(ep, .95), pct(ep, 1), pct(epWarm, .95), cells/len(sample), rows/len(sample))
	if pct(ep, .95) > 3*time.Second {
		t.Errorf("effective permissions p95 %s over the 3 s SLO", pct(ep, .95))
	}

	// Who can do Y on Z: p95 < 2 s.
	var who []time.Duration
	var cand int
	for i := 0; i < 100; i++ {
		a := sc.Actions[g.Intn(len(sc.Actions))]
		if i%3 == 0 {
			a = "s3:Get" // in the generated action universe; an action outside it is asked of every principal
		}
		r := sc.Buckets[g.Intn(len(sc.Buckets))]
		s := time.Now()
		w, err := q.WhoCan(ctx, a, r)
		if err != nil {
			t.Fatal(err)
		}
		who = append(who, time.Since(s))
		cand += w.Candidates
	}
	t.Logf("who can: p50 %s p95 %s max %s; %d candidate atoms on average of %d (SLO p95 < 2s)", pct(who, .5), pct(who, .95), pct(who, 1), cand/len(who), len(ix.Principals.Atoms))
	if pct(who, .95) > 2*time.Second {
		t.Errorf("who-can p95 %s over the 2 s SLO", pct(who, .95))
	}

	// PR diff of one identity or resource policy: p95 < 60 s. The time includes
	// refining the index for the head snapshot.
	//
	// The tenant, two indexes and the memo are live at once, so from here a tight
	// collector keeps the peak under about 8 GB (the tests share a 16 GB machine).
	debug.SetGCPercent(25)
	var diffs []time.Duration
	for i := 0; i < 6; i++ {
		var head *model.Snapshot
		if i%2 == 0 {
			head, err = sc.WithManagedPolicyEdited(sc.UsedManaged[g.Intn(len(sc.UsedManaged))])
		} else {
			head, err = sc.WithResourcePolicyEdited(g.Intn(len(sc.RPSources)))
		}
		if err != nil {
			t.Fatal(err)
		}
		s := time.Now()
		hix, err := ix.Refine(head, icfg)
		if err != nil {
			t.Fatal(err)
		}
		hq, _ := query.New(hix, memo, opts)
		res, err := query.Diff(ctx, q, hq, query.DiffOptions{MaxExpand: 5})
		if err != nil {
			t.Fatal(err)
		}
		d := time.Since(s)
		diffs = append(diffs, d)
		t.Logf("diff %d: %s, %d changes in %d principal groups (%d recomputed in full), refine %+v", i, d.Round(time.Millisecond), len(res.Changes), res.Groups, res.Recomputed, hix.ResourceStats)
	}
	t.Logf("single-policy diff: p95 %s (SLO p95 < 60s)", pct(diffs, .95))
	if pct(diffs, .95) > 60*time.Second {
		t.Errorf("diff p95 %s over the 60 s SLO", pct(diffs, .95))
	}

	// Full materialization < 60 min, extrapolated from a sample of principal atoms.
	mat := 200
	if v, err := strconv.Atoi(os.Getenv("TESSERA_PERF_SAMPLE")); err == nil && v > 0 {
		mat = v
	}
	if mat > len(ix.Principals.Atoms) {
		mat = len(ix.Principals.Atoms)
	}
	// A fresh memo, so the cells are really computed, and the normal collector:
	// the tight one above would charge the diff's memory pressure to this phase.
	debug.SetGCPercent(100)
	cold, _ := query.New(ix, index.NewMemo(12<<20), opts)
	t0 = time.Now()
	for i := 0; i < mat; i++ {
		at := ix.Principals.Atoms[(i*len(ix.Principals.Atoms))/mat]
		if _, err := cold.EffectivePermissions(ctx, ix.Principals.RepARN(at.ID)); err != nil {
			t.Fatal(err)
		}
	}
	per := time.Since(t0) / time.Duration(mat)
	total := per * time.Duration(len(ix.Principals.Atoms))
	t.Logf("materialization: %s per principal atom over %d sampled, %d atoms: about %s (SLO < 60m, extrapolated)", per, mat, len(ix.Principals.Atoms), total.Round(time.Second))
	if total > 60*time.Minute {
		t.Errorf("extrapolated materialization %s over the 60 min SLO", total)
	}

	// An SCP change under one OU; at the root it touches every principal and is
	// only run when TESSERA_PERF_ROOT=1 (SLO < 15 min).
	attach := sc.OUs[0]
	if os.Getenv("TESSERA_PERF_ROOT") == "1" {
		attach = "r-1"
	}
	debug.SetGCPercent(25)
	head, err := sc.WithSCPAttached(attach)
	if err != nil {
		t.Fatal(err)
	}
	s := time.Now()
	hix, err := ix.Refine(head, icfg)
	if err != nil {
		t.Fatal(err)
	}
	hq, _ := query.New(hix, memo, opts)
	dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	res, err := query.Diff(dctx, q, hq, query.DiffOptions{MaxExpand: 5})
	if err != nil {
		t.Fatalf("SCP diff at %s: %v after %s", attach, err, time.Since(s))
	}
	t.Logf("SCP attached at %s: %s, %d changes, %d of %d principal groups recomputed (SLO < 15m at root)", attach, time.Since(s).Round(time.Second), len(res.Changes), res.Recomputed, res.Groups)
	t.Logf("memo: %d cells; final heap %d MB", memo.Len(), heapMB())
}
