package query_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/query"
)

// The benchmarks run on a tenant of one fiftieth of the design's target (and
// one fiftieth of the catalog), so they finish in seconds and can be tracked
// with benchstat. The slow TestPerf covers the real scale.
func benchScaled(b *testing.B) (*awstest.Scaled, *index.Index, *query.Querier) {
	b.Helper()
	cfg := awstest.TargetScale()
	cfg.Accounts, cfg.Principals, cfg.ManagedDocs, cfg.Resources, cfg.ResourcePolicyDocs = 20, 1000, 400, 40000, 1000
	cfg.Services, cfg.PermissionSets = 40, 60
	sc, err := awstest.GenerateScale(cfg)
	if err != nil {
		b.Fatal(err)
	}
	ix, err := index.Build(sc.Snap, index.Config{Catalog: awstest.Catalog{}, Actions: sc.Actions, Applies: awstest.SameServiceRule})
	if err != nil {
		b.Fatal(err)
	}
	q, err := query.New(ix, index.NewMemo(1<<20), query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(fixedNow)})
	if err != nil {
		b.Fatal(err)
	}
	return sc, ix, q
}

func BenchmarkBuildIndex(b *testing.B) {
	sc, _, _ := benchScaled(b)
	cfg := index.Config{Catalog: awstest.Catalog{}, Actions: sc.Actions, Applies: awstest.SameServiceRule}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := index.Build(sc.Snap, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRefineIndex(b *testing.B) {
	sc, ix, _ := benchScaled(b)
	head, err := sc.WithManagedPolicyEdited(sc.UsedManaged[3])
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ix.Refine(head, ix.Config()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCan(b *testing.B) {
	sc, _, q := benchScaled(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := q.Can(context.Background(), sc.Principals[i%len(sc.Principals)], "s3:GetObject", sc.Buckets[i%len(sc.Buckets)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEffectivePermissions(b *testing.B) {
	sc, _, q := benchScaled(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// A fresh memo each time: the cost of the cells, not of the cache.
		fresh, _ := query.New(q.Idx, index.NewMemo(1<<20), query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(fixedNow)})
		if _, err := fresh.EffectivePermissions(context.Background(), sc.Principals[i%len(sc.Principals)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWhoCan(b *testing.B) {
	sc, _, q := benchScaled(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := q.WhoCan(context.Background(), "s3:Get", sc.Buckets[i%len(sc.Buckets)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiffManagedPolicy(b *testing.B) {
	sc, ix, q := benchScaled(b)
	head, err := sc.WithManagedPolicyEdited(sc.UsedManaged[5])
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hix, err := ix.Refine(head, ix.Config())
		if err != nil {
			b.Fatal(err)
		}
		hq, _ := query.New(hix, q.Memo, query.Options{Mode: eval.Symbolic, Profile: eval.DefaultProfile(fixedNow)})
		if _, err := query.Diff(context.Background(), q, hq, query.DiffOptions{MaxExpand: 5}); err != nil {
			b.Fatal(err)
		}
	}
}
