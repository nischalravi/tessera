package graph_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// Benchmarks over the seeded demo company (~90 identities, ~210 accounts,
// ~420 grant edges). Run with: go test -run '^$' -bench . ./internal/graph/

func BenchmarkBuild(b *testing.B) {
	testkit.Read(b, testkit.Demo(b), func(c *store.TenantTx) error {
		for b.Loop() {
			if _, err := graph.Build(c, testkit.Now); err != nil {
				return err
			}
		}
		return nil
	})
}

func BenchmarkAllEffectivePermissions(b *testing.B) {
	g := testkit.Get(b, testkit.Demo(b), func(c *store.TenantTx) (*graph.Snapshot, error) { return graph.Build(c, testkit.Now) })
	for b.Loop() {
		// a fresh copy has an empty cache, so every iteration recomputes
		eff := g.Copy().AllEffective()
		if len(eff) == 0 {
			b.Fatal("no identities")
		}
	}
}

func BenchmarkEffectivePermissionsOneIdentity(b *testing.B) {
	st := testkit.Demo(b)
	var alice int64
	g := testkit.Get(b, st, func(c *store.TenantTx) (*graph.Snapshot, error) {
		idents, err := c.Identities()
		if err != nil {
			return nil, err
		}
		for _, i := range idents {
			if i.Name == "Alice Okafor" {
				alice = i.ID
			}
		}
		return graph.Build(c, testkit.Now)
	})
	for b.Loop() {
		if g.Copy().EffectivePermissions(alice).Len() == 0 {
			b.Fatal("no permissions")
		}
	}
}

// BenchmarkAnalysisPipeline is what an analysis request does: build the graph
// and usage index, compute every identity's effective permissions and
// evaluate all policies.
func BenchmarkAnalysisPipeline(b *testing.B) {
	pols := testkit.Policies(b)
	testkit.Read(b, testkit.Demo(b), func(c *store.TenantTx) error {
		for b.Loop() {
			g, err := graph.Build(c, testkit.Now)
			if err != nil {
				return err
			}
			if _, err := usage.Build(c, testkit.Now); err != nil {
				return err
			}
			g.AllEffective()
			if _, err := policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now)); err != nil {
				return err
			}
		}
		return nil
	})
}
