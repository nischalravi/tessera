package graph_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// Benchmarks over the seeded demo company (~90 identities, ~210 accounts,
// ~420 grant edges). Run with: go test -run '^$' -bench . ./internal/graph/

func BenchmarkFromDB(b *testing.B) {
	c := testkit.Conn(testkit.Demo(b))
	for b.Loop() {
		if _, err := graph.FromDB(c, testkit.Now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAllEffectivePermissions(b *testing.B) {
	g, err := graph.FromDB(testkit.Conn(testkit.Demo(b)), testkit.Now)
	if err != nil {
		b.Fatal(err)
	}
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
	c := testkit.Conn(st)
	alice, err := c.Identities("WHERE name = 'Alice Okafor'")
	if err != nil || len(alice) != 1 {
		b.Fatal(err)
	}
	g, err := graph.FromDB(c, testkit.Now)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if g.Copy().EffectivePermissions(alice[0].ID).Len() == 0 {
			b.Fatal("no permissions")
		}
	}
}

// BenchmarkAnalysisPipeline is what an analysis request does: build the graph
// and usage index, compute every identity's effective permissions and
// evaluate all policies.
func BenchmarkAnalysisPipeline(b *testing.B) {
	c := testkit.Conn(testkit.Demo(b))
	pols := testkit.Policies(b)
	for b.Loop() {
		g, err := graph.FromDB(c, testkit.Now)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := usage.Build(c, testkit.Now); err != nil {
			b.Fatal(err)
		}
		g.AllEffective()
		if _, err := policy.Evaluate(pols, policy.NewContext(g, c, testkit.Now)); err != nil {
			b.Fatal(err)
		}
	}
}
