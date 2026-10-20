package graph_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func loadAsOf(t *testing.T, st *testkit.DB, at time.Time) *graph.Snapshot {
	t.Helper()
	return testkit.Get(t, st, func(c *store.TenantTx) (*graph.Snapshot, error) { return graph.BuildAsOf(c, at) })
}

// aliceProd reports whether alice reaches iam:* on aws/prod in g.
func aliceProd(g *graph.Snapshot, ids testkit.IDs) bool {
	return byAction(g.EffectivePermissions(ids["alice"]))[ar{"iam:*", "aws/prod"}] != nil
}

// TestAsOfAcrossAddedThenRemovedEdge: an edge added at t1 and removed at t2
// holds on [t1, t2): present at t1, absent a microsecond before t1, present a
// microsecond before t2, absent at t2 and after. Today's graph (the edge is
// gone) agrees with the answer at t2 and later, and a date before the data
// existed says nobody had the access.
func TestAsOfAcrossAddedThenRemovedEdge(t *testing.T) {
	st, ids := testkit.Tiny(t)
	t1, t2 := testkit.Now.Add(time.Hour), testkit.Now.Add(3*time.Hour)
	src, dst := acctKey(ids, "okta:alice"), groupKey(ids, "aws:ProdAdmin")
	var edgeID int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		edgeID, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "manual", CreatedAt: t1})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error { return c.DeleteEdge(edgeID, t2) })

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before any data", testkit.Now.Add(-24 * time.Hour), false},
		{"just before the edge was added", t1.Add(-time.Microsecond), false},
		{"exactly when it was added", t1, true},
		{"between", t1.Add(time.Hour), true},
		{"just before it was removed", t2.Add(-time.Microsecond), true},
		{"exactly when it was removed", t2, false},
		{"after it was removed", t2.Add(24 * time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aliceProd(loadAsOf(t, st, tc.at), ids); got != tc.want {
				t.Errorf("alice reaches iam:* on aws/prod at %s = %v, want %v", tc.at.Format(time.RFC3339Nano), got, tc.want)
			}
		})
	}
	if aliceProd(load(t, st, t2.Add(time.Hour)), ids) {
		t.Error("the live graph still has the removed edge")
	}
}

// TestAsOfReAddedEdgeHasTwoSpans: an edge removed and added again holds in
// both spans and not in the gap between them.
func TestAsOfReAddedEdgeHasTwoSpans(t *testing.T) {
	st, ids := testkit.Tiny(t)
	h := func(n int) time.Time { return testkit.Now.Add(time.Duration(n) * time.Hour) }
	src, dst := acctKey(ids, "okta:alice"), groupKey(ids, "aws:ProdAdmin")
	var id1 int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id1, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "manual", CreatedAt: h(1)})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error { return c.DeleteEdge(id1, h(2)) })
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "manual", CreatedAt: h(4)})
		return err
	})
	for at, want := range map[time.Time]bool{h(1): true, h(2): false, h(3): false, h(4): true, h(9): true} {
		if got := aliceProd(loadAsOf(t, st, at), ids); got != want {
			t.Errorf("at +%v = %v, want %v", at.Sub(testkit.Now), got, want)
		}
	}
}

// TestAsOfJITExpiryBeforeSweep: a JIT grant stops holding at its own expiry,
// even when the sweeper removed the edge hours later; an early revoke stops
// it at the revoke.
func TestAsOfJITExpiryBeforeSweep(t *testing.T) {
	st, ids := testkit.Tiny(t)
	h := func(n int) time.Time { return testkit.Now.Add(time.Duration(n) * time.Hour) }
	src, dst := acctKey(ids, "okta:alice"), groupKey(ids, "aws:ProdAdmin")
	exp := h(2)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "jit", ExpiresAt: &exp,
			CreatedAt: h(1)})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		n, err := c.DeleteExpiredJITEdges(h(10)) // the sweeper ran late
		if n != 1 {
			t.Errorf("swept %d edges, want 1", n)
		}
		return err
	})
	for at, want := range map[time.Time]bool{h(1): true, h(2).Add(-time.Microsecond): true, h(2): false, h(5): false} {
		if got := aliceProd(loadAsOf(t, st, at), ids); got != want {
			t.Errorf("expired JIT at +%v = %v, want %v", at.Sub(testkit.Now), got, want)
		}
	}

	// early revoke: closes the span at the revoke instant, before expiry
	exp2 := h(20)
	var edge int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		edge, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "jit", ExpiresAt: &exp2,
			CreatedAt: h(11)})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error { return c.DeleteJITEdge(edge, h(12)) })
	for at, want := range map[time.Time]bool{h(11): true, h(12).Add(-time.Microsecond): true, h(12): false, h(19): false} {
		if got := aliceProd(loadAsOf(t, st, at), ids); got != want {
			t.Errorf("revoked JIT at +%v = %v, want %v", at.Sub(testkit.Now), got, want)
		}
	}
}

// TestAsOfJITExtension: extending a grant closes the old span and opens a
// new one with the new expiry, so the answer before the extension still uses
// the old expiry.
func TestAsOfJITExtension(t *testing.T) {
	st, ids := testkit.Tiny(t)
	h := func(n int) time.Time { return testkit.Now.Add(time.Duration(n) * time.Hour) }
	src, dst := acctKey(ids, "okta:alice"), groupKey(ids, "aws:ProdAdmin")
	exp := h(3)
	var edge int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		edge, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "jit", ExpiresAt: &exp,
			CreatedAt: h(1)})
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error { return c.SetEdgeExpiry(edge, h(8), h(2)) })
	for at, want := range map[time.Time]bool{h(1): true, h(3): true, h(7): true, h(8): false} {
		if got := aliceProd(loadAsOf(t, st, at), ids); got != want {
			t.Errorf("extended JIT at +%v = %v, want %v", at.Sub(testkit.Now), got, want)
		}
	}
}

// TestAsOfIgnoresTodaysAccountStatus: dave's Okta account is disabled today
// but his edges held earlier, so as of an earlier time his access via Okta is
// still reported, and the live graph keeps ignoring it.
func TestAsOfIgnoresTodaysAccountStatus(t *testing.T) {
	st, ids := testkit.Tiny(t)
	live := byAction(load(t, st, testkit.Now).EffectivePermissions(ids["dave"]))
	asOf := byAction(loadAsOf(t, st, testkit.Now).EffectivePermissions(ids["dave"]))
	if len(asOf) <= len(live) {
		t.Errorf("as-of dave has %d permissions, live %d: the disabled account's grants should show as of then", len(asOf), len(live))
	}
}
