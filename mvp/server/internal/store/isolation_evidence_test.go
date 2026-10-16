package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Edge history and evidence packs (issue #111): a tenant sees and changes
// only its own spans and packs.

func TestIsolation_EdgeHistoryReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	count := func(tn storetest.Tenant) (all, asOf, since int) {
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			spans, err := c.EdgeSpans()
			if err != nil {
				return err
			}
			a, err := c.EdgeSpansAsOf(storetest.Now)
			if err != nil {
				return err
			}
			s, err := c.EdgeSpansSince(storetest.Now.Add(-1000 * time.Hour))
			if err != nil {
				return err
			}
			for _, x := range append(append(spans, a...), s...) {
				if x.TenantID != tn.ID {
					t.Errorf("tenant %s read a span of %s", tn.Slug, x.TenantID)
				}
			}
			all, asOf, since = len(spans), len(a), len(s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	aAll, aAsOf, aSince := count(f.A)
	bAll, bAsOf, bSince := count(f.B)
	if aAll == 0 || aAsOf == 0 || aSince == 0 {
		t.Fatalf("the fixture should give tenant A spans: %d %d %d", aAll, aAsOf, aSince)
	}
	// A and B hold the same data: an unscoped query would return twice as many
	if aAll != bAll || aAsOf != bAsOf || aSince != bSince {
		t.Errorf("A has %d/%d/%d spans, B has %d/%d/%d", aAll, aAsOf, aSince, bAll, bAsOf, bSince)
	}
}

// TestIsolation_EdgeHistoryWritesScoped: removing edges in B closes only B's
// spans, and an edge of A named by id in B is neither deleted nor closed.
func TestIsolation_EdgeHistoryWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := storetest.Dump(t, f.DB, f.A.ID)
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.DeleteEdge(f.A.IDs["edge:0"], storetest.Now); err != nil {
			return err
		}
		if err := c.RevokeEdge(f.B.IDs["edge:0"], storetest.Now, "test"); err != nil {
			return err
		}
		_, err := c.DeleteExpiredJITEdges(storetest.Now.Add(1000 * time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
		t.Error("closing spans in B changed tenant A")
	}
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		spans, err := c.EdgeSpans()
		if err != nil {
			return err
		}
		closed := 0
		for _, s := range spans {
			if s.ValidTo != nil {
				closed++
			}
		}
		if closed < 2 {
			t.Errorf("B has %d closed spans, want the revoked edge and the swept JIT edges closed", closed)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func seedPacks(t *testing.T, f *storetest.Fixture) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for i, tn := range []storetest.Tenant{f.A, f.B} {
		p := &store.EvidencePack{ID: "00000000-0000-4000-8000-00000000000" + string(rune('1'+i)), Framework: "soc2",
			PeriodFrom: storetest.Now.Add(-24 * time.Hour), PeriodTo: storetest.Now, GeneratedAt: storetest.Now,
			GeneratedBy: "auditor", ManifestSHA256: "abc", Manifest: []byte(`{"files":[]}`), SizeBytes: 3, Content: []byte("zip")}
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error { return c.InsertEvidencePack(p) }); err != nil {
			t.Fatal(err)
		}
		ids[tn.Slug] = p.ID
	}
	return ids
}

func TestIsolation_EvidencePackReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedPacks(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		packs, err := c.EvidencePacks()
		if err != nil || len(packs) != 1 || packs[0].ID != ids[f.B.Slug] || packs[0].TenantID != f.B.ID {
			t.Errorf("EvidencePacks = %v, %v", packs, err)
		}
		if len(packs) == 1 && len(packs[0].Content) != 0 {
			t.Error("the list carries pack content")
		}
		if _, err := c.EvidencePack(ids[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("EvidencePack(A's) in B = %v, want ErrNotFound", err)
		}
		own, err := c.EvidencePack(ids[f.B.Slug])
		if err != nil || string(own.Content) != "zip" {
			t.Errorf("EvidencePack(B's) = %v, %v", own, err)
		}
		return nil
	})
}

func TestIsolation_EvidencePackWriteScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedPacks(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertEvidencePack(&store.EvidencePack{ID: "x", TenantID: f.A.ID, Framework: "soc2", Manifest: []byte(`{}`)})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("a pack stamped with A inserted in B = %v, want ErrCrossTenant", err)
	}
	// the same id in both tenants is two packs (the key is (tenant, id))
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.InsertEvidencePack(&store.EvidencePack{ID: "same", Framework: "soc2", Manifest: []byte(`{}`), Content: []byte(tn.Slug)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		p, err := c.EvidencePack("same")
		if err != nil || string(p.Content) != f.B.Slug {
			t.Errorf("B's pack %q = %v, %v", "same", p, err)
		}
		return nil
	})
}

func evidenceCovered() map[string]bool {
	return map[string]bool{"EdgeSpans": true, "EdgeSpansAsOf": true, "EdgeSpansSince": true, // TestIsolation_EdgeHistoryReads
		"EvidencePacks": true, "EvidencePack": true, // TestIsolation_EvidencePackReads
		"InsertEvidencePack": true, // TestIsolation_EvidencePackWriteScoped
	}
}
