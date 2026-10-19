package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The writers of intended and observed access (issue #301): every edge writer
// of approval-side code writes or closes intent beside grant_edges, in the same
// transaction; connector edges and syncs never create intent.

func openIntent(t *testing.T, c *store.TenantTx, identity int64, ref string) *store.IntendedGrant {
	t.Helper()
	gs, err := c.IntendedGrants()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gs {
		if g.IdentityID == identity && g.TargetRef == ref && g.ClosedAt == nil {
			return g
		}
	}
	return nil
}

func TestAccessModel_EdgeWritersWriteAndCloseIntent(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := f.A.IDs
	acct, alice := ids["acct:okta:alice"], ids["alice"]
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g, err := c.Group(ids["group:aws:ProdAdmin"])
		if err != nil {
			return err
		}
		src, dst := key("account", acct), key("group", g.ID)
		before, _ := c.CountIntendedGrants()
		cases := []struct {
			source, wantProv string
			prov, ref        string
		}{
			{"request", store.ProvRequest, "", "line:1"},
			{"role", store.ProvRole, "", "role:r1"},
			{"role", store.ProvBirthright, store.ProvBirthright, "role:r2"},
			{"manual", store.ProvManual, "", "jml:alice"},
		}
		for _, tc := range cases {
			exp := storetest.Now.Add(time.Hour)
			id, err := c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: tc.source,
				ExpiresAt: &exp, CreatedAt: storetest.Now, Ref: tc.ref, Provenance: tc.prov})
			if err != nil {
				return err
			}
			in := openIntent(t, c, alice, g.ExternalID)
			if in == nil || in.Provenance != tc.wantProv || in.ProvenanceRef == nil || *in.ProvenanceRef != tc.ref ||
				in.EdgeID == nil || *in.EdgeID != id || in.ValidUntil == nil || !in.ValidUntil.Equal(exp) || in.TargetSystem != g.System {
				t.Fatalf("%s edge: intent = %+v", tc.source, in)
			}
			if err := c.DeleteEdge(id); err != nil {
				return err
			}
			if openIntent(t, c, alice, g.ExternalID) != nil {
				t.Fatalf("%s edge: DeleteEdge left the intent open", tc.source)
			}
		}
		if n, _ := c.CountIntendedGrants(); n != before+len(cases) {
			t.Errorf("intended grants = %d, want %d (closed rows are kept)", n, before+len(cases))
		}
		// revoke closes with the reason; extending a JIT edge moves valid_until
		id, err := c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "jit",
			CreatedAt: storetest.Now, Ref: "jit:9"})
		if err != nil {
			return err
		}
		until := storetest.Now.Add(3 * time.Hour)
		if err := c.SetEdgeExpiry(id, until); err != nil {
			return err
		}
		if in := openIntent(t, c, alice, g.ExternalID); in == nil || in.ValidUntil == nil || !in.ValidUntil.Equal(until) {
			t.Errorf("SetEdgeExpiry: intent = %+v", in)
		}
		if err := c.RevokeEdge(id, storetest.Now, "review"); err != nil {
			return err
		}
		gs, _ := c.IntendedGrants()
		var last *store.IntendedGrant
		for _, x := range gs {
			// (an edge id can be reused after a delete, so match on the reason)
			if x.CloseReason != nil && *x.CloseReason == "review" {
				last = x
			}
		}
		if last == nil || last.ClosedAt == nil || last.CloseReason == nil || *last.CloseReason != "review" {
			t.Errorf("RevokeEdge: intent = %+v", last)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccessModel_JITExpiryAndRequestRoleDeletesCloseIntent(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := f.A.IDs
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		// the fixture's expired JIT grant (carol) has an open intent until the sweep
		carol := ids["carol"]
		g, _ := c.Group(ids["group:aws:ProdAdmin"])
		if openIntent(t, c, carol, g.ExternalID) == nil {
			t.Fatal("the fixture's JIT grant has no intent")
		}
		// the approved request that points at the edge keeps it; only edges of
		// no approved request are swept (the fixture's expired one has such a request)
		if _, err := c.DeleteExpiredJITEdges(storetest.Now); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// a JIT edge of no request: swept, its intent closed as expired
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g, _ := c.Group(ids["group:snowflake:PII_READER"])
		exp := storetest.Now.Add(-time.Minute)
		if _, err := c.InsertEdge(&store.GrantEdge{Src: key("account", ids["acct:okta:carol"]), Dst: key("group", g.ID),
			Relation: "member_of", Source: "jit", ExpiresAt: &exp, CreatedAt: storetest.Now.Add(-time.Hour)}); err != nil {
			return err
		}
		if openIntent(t, c, ids["carol"], g.ExternalID) == nil {
			t.Fatal("no intent for the JIT edge")
		}
		if n, err := c.DeleteExpiredJITEdges(storetest.Now); err != nil || n == 0 {
			t.Fatalf("DeleteExpiredJITEdges = %d, %v", n, err)
		}
		if openIntent(t, c, ids["carol"], g.ExternalID) != nil {
			t.Error("the sweep left the intent open")
		}
		gs, _ := c.IntendedGrants()
		for _, x := range gs {
			if x.IdentityID == ids["carol"] && x.TargetRef == g.ExternalID && (x.CloseReason == nil || *x.CloseReason != store.CloseExpired) {
				t.Errorf("intent closed as %v, want expired", x.CloseReason)
			}
		}
		// request and role deletes close by source
		for _, src := range []string{"request", "role"} {
			id, err := c.InsertEdge(&store.GrantEdge{Src: key("account", ids["acct:okta:carol"]), Dst: key("group", g.ID),
				Relation: "member_of", Source: src, CreatedAt: storetest.Now})
			if err != nil {
				return err
			}
			if src == "request" {
				err = c.DeleteRequestEdge(id)
			} else {
				err = c.DeleteRoleEdge(id)
			}
			if err != nil {
				return err
			}
			if openIntent(t, c, ids["carol"], g.ExternalID) != nil {
				t.Errorf("%s delete left the intent open", src)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccessModel_ConnectorNeverCreatesIntent(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := f.A.IDs
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g, _ := c.Group(ids["group:aws:ProdAdmin"])
		before, _ := c.CountIntendedGrants()
		src, dst := key("account", ids["acct:okta:dave"]), key("group", g.ID)
		if err := c.UpsertConnectorEdge(src, dst, "member_of", storetest.Now); err != nil {
			return err
		}
		g2, _ := c.Group(ids["group:snowflake:PII_READER"])
		if _, err := c.InsertEdge(&store.GrantEdge{Src: key("account", ids["acct:okta:carol"]), Dst: key("group", g2.ID),
			Relation: "member_of", Source: "connector", CreatedAt: storetest.Now}); err != nil {
			return err
		}
		if n, _ := c.CountIntendedGrants(); n != before {
			t.Errorf("connector edges created %d intended grants", n-before)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccessModel_ObservedRunReplacesSnapshot(t *testing.T) {
	f := storetest.TwoTenants(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		row := func(acct, ref string) store.ObservedRow {
			return store.ObservedRow{System: "okta", AccountRef: acct, EntitlementKind: "group", EntitlementSystem: "okta", EntitlementRef: ref}
		}
		at := storetest.Now.Add(time.Hour)
		r1, err := c.RecordObservedRun("okta", at, []store.ObservedRow{row("alice", "eng"), row("alice", "eng-x")})
		if err != nil {
			return err
		}
		r2, err := c.RecordObservedRun("okta", at.Add(time.Hour), []store.ObservedRow{row("alice", "eng")})
		if err != nil {
			return err
		}
		if r1 == r2 {
			t.Fatal("two runs share an id")
		}
		os, _ := c.ObservedEntitlements()
		var okta int
		for _, o := range os {
			if o.System != "okta" {
				continue
			}
			okta++
			if o.RunID != r2 || !o.ObservedAt.Equal(at.Add(time.Hour)) {
				t.Errorf("observed %+v is not from the latest run %s", o, r2)
			}
			if o.EntitlementRef == "eng-x" {
				t.Error("an entitlement the system stopped reporting is still observed")
			}
		}
		if okta != 1 {
			t.Errorf("okta observed rows = %d, want 1", okta)
		}
		runs, _ := c.ObservedRuns()
		n := 0
		for _, r := range runs {
			if r.System == "okta" {
				n++
				if r.ID != r2 || r.Entitlements != 1 || r.Source != store.ObsConnector {
					t.Errorf("run = %+v", r)
				}
			}
		}
		if n != 1 {
			t.Errorf("okta runs kept = %d, want the latest only", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
