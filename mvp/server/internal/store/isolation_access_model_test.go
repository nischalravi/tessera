package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Intended and observed access, drift and remediation policies (schema/0330,
// 0331, issue #301): a tenant sees and changes only its own rows; rows naming
// another tenant's identity, account or intent are refused by the guards.

type accessRows struct {
	drift, policy string
	intended      string
	alice, acct   int64
	group         *store.Group
}

func seedAccessModel(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) accessRows {
	t.Helper()
	r := accessRows{drift: "drift-" + tag, alice: tn.IDs["alice"], acct: tn.IDs["acct:okta:alice"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		g, err := c.Group(tn.IDs["group:okta:eng"])
		if err != nil {
			return err
		}
		r.group = g
		if err := c.KeepIntent(key("account", r.acct), key("group", g.ID), "review-item:"+tag, storetest.Now); err != nil {
			return err
		}
		gs, err := c.IntendedGrants()
		if err != nil {
			return err
		}
		for _, x := range gs {
			if x.Provenance == store.ProvReviewKeep {
				r.intended = x.ID
			}
		}
		if _, err := c.InsertAccessDrift(&store.AccessDrift{ID: r.drift, TenantID: tn.ID, Key: "rogue|" + tag, Class: store.DriftRogue,
			System: g.System, EntitlementKind: "group", EntitlementRef: g.ExternalID, AccountID: &r.acct, IdentityID: &r.alice,
			Status: store.DriftOpen, DetectedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.UpsertRemediationPolicy(&store.RemediationPolicy{ID: "pol-" + tag, TenantID: tn.ID, System: g.System,
			DriftClass: store.DriftRogue, Action: store.ActionOwnerTask, CreatedBy: "t", UpdatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.intended == "" {
		t.Fatal("KeepIntent wrote no intended grant")
	}
	return r
}

func accessFixture(t *testing.T) (*storetest.Fixture, accessRows, accessRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedAccessModel(t, f.DB, f.A, "a"), seedAccessModel(t, f.DB, f.B, "b")
}

func TestIsolation_AccessModelReads(t *testing.T) {
	f, a, b := accessFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if ds, err := c.AccessDrifts(store.DriftFilter{}); err != nil || len(ds) != 1 || ds[0].ID != b.drift {
			t.Errorf("AccessDrifts = %v, %v", ds, err)
		}
		if ds, err := c.AccessDrifts(store.DriftFilter{IdentityID: a.alice, Class: store.DriftRogue}); err != nil || len(ds) != 0 {
			// B's alice has another id; A's alice id matches no B row
			t.Errorf("AccessDrifts(A's identity) = %v, %v", ds, err)
		}
		if _, err := c.AccessDrift(a.drift); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AccessDrift(A's) = %v", err)
		}
		if cs, err := c.AccessDriftCounts(); err != nil || len(cs) != 1 || cs[0].N != 1 {
			t.Errorf("AccessDriftCounts = %v, %v", cs, err)
		}
		if _, err := c.IntendedGrant(a.intended); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("IntendedGrant(A's) = %v", err)
		}
		gs, err := c.IntendedGrants()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.TenantID != f.B.ID || g.ID == a.intended {
				t.Errorf("IntendedGrants has %s of tenant %s", g.ID, g.TenantID)
			}
		}
		if n, err := c.CountIntendedGrants(); err != nil || n != len(gs) {
			t.Errorf("CountIntendedGrants = %d, %v", n, err)
		}
		os, err := c.ObservedEntitlements()
		if err != nil || len(os) == 0 {
			t.Errorf("ObservedEntitlements = %d, %v", len(os), err)
		}
		for _, o := range os {
			if o.TenantID != f.B.ID {
				t.Errorf("ObservedEntitlements has a row of tenant %s", o.TenantID)
			}
		}
		if n, err := c.CountObservedEntitlements(); err != nil || n != len(os) {
			t.Errorf("CountObservedEntitlements = %d, %v", n, err)
		}
		runs, err := c.ObservedRuns()
		if err != nil || len(runs) == 0 {
			t.Errorf("ObservedRuns = %v, %v", runs, err)
		}
		for _, r := range runs {
			if r.TenantID != f.B.ID {
				t.Errorf("ObservedRuns has a run of tenant %s", r.TenantID)
			}
		}
		if ps, err := c.RemediationPolicies(); err != nil || len(ps) != 1 || ps[0].ID != "pol-b" {
			t.Errorf("RemediationPolicies = %v, %v", ps, err)
		}
		if _, err := c.RemediationPolicy("pol-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RemediationPolicy(A's) = %v", err)
		}
		return nil
	})
}

var accessMutations = map[string]func(c *store.TenantTx, a, b accessRows, aid tenancy.ID) error{
	"UpdateAccessDrift": func(c *store.TenantTx, a, _ accessRows, _ tenancy.ID) error {
		return c.UpdateAccessDrift(&store.AccessDrift{ID: a.drift, Status: store.DriftResolved, DetectedAt: storetest.Now,
			UpdatedAt: storetest.Now, Action: store.ActionNone})
	},
	"InsertAccessDrift": func(c *store.TenantTx, a, _ accessRows, _ tenancy.ID) error {
		// B's drift row naming A's identity and account
		_, err := c.InsertAccessDrift(&store.AccessDrift{Key: "x", Class: store.DriftRogue, System: "okta", AccountID: &a.acct,
			IdentityID: &a.alice, Status: store.DriftOpen, DetectedAt: storetest.Now, UpdatedAt: storetest.Now})
		return err
	},
	"InsertAccessDrift.intended_id": func(c *store.TenantTx, a, _ accessRows, _ tenancy.ID) error {
		_, err := c.InsertAccessDrift(&store.AccessDrift{Key: "y", Class: store.DriftStale, System: "okta", IntendedID: &a.intended,
			Status: store.DriftOpen, DetectedAt: storetest.Now, UpdatedAt: storetest.Now})
		return err
	},
	"UpsertRemediationPolicy": func(c *store.TenantTx, _, _ accessRows, aid tenancy.ID) error {
		return c.UpsertRemediationPolicy(&store.RemediationPolicy{TenantID: aid, System: "okta", DriftClass: store.DriftRogue,
			Action: store.ActionReportOnly, CreatedBy: "x", UpdatedAt: storetest.Now})
	},
	"DeleteRemediationPolicy": func(c *store.TenantTx, _, _ accessRows, _ tenancy.ID) error {
		return c.DeleteRemediationPolicy("pol-a")
	},
}

func TestIsolation_AccessModelMutationsScoped(t *testing.T) {
	for name, fn := range accessMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := accessFixture(t)
			before := accessDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b, f.A.ID) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if accessDump(t, f.DB, f.A.ID) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// The writers that resolve their target by id write nothing when the id is
// another tenant's: KeepIntent, RecordObservedRun and BackfillAccessModel
// change only their own tenant.
func TestIsolation_AccessModelWritersScoped(t *testing.T) {
	f, a, _ := accessFixture(t)
	before := accessDump(t, f.DB, f.A.ID)
	bBefore := accessDump(t, f.DB, f.B.ID)
	inB(t, f, func(c *store.TenantTx) error {
		// A's account and group ids in B: unknown here, so nothing is recorded
		if err := c.KeepIntent(key("account", a.acct), key("group", a.group.ID), "x", storetest.Now); err != nil {
			t.Errorf("KeepIntent(A's ids) = %v", err)
		}
		if _, err := c.RecordObservedRun("okta", storetest.Now.Add(time.Hour), []store.ObservedRow{{System: "okta", AccountRef: "alice",
			EntitlementKind: "group", EntitlementSystem: "okta", EntitlementRef: "eng"}}); err != nil {
			t.Errorf("RecordObservedRun = %v", err)
		}
		if ran, err := c.BackfillAccessModel(storetest.Now); err != nil || ran {
			t.Errorf("BackfillAccessModel = %v, %v (B already has both sets)", ran, err)
		}
		return nil
	})
	if accessDump(t, f.DB, f.A.ID) != before {
		t.Error("writers in B changed A")
	}
	if accessDump(t, f.DB, f.B.ID) == bBefore {
		t.Error("RecordObservedRun in B changed nothing in B")
	}
}

func accessDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		gs, err := c.IntendedGrants()
		if err != nil {
			return err
		}
		os, err := c.ObservedEntitlements()
		if err != nil {
			return err
		}
		rs, err := c.ObservedRuns()
		if err != nil {
			return err
		}
		ds, err := c.AccessDrifts(store.DriftFilter{})
		if err != nil {
			return err
		}
		ps, err := c.RemediationPolicies()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{gs, os, rs, ds, ps})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func accessModelCovered() map[string]bool {
	out := map[string]bool{}
	for k := range accessMutations {
		out[k] = true
	}
	for _, k := range []string{"AccessDrifts", "AccessDrift", "AccessDriftCounts", "IntendedGrants", "IntendedGrant", "CountIntendedGrants",
		"ObservedEntitlements", "ObservedRuns", "CountObservedEntitlements", "RemediationPolicies", "RemediationPolicy",
		// TestIsolation_AccessModelWritersScoped
		"KeepIntent", "RecordObservedRun", "BackfillAccessModel"} {
		out[k] = true
	}
	return out
}
