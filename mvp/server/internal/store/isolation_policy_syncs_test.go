package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// policySyncsCovered lists the repository methods the tests below exercise (TestIsolation_EveryTenantTxMethodCovered).
func policySyncsCovered() map[string]bool {
	return map[string]bool{"InsertPolicySync": true, "PolicySyncByKey": true, "PolicySyncByChange": true, "ClosePolicySync": true,
		"MarkPolicySyncApplied": true, "LastPolicySync": true, "AppliedPolicySync": true, "RecentPolicySyncs": true,
		"InsertPolicySyncFinding": true, "PolicySyncFindings": true}
}

const syncSHA1, syncSHA2 = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"

// The merge sync of the policy repository (schema/0961 and 0962, issue #657) is a tenant's own: the same repository and commit
// in two tenants are two rows, a tenant sees neither the other's syncs, last synced commit nor findings, cannot file a sync
// for the other's change request (guard trigger, composite foreign key in Postgres) nor close or mark it applied, and a
// commit is filed once while its request is open or the newest applied one.
func TestIsolation_PolicySyncs(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	at := storetest.Now.Add(time.Hour)
	mk := func(changeID string, sha, kind string) *store.PolicySync {
		return &store.PolicySync{Repo: "o/policy", SHA: sha, Kind: kind, ChangeID: changeID, BundleSHA256: "b", PlanSHA256: "p",
			Prediction: `{"perms":[]}`, RequestedBy: "x"}
	}
	in := func(tn storetest.Tenant, fn func(c *store.TenantTx) error) error {
		return f.DB.InTenant(context.Background(), tn.ID, fn)
	}
	var syncA *store.PolicySync
	if err := in(f.A, func(c *store.TenantTx) error {
		syncA = mk(a.pending.ID.String(), syncSHA1, store.PolicySyncKindSync)
		return c.InsertPolicySync(syncA, at)
	}); err != nil {
		t.Fatal(err)
	}
	// B cannot file a sync for A's change request, and cannot see, close or apply A's
	if err := in(f.B, func(c *store.TenantTx) error {
		return c.InsertPolicySync(mk(a.pending.ID.String(), syncSHA1, store.PolicySyncKindSync), at)
	}); err == nil {
		t.Error("B filed a sync for A's change request")
	}
	inB(t, f, func(c *store.TenantTx) error {
		if got, err := c.PolicySyncByChange(a.pending.ID.String()); err != nil || got != nil {
			t.Errorf("B reads A's sync by change = %v, %v", got, err)
		}
		if got, err := c.PolicySyncByKey("o/policy", syncSHA1, store.PolicySyncKindSync); err != nil || got != nil {
			t.Errorf("B reads A's sync by key = %v, %v", got, err)
		}
		if got, err := c.RecentPolicySyncs("o/policy", 10); err != nil || len(got) != 0 {
			t.Errorf("B lists A's syncs = %v, %v", got, err)
		}
		if err := c.MarkPolicySyncApplied("o/policy", a.pending.ID.String(), at, store.PolicySyncVerified, "{}"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B marks A's sync applied = %v, want ErrNotFound", err)
		}
		return c.ClosePolicySync(a.pending.ID.String())
	})
	// the same commit in B is B's own row
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertPolicySync(mk(b.pending.ID.String(), syncSHA1, store.PolicySyncKindSync), at)
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.PolicySyncByChange(a.pending.ID.String())
		if err != nil || got == nil || got.ID != syncA.ID || got.ActiveKey == "" || got.AppliedAt != nil || got.CheckStatus != store.PolicySyncPending {
			t.Errorf("A's sync after B's close attempt = %+v, %v", got, err)
		}
		if got, err := c.PolicySyncByChange(b.pending.ID.String()); err != nil || got != nil {
			t.Errorf("A reads B's sync = %v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// a commit is filed once while open
	if err := in(f.A, func(c *store.TenantTx) error {
		return c.InsertPolicySync(mk(a.cooling.ID.String(), syncSHA1, store.PolicySyncKindSync), at)
	}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("a second open sync of one commit = %v, want ErrDuplicate", err)
	}

	// A applies it, with a finding; the last synced commit is A's own and B has none
	if err := in(f.A, func(c *store.TenantTx) error {
		if err := c.MarkPolicySyncApplied("o/policy", a.pending.ID.String(), at.Add(time.Minute), store.PolicySyncMismatch, `{"mismatches":1}`); err != nil {
			return err
		}
		return c.InsertPolicySyncFinding(&store.PolicySyncFinding{SyncID: syncA.ID, Kind: "permission_gain_missing", Subject: "x", Predicted: "gained", Observed: "not held"}, at)
	}); err != nil {
		t.Fatal(err)
	}
	// B cannot hang a finding on A's sync
	if err := in(f.B, func(c *store.TenantTx) error {
		return c.InsertPolicySyncFinding(&store.PolicySyncFinding{SyncID: syncA.ID, Kind: "k", Subject: "x", Predicted: "p", Observed: "o"}, at)
	}); err == nil {
		t.Error("B raised a finding on A's sync")
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		last, err := c.LastPolicySync("o/policy")
		if err != nil || last == nil || last.SHA != syncSHA1 || last.CheckStatus != store.PolicySyncMismatch || last.AppliedAt == nil {
			t.Errorf("A's last sync = %+v, %v", last, err)
		}
		fs, n, err := c.PolicySyncFindings(syncA.ID, 10)
		if err != nil || n != 1 || len(fs) != 1 || fs[0].Predicted != "gained" {
			t.Errorf("A's findings = %v, %d, %v", fs, n, err)
		}
		if got, err := c.AppliedPolicySync("o/policy", syncSHA1); err != nil || got == nil {
			t.Errorf("A's applied sync of the commit = %v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if last, err := c.LastPolicySync("o/policy"); err != nil || last != nil {
			t.Errorf("B's last sync = %v, %v (its own is not applied)", last, err)
		}
		if fs, n, err := c.PolicySyncFindings(syncA.ID, 10); err != nil || n != 0 || len(fs) != 0 {
			t.Errorf("B reads A's findings = %v, %d, %v", fs, n, err)
		}
		return nil
	})

	// a newer applied sync frees the older one's commit; a rollback never holds its commit once applied; a closed request frees its own
	if err := in(f.A, func(c *store.TenantTx) error {
		if err := c.InsertPolicySync(mk(a.cooling.ID.String(), syncSHA2, store.PolicySyncKindRollback), at.Add(2*time.Minute)); err != nil {
			return err
		}
		if err := c.MarkPolicySyncApplied("o/policy", a.cooling.ID.String(), at.Add(3*time.Minute), store.PolicySyncVerified, "{}"); err != nil {
			return err
		}
		old, err := c.PolicySyncByChange(a.pending.ID.String())
		if err != nil || old == nil || old.ActiveKey != "" {
			t.Errorf("older applied sync keeps its commit: %+v, %v", old, err)
		}
		rb, err := c.PolicySyncByChange(a.cooling.ID.String())
		if err != nil || rb == nil || rb.ActiveKey != "" {
			t.Errorf("an applied rollback holds its commit: %+v, %v", rb, err)
		}
		last, err := c.LastPolicySync("o/policy")
		if err != nil || last == nil || last.Kind != store.PolicySyncKindRollback || last.SHA != syncSHA2 {
			t.Errorf("last after the rollback = %+v, %v", last, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.ClosePolicySync(b.pending.ID.String()); err != nil {
			return err
		}
		got, err := c.PolicySyncByChange(b.pending.ID.String())
		if err != nil || got == nil || got.ActiveKey != "" {
			t.Errorf("B's closed sync = %+v, %v", got, err)
		}
		return c.InsertPolicySync(mk(b.cooling.ID.String(), syncSHA1, store.PolicySyncKindSync), at)
	})
}
