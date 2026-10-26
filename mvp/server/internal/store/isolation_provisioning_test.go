package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Provisioning isolation (issue #103): targets, operations and findings are
// per tenant, and none can reference another tenant's connection or operation.
func TestIsolation_Provisioning(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aConn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.UpsertProvTarget(&store.ProvTarget{ID: "pt-a", ConnectionID: aConn, Kind: "scim", BaseURL: "https://a.example/scim/v2",
			Settings: "{}", CredentialEnc: []byte("sealed"), WriteBack: true, CreatedBy: "alice"}, now); err != nil {
			return err
		}
		if err := c.InsertProvOp(&store.ProvOp{ID: "po-a", ConnectionID: aConn, Kind: "disable_account", TargetRef: "x",
			Payload: "{}", Source: "test", IdempotencyKey: "k1", RequestedBy: "alice"}, now); err != nil {
			return err
		}
		return c.InsertProvFinding(&store.ProvFinding{ID: "pf-a", OpID: "po-a", ConnectionID: aConn, Code: "verify_mismatch",
			Severity: "high", Title: "t", Expected: "e", Observed: "o"}, now)
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ProvTarget(aConn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ProvTarget(A's) = %v", err)
		}
		if ts, err := c.ProvTargets(); err != nil || len(ts) != 0 {
			t.Errorf("ProvTargets = %v, %v", ts, err)
		}
		if _, err := c.ProvTargetBySystem("active-directory"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ProvTargetBySystem = %v", err)
		}
		if err := c.DeleteProvTarget(aConn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteProvTarget(A's) = %v", err)
		}
		if err := c.SetProvTargetWriteBack(aConn, false, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetProvTargetWriteBack(A's) = %v", err)
		}
		if _, err := c.ProvOp("po-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ProvOp(A's) = %v", err)
		}
		if _, err := c.ProvOpByKey("k1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ProvOpByKey(A's) = %v", err)
		}
		if os, err := c.ProvOps(store.ProvOpFilter{}); err != nil || len(os) != 0 {
			t.Errorf("ProvOps = %v, %v", os, err)
		}
		if os, err := c.DueProvOps(now.Add(time.Hour), 10); err != nil || len(os) != 0 {
			t.Errorf("DueProvOps = %v, %v", os, err)
		}
		if err := c.SetProvOpState("po-a", "queued", store.ProvOpState{Status: "failed", NextAttemptAt: now}, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetProvOpState(A's) = %v", err)
		}
		if n, err := c.RequeueStaleProvOps(now.Add(time.Hour), now); err != nil || n != 0 {
			t.Errorf("RequeueStaleProvOps = %d, %v", n, err)
		}
		if m, err := c.ProvOpCounts(); err != nil || len(m) != 0 {
			t.Errorf("ProvOpCounts = %v, %v", m, err)
		}
		if fs, err := c.ProvFindings("", ""); err != nil || len(fs) != 0 {
			t.Errorf("ProvFindings = %v, %v", fs, err)
		}
		if n, err := c.ResolveProvFindings("po-a", now); err != nil || n != 0 {
			t.Errorf("ResolveProvFindings(A's) = %d, %v", n, err)
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	// B referencing A's connection or A's operation is refused by the guard triggers.
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"target connection": func(c *store.TenantTx) error {
			return c.UpsertProvTarget(&store.ProvTarget{ID: "pt-b", ConnectionID: aConn, Kind: "scim", BaseURL: "https://b.example",
				Settings: "{}", CreatedBy: "b"}, now)
		},
		"op connection": func(c *store.TenantTx) error {
			return c.InsertProvOp(&store.ProvOp{ID: "po-b", ConnectionID: aConn, Kind: "disable_account", TargetRef: "x",
				Payload: "{}", Source: "test", IdempotencyKey: "kb", RequestedBy: "b"}, now)
		},
		"finding op": func(c *store.TenantTx) error {
			return c.InsertProvFinding(&store.ProvFinding{ID: "pf-b", OpID: "po-a", ConnectionID: bConn, Code: "verify_mismatch",
				Severity: "high", Title: "t", Expected: "e", Observed: "o"}, now)
		},
	} {
		if err := f.DB.InTenant(t.Context(), f.B.ID, fn); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s: err = %v, want ErrCrossTenant", name, err)
		}
	}
	// The same idempotency key is a different operation in another tenant.
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertProvOp(&store.ProvOp{ID: "po-b2", ConnectionID: bConn, Kind: "disable_account", TargetRef: "x",
			Payload: "{}", Source: "test", IdempotencyKey: "k1", RequestedBy: "b"}, now)
	})
	// A's own lifecycle.
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertProvOp(&store.ProvOp{ID: "po-a-dup", ConnectionID: aConn, Kind: "disable_account", TargetRef: "x",
			Payload: "{}", Source: "test", IdempotencyKey: "k1", RequestedBy: "alice"}, now); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("duplicate idempotency key = %v, want ErrDuplicate", err)
		}
		due, err := c.DueProvOps(now, 10)
		if err != nil || len(due) != 1 || due[0].ID != "po-a" {
			t.Fatalf("DueProvOps = %v, %v", due, err)
		}
		if err := c.SetProvOpState("po-a", "queued", store.ProvOpState{Status: "sent", Attempts: 1, NextAttemptAt: now}, now); err != nil {
			t.Errorf("SetProvOpState = %v", err)
		}
		if err := c.SetProvOpState("po-a", "queued", store.ProvOpState{Status: "failed", NextAttemptAt: now}, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetProvOpState from the wrong status = %v", err)
		}
		if n, err := c.RequeueStaleProvOps(now.Add(time.Hour), now); err != nil || n != 1 {
			t.Errorf("RequeueStaleProvOps = %d, %v", n, err)
		}
		if n, err := c.ResolveProvFindings("po-a", now); err != nil || n != 1 {
			t.Errorf("ResolveProvFindings = %d, %v", n, err)
		}
		if tg, err := c.ProvTarget(aConn); err != nil || !tg.WriteBack || string(tg.CredentialEnc) != "sealed" {
			t.Errorf("ProvTarget = %+v, %v", tg, err)
		}
		return nil
	})
}

func provisioningCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"UpsertProvTarget", "ProvTarget", "ProvTargetBySystem", "ProvTargets", "DeleteProvTarget", "SetProvTargetWriteBack",
		"InsertProvOp", "ProvOp", "ProvOpByKey", "ProvOps", "DueProvOps", "SetProvOpState", "RequeueStaleProvOps",
		"ProvOpCounts", "InsertProvFinding", "ProvFindings", "ResolveProvFindings"} {
		out[k] = true // TestIsolation_Provisioning
	}
	return out
}
