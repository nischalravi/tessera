package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group provisioning (issue #54, GR-11): a tenant's provisioners, marks,
// ownership records, runs and ops are its own. Another tenant's ids look
// nonexistent, writes and deletes by another tenant touch nothing, and a row
// that names another tenant's provisioner, group or connection is refused by
// the guard triggers (TestIsolation_GroupProvTablesGuarded in package store).

type provIDs struct {
	prov, run, op string
	group         store.GroupID
	folder        string
}

func seedGroupProv(t *testing.T, f *storetest.Fixture) map[string]provIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]provIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := provIDs{prov: "prov-" + tn.Slug, run: "run-" + tn.Slug, op: "op-" + tn.Slug, group: base[tn.Slug].g1}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			g, err := c.GrpGroup(ids.group)
			if err != nil {
				return err
			}
			ids.folder = string(g.FolderID)
			if err := c.InsertProvisioner(&store.Provisioner{ID: ids.prov, Name: "scim-" + tn.Slug, TargetType: "scim2",
				Config: json.RawMessage(`{}`), SecretEnc: []byte("sealed"), Mode: store.ProvModeAdopt, FullSchedule: "0 2 * * *",
				Failsafe: json.RawMessage(`{}`), CreatedAt: storetest.Now}); err != nil {
				return err
			}
			for _, m := range []*store.ProvMark{
				{ProvisionerID: ids.prov, ObjectType: "group", ObjectID: string(ids.group), Scope: "self", Include: true},
				{ProvisionerID: ids.prov, ObjectType: "folder", ObjectID: ids.folder, Scope: "sub", Include: true},
			} {
				if err := c.PutProvMark(m); err != nil {
					return err
				}
			}
			if err := c.PutSyncGroup(&store.SyncGroup{ProvisionerID: ids.prov, GroupID: string(ids.group), TargetName: "x", Status: "drift",
				StateCache: json.RawMessage(`{"members":[]}`)}); err != nil {
				return err
			}
			if err := c.InsertSyncRun(&store.SyncRun{ID: ids.run, ProvisionerID: ids.prov, Kind: store.RunFull, Mode: store.ProvModeAdopt,
				StartedAt: storetest.Now}); err != nil {
				return err
			}
			return c.InsertSyncOp(&store.SyncOp{ID: ids.op, ProvisionerID: ids.prov, RunID: ids.run, Op: "members", ObjectRef: "x",
				GroupID: string(ids.group), PayloadHash: "h", Status: store.OpPlanned, PlannedAt: storetest.Now})
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupProvTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupProv(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	ctx := context.Background()

	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.ReadTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			ps, err := c.Provisioners()
			if err != nil || len(ps) != 1 || ps[0].ID != ids[tn.Slug].prov || string(ps[0].SecretEnc) != "sealed" {
				t.Errorf("%s: Provisioners = %v, %v", tn.Slug, ps, err)
			}
			ms, err := c.ProvMarks(ids[tn.Slug].prov)
			if err != nil || len(ms) != 2 {
				t.Errorf("%s: ProvMarks = %d, %v", tn.Slug, len(ms), err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	notFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		// reads of A's rows see nothing
		_, err := c.Provisioner(a.prov)
		notFound("Provisioner(A's)", err)
		_, err = c.ProvisionerByName("scim-" + f.A.Slug)
		notFound("ProvisionerByName(A's)", err)
		if ms, err := c.ProvMarks(a.prov); err != nil || len(ms) != 0 {
			t.Errorf("ProvMarks(A's) = %d, %v", len(ms), err)
		}
		_, err = c.SyncGroup(a.prov, string(a.group))
		notFound("SyncGroup(A's)", err)
		if gs, err := c.SyncGroups(a.prov, 0, 0); err != nil || len(gs) != 0 {
			t.Errorf("SyncGroups(A's) = %d, %v", len(gs), err)
		}
		if gs, err := c.SyncGroupsRetryDue(a.prov, storetest.Now.Add(time.Hour), 10); err != nil || len(gs) != 0 {
			t.Errorf("SyncGroupsRetryDue(A's) = %d, %v", len(gs), err)
		}
		_, err = c.SyncRun(a.run)
		notFound("SyncRun(A's)", err)
		if rs, err := c.SyncRuns(a.prov, 10, 0); err != nil || len(rs) != 0 {
			t.Errorf("SyncRuns(A's) = %d, %v", len(rs), err)
		}
		_, err = c.LastSyncRun(a.prov, store.RunFull)
		notFound("LastSyncRun(A's)", err)
		if busy, err := c.SyncRunActive(a.prov, time.Time{}); err != nil || busy {
			t.Errorf("SyncRunActive(A's) = %v, %v", busy, err)
		}
		_, err = c.SyncOp(a.op)
		notFound("SyncOp(A's)", err)
		if os, err := c.SyncOps(a.prov, store.SyncOpFilter{}); err != nil || len(os) != 0 {
			t.Errorf("SyncOps(A's) = %d, %v", len(os), err)
		}
		if n, err := c.SyncOpCounts(a.prov); err != nil || len(n) != 0 {
			t.Errorf("SyncOpCounts(A's) = %v, %v", n, err)
		}

		// writes by B reach none of A's rows
		notFound("DeleteProvMark(A's)", c.DeleteProvMark(a.prov, "group", string(a.group)))
		notFound("DeleteProvisioner(A's)", c.DeleteProvisioner(a.prov))
		err = c.UpdateProvisioner(&store.Provisioner{ID: a.prov, Name: "hijacked", Config: json.RawMessage(`{}`), Mode: store.ProvModeActive,
			FullSchedule: "0 2 * * *", Failsafe: json.RawMessage(`{}`), Version: 1}, storetest.Now)
		notFound("UpdateProvisioner(A's)", err)
		if err := c.SetProvisionerNeedsFull(a.prov, true, true); err != nil {
			t.Error(err)
		}
		if err := c.UpdateSyncOp(&store.SyncOp{ID: a.op, Status: store.OpVerified}); err != nil {
			t.Error(err)
		}
		fin := storetest.Now
		if err := c.FinishSyncRun(&store.SyncRun{ID: a.run, Status: store.RunDone, FinishedAt: &fin}); err != nil {
			t.Error(err)
		}
		if err := c.FailAbandonedSyncRuns(a.prov, storetest.Now.Add(time.Hour), fin); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		p, err := c.Provisioner(a.prov)
		if err != nil || p.Name != "scim-"+f.A.Slug || p.Mode != store.ProvModeAdopt || p.ApproveNext || p.Version != 1 {
			t.Errorf("A's provisioner after B's writes = %+v, %v", p, err)
		}
		if ms, _ := c.ProvMarks(a.prov); len(ms) != 2 {
			t.Errorf("A has %d marks after B's delete", len(ms))
		}
		r, err := c.SyncRun(a.run)
		if err != nil || r.Status != store.RunRunning {
			t.Errorf("A's run after B's writes = %+v, %v", r, err)
		}
		o, err := c.SyncOp(a.op)
		if err != nil || o.Status != store.OpPlanned {
			t.Errorf("A's op after B's writes = %+v, %v", o, err)
		}
		if gs, err := c.SyncGroupsRetryDue(a.prov, storetest.Now.Add(time.Hour), 10); err != nil || len(gs) != 1 {
			t.Errorf("A's retry-due groups = %d, %v", len(gs), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// B names A's rows in its own: refused
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.PutProvMark(&store.ProvMark{ProvisionerID: b.prov, ObjectType: "group", ObjectID: string(a.group), Scope: "self", Include: true})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("B's mark on A's group = %v, want ErrCrossTenant", err)
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.PutProvMark(&store.ProvMark{ProvisionerID: a.prov, ObjectType: "folder", ObjectID: b.folder, Scope: "sub", Include: true})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("B's mark under A's provisioner = %v, want ErrCrossTenant", err)
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.PutSyncGroup(&store.SyncGroup{ProvisionerID: b.prov, GroupID: string(a.group), Status: "synced"})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("B's sync group on A's group = %v, want ErrCrossTenant", err)
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertSyncOp(&store.SyncOp{ID: "x", ProvisionerID: b.prov, RunID: a.run, Op: "members", ObjectRef: "x", PayloadHash: "h",
			Status: store.OpPlanned, PlannedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("B's op in A's run = %v, want ErrCrossTenant", err)
	}

	// deleting A's provisioner removes everything of it and nothing of B's
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.DeleteProvisioner(a.prov) }); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if _, err := c.Provisioner(b.prov); err != nil {
			t.Error(err)
		}
		if ms, _ := c.ProvMarks(b.prov); len(ms) != 2 {
			t.Errorf("B has %d marks", len(ms))
		}
		if _, err := c.SyncOp(b.op); err != nil {
			t.Error(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func groupProvCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		"InsertProvisioner", "Provisioner", "ProvisionerByName", "Provisioners", "UpdateProvisioner", "SetProvisionerNeedsFull",
		"DeleteProvisioner", "PutProvMark", "DeleteProvMark", "ProvMarks", "PutSyncGroup", "SyncGroup", "SyncGroups",
		"SyncGroupsRetryDue", "InsertSyncRun", "FinishSyncRun", "SyncRun", "SyncRuns", "LastSyncRun", "SyncRunActive",
		"FailAbandonedSyncRuns", "InsertSyncOp", "UpdateSyncOp", "SyncOp", "SyncOps", "SyncOpCounts",
	} {
		m[name] = true
	}
	return m
}
