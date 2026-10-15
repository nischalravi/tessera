package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Flat-file import (issue #105): a tenant sees and changes only its own
// mappings, uploads, snapshot rows and manual tasks. Both tenants use the same
// system name, so only the tenant filter tells their rows apart; a row naming
// another tenant's mapping, upload, account or identity is refused by the
// guard triggers.

const flatSystem = "hr-app"

type flatIDs struct{ mapping, upload, task string }

func seedFlatfile(t *testing.T, f *storetest.Fixture) map[string]flatIDs {
	t.Helper()
	out := map[string]flatIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		var ids flatIDs
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.PutFlatMapping(&store.FlatMapping{System: flatSystem, Name: "HR app " + tn.Slug, Owner: "owner",
				AccountCols: `{"account_id":"id","username":"login"}`, UpdatedBy: "admin", UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			m, err := c.FlatMapping(flatSystem)
			if err != nil {
				return err
			}
			ids.mapping = m.ID
			u := &store.FlatUpload{MappingID: m.ID, System: flatSystem, Kind: "accounts", Source: "api", Filename: tn.Slug + ".csv",
				SHA256: "00", SizeBytes: 10, Status: store.FlatUploadRejected, RowsTotal: 1, RowsRejected: 1, UploadedBy: "admin",
				UploadedAt: storetest.Now}
			if err := c.InsertFlatUpload(u); err != nil {
				return err
			}
			ids.upload = u.ID
			if err := c.InsertFlatUploadError(u.ID, store.FlatUploadError{Seq: 1, Row: 1, Column: "id", Code: "required", Message: "m " + tn.Slug}); err != nil {
				return err
			}
			if err := c.InsertFlatChange(u.ID, store.FlatChange{Seq: 1, Kind: "accounts", Change: "added", Label: "L " + tn.Slug}); err != nil {
				return err
			}
			if err := c.PutFlatRecord(&store.FlatRecord{System: flatSystem, Kind: "accounts", Key: "a1", Data: `{"who":"` + tn.Slug + `"}`,
				Hash: "h", UploadID: u.ID}); err != nil {
				return err
			}
			task := &store.FlatTask{System: flatSystem, Kind: "disable_account", AccountID: tn.IDs["acct:okta:alice"], AccountXID: "alice",
				AccountLabel: "alice", IdentityID: ptr(tn.IDs["alice"]), Trigger: "leaver", CreatedBy: "admin", CreatedAt: storetest.Now}
			if err := c.InsertFlatTask(task); err != nil {
				return err
			}
			ids.task = task.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func ptr[T any](v T) *T { return &v }

func TestIsolation_FlatfileReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedFlatfile(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	inB(t, f, func(c *store.TenantTx) error {
		if ms, err := c.FlatMappings(); err != nil || len(ms) != 1 || ms[0].ID != b.mapping || ms[0].Name != "HR app "+f.B.Slug {
			t.Errorf("FlatMappings = %v, %v", ms, err)
		}
		if m, err := c.FlatMapping(flatSystem); err != nil || m.ID != b.mapping {
			t.Errorf("FlatMapping = %v, %v", m, err)
		}
		if _, err := c.FlatUpload(a.upload); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FlatUpload(A's) = %v", err)
		}
		if us, err := c.FlatUploads(""); err != nil || len(us) != 1 || us[0].ID != b.upload {
			t.Errorf("FlatUploads = %v, %v", us, err)
		}
		if us, err := c.FlatUploads(flatSystem); err != nil || len(us) != 1 || us[0].ID != b.upload {
			t.Errorf("FlatUploads(system) = %v, %v", us, err)
		}
		if es, err := c.FlatUploadErrors(a.upload); err != nil || len(es) != 0 {
			t.Errorf("FlatUploadErrors(A's upload) = %v, %v", es, err)
		}
		if es, err := c.FlatUploadErrors(b.upload); err != nil || len(es) != 1 || es[0].Message != "m "+f.B.Slug {
			t.Errorf("FlatUploadErrors = %v, %v", es, err)
		}
		if cs, err := c.FlatChanges(a.upload); err != nil || len(cs) != 0 {
			t.Errorf("FlatChanges(A's upload) = %v, %v", cs, err)
		}
		if cs, err := c.FlatChanges(b.upload); err != nil || len(cs) != 1 || cs[0].Label != "L "+f.B.Slug {
			t.Errorf("FlatChanges = %v, %v", cs, err)
		}
		if rs, err := c.FlatRecords(flatSystem, "accounts"); err != nil || len(rs) != 1 || rs[0].UploadID != b.upload {
			t.Errorf("FlatRecords = %v, %v", rs, err)
		}
		if _, err := c.FlatTask(a.task); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FlatTask(A's) = %v", err)
		}
		for _, status := range []string{"", "open"} {
			if ts, err := c.FlatTasks(status); err != nil || len(ts) != 1 || ts[0].ID != b.task {
				t.Errorf("FlatTasks(%q) = %v, %v", status, ts, err)
			}
		}
		if ts, err := c.OpenFlatTasks(flatSystem); err != nil || len(ts) != 1 || ts[0].ID != b.task {
			t.Errorf("OpenFlatTasks = %v, %v", ts, err)
		}
		if _, err := c.OpenFlatTask(f.A.IDs["acct:okta:alice"], "disable_account", ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenFlatTask(A's account) = %v", err)
		}
		if x, err := c.OpenFlatTask(f.B.IDs["acct:okta:alice"], "disable_account", ""); err != nil || x.ID != b.task {
			t.Errorf("OpenFlatTask = %v, %v", x, err)
		}
		if acct, err := c.AccountByXID("okta", "alice"); err != nil || acct.ID != f.B.IDs["acct:okta:alice"] {
			t.Errorf("AccountByXID = %v, %v", acct, err)
		}
		if p, err := c.PermissionByXID("aws", "get-pii"); err != nil || p.ID != f.B.IDs["perm:aws:get-pii"] {
			t.Errorf("PermissionByXID = %v, %v", p, err)
		}
		return nil
	})
}

func TestIsolation_FlatfileWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedFlatfile(t, f)
	a := ids[f.A.Slug]
	ctx := context.Background()
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if err := c.CloseFlatTask(a.task, "closed", "b", storetest.Now, "x", nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CloseFlatTask(A's) = %v, want ErrNotFound", err)
		}
		// same key, same system: B's rows are separate from A's
		if err := c.DeleteFlatRecord(flatSystem, "accounts", "a1"); err != nil {
			t.Error(err)
		}
		return c.PutFlatMapping(&store.FlatMapping{System: flatSystem, Name: "B renamed", AccountCols: `{}`, UpdatedBy: "b", UpdatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if rs, err := c.FlatRecords(flatSystem, "accounts"); err != nil || len(rs) != 1 {
			t.Errorf("A's records after B's delete = %v, %v", rs, err)
		}
		if m, err := c.FlatMapping(flatSystem); err != nil || m.Name != "HR app "+f.A.Slug {
			t.Errorf("A's mapping after B's put = %v, %v", m, err)
		}
		if x, err := c.FlatTask(a.task); err != nil || x.Status != "open" {
			t.Errorf("A's task = %v, %v", x, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// B naming A's rows is refused by the guard triggers.
func TestIsolation_FlatfileGuardsRefuseCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedFlatfile(t, f)
	a := ids[f.A.Slug]
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"upload naming A's mapping": func(c *store.TenantTx) error {
			return c.InsertFlatUpload(&store.FlatUpload{MappingID: a.mapping, System: flatSystem, Kind: "accounts", Source: "api",
				Filename: "x.csv", SHA256: "00", Status: store.FlatUploadApplied, UploadedBy: "b", UploadedAt: storetest.Now})
		},
		"error naming A's upload": func(c *store.TenantTx) error {
			return c.InsertFlatUploadError(a.upload, store.FlatUploadError{Seq: 9, Row: 1, Code: "x", Message: "x"})
		},
		"change naming A's upload": func(c *store.TenantTx) error {
			return c.InsertFlatChange(a.upload, store.FlatChange{Seq: 9, Kind: "accounts", Change: "added", Label: "x"})
		},
		"record naming A's upload": func(c *store.TenantTx) error {
			return c.PutFlatRecord(&store.FlatRecord{System: flatSystem, Kind: "accounts", Key: "z", Data: "{}", Hash: "h", UploadID: a.upload})
		},
		"task naming A's account": func(c *store.TenantTx) error {
			return c.InsertFlatTask(&store.FlatTask{System: flatSystem, Kind: "disable_account", AccountID: f.A.IDs["acct:okta:bob"],
				AccountXID: "bob", AccountLabel: "bob", Trigger: "leaver", CreatedBy: "b", CreatedAt: storetest.Now})
		},
		"task naming A's identity": func(c *store.TenantTx) error {
			return c.InsertFlatTask(&store.FlatTask{System: flatSystem, Kind: "disable_account", AccountID: f.B.IDs["acct:okta:bob"],
				AccountXID: "bob", AccountLabel: "bob", IdentityID: ptr(f.A.IDs["bob"]), Trigger: "leaver", CreatedBy: "b", CreatedAt: storetest.Now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("got %v, want ErrCrossTenant", err)
			}
		})
	}
}

// A task ends once: a confirmed or closed task cannot be closed again, and
// the history tables cannot be rewritten.
func TestFlatfileTaskEndsOnce(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedFlatfile(t, f)
	b := ids[f.B.Slug]
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.CloseFlatTask(b.task, store.FlatTaskConfirmed, "import", storetest.Now, "", &b.upload); err != nil {
			t.Fatal(err)
		}
		if err := c.CloseFlatTask(b.task, store.FlatTaskClosed, "x", storetest.Now, "again", nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second close = %v, want ErrNotFound", err)
		}
		x, err := c.FlatTask(b.task)
		if err != nil || x.Status != store.FlatTaskConfirmed || x.ClosedUploadID == nil || *x.ClosedUploadID != b.upload || x.ClosedAt == nil {
			t.Errorf("task = %+v, %v", x, err)
		}
		if ts, err := c.OpenFlatTasks(flatSystem); err != nil || len(ts) != 0 {
			t.Errorf("open tasks = %v, %v", ts, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func flatfileCovered() map[string]bool {
	return map[string]bool{"PutFlatMapping": true, "FlatMapping": true, "FlatMappings": true, // TestIsolation_FlatfileReads / WritesScoped
		"InsertFlatUpload": true, "FlatUpload": true, "FlatUploads": true,
		"InsertFlatUploadError": true, "FlatUploadErrors": true, "InsertFlatChange": true, "FlatChanges": true,
		"PutFlatRecord": true, "FlatRecords": true, "DeleteFlatRecord": true,
		"InsertFlatTask": true, "FlatTask": true, "FlatTasks": true, "OpenFlatTasks": true, "OpenFlatTask": true,
		"CloseFlatTask": true, "AccountByXID": true, "PermissionByXID": true}
}
