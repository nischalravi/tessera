package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func groupPurgeCovered() map[string]bool {
	return map[string]bool{"DeleteGrpGroup": true, "DeleteGrpLevel": true, "GrpGroupUsers": true, "GrpGroupRefs": true,
		"GrpFolderDeletedGroupCount": true}
}

// TestIsolation_GroupPurge: the purge statements see and change only the
// calling tenant's rows, even when handed another tenant's ids.
func TestIsolation_GroupPurge(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroups(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]

	// the other group of tenant A's folder, deleted, and a nest of A's group in it
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		g := &store.NativeGroup{FolderID: store.FolderID(a.folder), Extension: "gone", DisplayExtension: "gone", Name: "app:gone",
			DisplayName: "app:gone", Status: store.GroupDeleted, CreatedAt: storetest.Now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		n, err := c.GrpFolderDeletedGroupCount(store.FolderID(a.folder))
		if err != nil || n != 1 {
			t.Errorf("A's deleted group count = %d, %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	inB(t, f, func(c *store.TenantTx) error {
		if n, err := c.GrpFolderDeletedGroupCount(store.FolderID(a.folder)); err != nil || n != 0 {
			t.Errorf("GrpFolderDeletedGroupCount(A's folder) from B = %d, %v", n, err)
		}
		if us, err := c.GrpGroupUsers(store.GroupID(a.group)); err != nil || len(us) != 0 {
			t.Errorf("GrpGroupUsers(A's group) = %v, %v", us, err)
		}
		if rs, err := c.GrpGroupRefs(store.GroupID(a.group)); err != nil || len(rs) != 0 {
			t.Errorf("GrpGroupRefs(A's group) = %v, %v", rs, err)
		}
		if err := c.DeleteGrpGroup(store.GroupID(a.group)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteGrpGroup(A's) = %v, want ErrNotFound", err)
		}
		if err := c.DeleteGrpLevel(store.GroupID(a.group)); err != nil {
			t.Errorf("DeleteGrpLevel(A's) = %v", err)
		}
		// B's own row is deleted
		if err := c.DeleteGrpGroup(store.GroupID(b.group)); err != nil {
			t.Errorf("DeleteGrpGroup(B's) = %v", err)
		}
		return nil
	})
	// A's group is still there
	err = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.GrpGroup(store.GroupID(a.group)); err != nil {
			t.Errorf("A's group = %v after B's purge calls", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
