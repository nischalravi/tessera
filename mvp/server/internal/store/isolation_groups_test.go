package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Native groups (issue #44, GR-1): a tenant sees and changes only its own
// folders, groups, aliases and lists; another tenant's id looks nonexistent,
// and a row naming another tenant's folder or group is refused by the guard
// triggers. The engine tables are covered in isolation_groups_engine_test.go,
// and their triggers raw by TestIsolation_GroupsTablesGuarded.

type grpIDs struct{ root, folder, group string }

func seedGroups(t *testing.T, f *storetest.Fixture) map[string]grpIDs {
	t.Helper()
	out := map[string]grpIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		var ids grpIDs
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			root := &store.Folder{CreatedAt: storetest.Now}
			if err := c.InsertGrpFolder(root); err != nil {
				return err
			}
			pid := root.ID
			fo := &store.Folder{ParentID: &pid, Extension: "app", DisplayExtension: "app", Name: "app", DisplayName: "app",
				CreatedAt: storetest.Now}
			if err := c.InsertGrpFolder(fo); err != nil {
				return err
			}
			g := &store.NativeGroup{FolderID: fo.ID, Extension: "admins", DisplayExtension: "admins", Name: "app:admins",
				DisplayName: "app:admins", CreatedAt: storetest.Now}
			if err := c.InsertGrpGroup(g); err != nil {
				return err
			}
			if err := c.InsertGrpAlias(&store.GrpAlias{ObjectType: store.AliasGroup, ObjectID: string(g.ID), OldName: "old:admins",
				CreatedAt: storetest.Now}); err != nil {
				return err
			}
			if _, err := c.EnsureGrpMembersList(); err != nil {
				return err
			}
			ids = grpIDs{string(root.ID), string(fo.ID), string(g.ID)}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupsTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroups(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	inB(t, f, func(c *store.TenantTx) error {
		// reads return only B's rows
		fs, err := c.GrpFolders(store.GrpFolderFilter{})
		if err != nil || len(fs) != 2 {
			t.Errorf("GrpFolders = %d, %v; want B's 2", len(fs), err)
		}
		for _, x := range fs {
			if x.TenantID != f.B.ID || string(x.ID) == a.root || string(x.ID) == a.folder {
				t.Errorf("GrpFolders returned %s of tenant %s", x.ID, x.TenantID)
			}
		}
		gs, err := c.GrpGroups(store.GrpGroupFilter{IncludeDeleted: true})
		if err != nil || len(gs) != 1 || string(gs[0].ID) != b.group {
			t.Errorf("GrpGroups = %v, %v", gs, err)
		}
		if r, err := c.GrpRootFolder(); err != nil || string(r.ID) != b.root {
			t.Errorf("GrpRootFolder = %v, %v", r, err)
		}
		below, err := c.GrpFoldersBelow("app")
		if err != nil || len(below) != 0 {
			t.Errorf("GrpFoldersBelow = %v, %v", below, err)
		}
		if gb, err := c.GrpGroupsBelow("app"); err != nil || len(gb) != 1 || string(gb[0].ID) != b.group {
			t.Errorf("GrpGroupsBelow = %v, %v", gb, err)
		}
		if gi, err := c.GrpGroupsInFolder(store.FolderID(a.folder)); err != nil || len(gi) != 0 {
			t.Errorf("GrpGroupsInFolder(A's folder) = %v, %v", gi, err)
		}
		if fo, gr, err := c.GrpFolderChildCounts(store.FolderID(a.folder)); err != nil || fo+gr != 0 {
			t.Errorf("GrpFolderChildCounts(A's folder) = %d, %d, %v", fo, gr, err)
		}
		// A's ids look nonexistent
		if _, err := c.GrpFolder(store.FolderID(a.folder)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpFolder(A's) = %v", err)
		}
		if _, err := c.GrpGroup(store.GroupID(a.group)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpGroup(A's) = %v", err)
		}
		// the same name is B's own row, not A's
		if g, err := c.GrpGroupByName("APP:Admins"); err != nil || string(g.ID) != b.group {
			t.Errorf("GrpGroupByName = %v, %v", g, err)
		}
		if fo, err := c.GrpFolderByName("App"); err != nil || string(fo.ID) != b.folder {
			t.Errorf("GrpFolderByName = %v, %v", fo, err)
		}
		if al, err := c.GrpAliasByName("OLD:admins"); err != nil || al.ObjectID != b.group {
			t.Errorf("GrpAliasByName = %v, %v", al, err)
		}
		if as, err := c.GrpAliasesOf(store.AliasGroup, a.group); err != nil || len(as) != 0 {
			t.Errorf("GrpAliasesOf(A's group) = %v, %v", as, err)
		}
		// the members list id is derived per tenant
		if id, err := c.EnsureGrpMembersList(); err != nil || id != store.MembersListID(f.B.ID) || id == store.MembersListID(f.A.ID) {
			t.Errorf("EnsureGrpMembersList = %s, %v", id, err)
		}
		return nil
	})
	// writes naming A's rows from B change nothing
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.UpdateGrpFolder(&store.Folder{ID: store.FolderID(a.folder), Extension: "x", Name: "x", Version: 1}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateGrpFolder(A's) = %v", err)
		}
		if err := c.UpdateGrpGroup(&store.NativeGroup{ID: store.GroupID(a.group), Extension: "x", Name: "x", Status: "deleted", Version: 1}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateGrpGroup(A's) = %v", err)
		}
		if err := c.SetGrpFolderManagedBy(store.FolderID(a.folder), store.ManagedByGrouperMirror); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetGrpFolderManagedBy(A's) = %v", err)
		}
		if err := c.DeleteGrpFolder(store.FolderID(a.folder)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteGrpFolder(A's) = %v", err)
		}
		if err := c.DeleteGrpAlias(store.AliasGroup, a.group, "old:admins"); err != nil {
			return err
		}
		return c.DeleteGrpAliasesOf(store.AliasGroup, a.group)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if g, err := c.GrpGroup(store.GroupID(a.group)); err != nil || g.Status != "active" || g.Name != "app:admins" || g.Version != 1 {
			t.Errorf("A's group after B's writes = %+v, %v", g, err)
		}
		if _, err := c.GrpFolder(store.FolderID(a.folder)); err != nil {
			t.Errorf("A's folder after B's delete = %v", err)
		}
		if al, err := c.GrpAliasByName("old:admins"); err != nil || al.ObjectID != a.group {
			t.Errorf("A's alias after B's deletes = %v, %v", al, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_GroupsCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroups(t, f)
	a := ids[f.A.Slug]
	pa := store.FolderID(a.folder)
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"folder with A's parent": func(c *store.TenantTx) error {
			return c.InsertGrpFolder(&store.Folder{ParentID: &pa, Extension: "x", DisplayExtension: "x", Name: "x", DisplayName: "x", CreatedAt: storetest.Now})
		},
		"group in A's folder": func(c *store.TenantTx) error {
			return c.InsertGrpGroup(&store.NativeGroup{FolderID: pa, Extension: "x", DisplayExtension: "x", Name: "x", DisplayName: "x", CreatedAt: storetest.Now})
		},
		"alias of A's group": func(c *store.TenantTx) error {
			return c.InsertGrpAlias(&store.GrpAlias{ObjectType: store.AliasGroup, ObjectID: a.group, OldName: "stolen", CreatedAt: storetest.Now})
		},
		"alias of A's folder": func(c *store.TenantTx) error {
			return c.InsertGrpAlias(&store.GrpAlias{ObjectType: store.AliasFolder, ObjectID: a.folder, OldName: "stolen2", CreatedAt: storetest.Now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	// a row stamped with the other tenant is refused too
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertGrpFolder(&store.Folder{TenantID: f.A.ID, Extension: "y", Name: "y"})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("insert stamped with A = %v, want ErrCrossTenant", err)
	}
}

func TestIsolation_GroupsOneRootPerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedGroups(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertGrpFolder(&store.Folder{CreatedAt: storetest.Now}) // a second root
	})
	if err == nil {
		t.Error("a second root folder was accepted")
	}
}

func groupsCovered() map[string]bool {
	return map[string]bool{"InsertGrpFolder": true, "InsertGrpGroup": true, "InsertGrpAlias": true, // CrossTenantReferences
		"GrpFolder": true, "GrpGroup": true, "GrpRootFolder": true, "GrpFolderByName": true, "GrpGroupByName": true, // GroupsTables
		"GrpFolders": true, "GrpGroups": true, "GrpFoldersBelow": true, "GrpGroupsBelow": true, "GrpGroupsInFolder": true,
		"GrpFolderChildCounts": true, "GrpAliasByName": true, "GrpAliasesOf": true, "EnsureGrpMembersList": true,
		"UpdateGrpFolder": true, "UpdateGrpGroup": true, "DeleteGrpFolder": true, "SetGrpFolderManagedBy": true, "DeleteGrpAlias": true, "DeleteGrpAliasesOf": true}
}
