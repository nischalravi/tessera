package model_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// run executes fn in tenant B's write transaction.
func run(t *testing.T, f *storetest.Fixture, fn func(e model.Env) error) error {
	t.Helper()
	return f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return fn(model.Env{Tx: c, Now: storetest.Now})
	})
}

func must(t *testing.T, f *storetest.Fixture, fn func(e model.Env) error) {
	t.Helper()
	if err := run(t, f, fn); err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, kind model.Kind, code string) {
	t.Helper()
	var me *model.Error
	if !errors.As(err, &me) || me.Kind != kind || me.Code != code {
		t.Fatalf("err = %v, want kind %d code %s", err, kind, code)
	}
}

func TestOneRootFolderPerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	var a, b store.FolderID
	must(t, f, func(e model.Env) error {
		r1, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		r2, err := e.EnsureRoot()
		a, b = r1.ID, r2.ID
		if r1.Name != "" || r1.ParentID != nil {
			t.Errorf("root = %+v", r1)
		}
		return err
	})
	if a != b {
		t.Errorf("EnsureRoot made two roots: %s, %s", a, b)
	}
	// the other tenant gets its own root
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := model.Env{Tx: c, Now: storetest.Now}.EnsureRoot()
		if err == nil && r.ID == a {
			t.Error("tenants share a root")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// the root cannot be renamed, moved, copied or deleted
	must(t, f, func(e model.Env) error {
		x := "x"
		for name, err := range map[string]error{
			"rename": func() error { _, err := e.UpdateFolder(a, model.UpdateFolderInput{Extension: &x}); return err }(),
			"move":   func() error { _, err := e.MoveFolder(a, a); return err }(),
			"copy":   func() error { _, err := e.CopyFolder(a, model.CopyInput{Parent: a}); return err }(),
			"delete": e.DeleteFolder(a),
		} {
			var me *model.Error
			if !errors.As(err, &me) || me.Code != "root_folder" {
				t.Errorf("%s of the root = %v, want root_folder", name, err)
			}
		}
		return nil
	})
}

func TestCreateAndUniqueness(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, err := e.CreateFolder(model.CreateFolderInput{Extension: "App", DisplayExtension: "The app"})
		if err != nil {
			return err
		}
		if app.Name != "App" || app.DisplayName != "The app" {
			t.Errorf("folder = %q / %q", app.Name, app.DisplayName)
		}
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "Admins"})
		if err != nil {
			return err
		}
		if g.Name != "App:Admins" || g.DisplayName != "The app:Admins" || g.Definition != store.DefinitionBasic || g.Status != "active" {
			t.Errorf("group = %+v", g)
		}
		// case-insensitive, across folders and groups
		_, err = e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		wantCode(t, err, model.Conflict, "name_taken")
		_, err = e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "ADMINS"})
		wantCode(t, err, model.Conflict, "name_taken")
		_, err = e.CreateFolder(model.CreateFolderInput{Parent: app.ID, Extension: "admins"})
		wantCode(t, err, model.Conflict, "name_taken")
		// characters and unknown parents
		_, err = e.CreateFolder(model.CreateFolderInput{Extension: "a:b"})
		wantCode(t, err, model.Invalid, "invalid_name")
		_, err = e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "has space"})
		wantCode(t, err, model.Invalid, "invalid_name")
		_, err = e.CreateGroup(model.CreateGroupInput{Folder: "00000000-0000-4000-8000-00000000dead", Extension: "x"})
		wantCode(t, err, model.NotFound, "not_found")
		_, err = e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "r", Kind: "weird"})
		wantCode(t, err, model.Invalid, "invalid_type")
		return nil
	})
	// the same names are free in the other tenant
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		_, err := model.Env{Tx: c, Now: storetest.Now}.CreateFolder(model.CreateFolderInput{Extension: "App"})
		return err
	})
	if err != nil {
		t.Errorf("tenant A creating App: %v", err)
	}
}

func aliasNames(t *testing.T, e model.Env, typ, id string) []string {
	t.Helper()
	as, err := e.Tx.GrpAliasesOf(typ, id)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range as {
		out = append(out, a.OldName)
	}
	return out
}

func TestRenameKeepsAliases(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, _ := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		sub, _ := e.CreateFolder(model.CreateFolderInput{Parent: app.ID, Extension: "sub"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: sub.ID, Extension: "users"})
		gd, _ := e.CreateGroup(model.CreateGroupInput{Folder: sub.ID, Extension: "gone"})
		if err := e.DeleteGroup(gd.ID); err != nil {
			return err
		}
		ext := "application"
		renamed, err := e.UpdateFolder(app.ID, model.UpdateFolderInput{Extension: &ext})
		if err != nil {
			return err
		}
		if renamed.Name != "application" || renamed.DisplayExtension != "application" || renamed.Version != 2 {
			t.Errorf("renamed = %+v", renamed)
		}
		sub, _ = e.Tx.GrpFolder(sub.ID)
		g, _ = e.Tx.GrpGroup(g.ID)
		gd, _ = e.Tx.GrpGroup(gd.ID)
		if sub.Name != "application:sub" || g.Name != "application:sub:users" || gd.Name != "application:sub:gone" ||
			g.DisplayName != "application:sub:users" {
			t.Errorf("subtree = %q, %q, %q (display %q)", sub.Name, g.Name, gd.Name, g.DisplayName)
		}
		if got := aliasNames(t, e, "folder", string(app.ID)); len(got) != 1 || got[0] != "app" {
			t.Errorf("folder aliases = %v", got)
		}
		if got := aliasNames(t, e, "group", string(g.ID)); len(got) != 1 || got[0] != "app:sub:users" {
			t.Errorf("group aliases = %v", got)
		}
		// the old names resolve to the objects and stay reserved
		if a, err := e.Tx.GrpAliasByName("APP:sub:users"); err != nil || a.ObjectID != string(g.ID) {
			t.Errorf("alias lookup = %v, %v", a, err)
		}
		_, err = e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		wantCode(t, err, model.Conflict, "name_reserved_by_alias")
		// renaming back takes the name (and drops the alias)
		back := "app"
		if _, err := e.UpdateFolder(app.ID, model.UpdateFolderInput{Extension: &back}); err != nil {
			return err
		}
		if got := aliasNames(t, e, "folder", string(app.ID)); len(got) != 1 || got[0] != "application" {
			t.Errorf("aliases after renaming back = %v", got)
		}
		// a case-only rename needs no alias
		up := "APP"
		if _, err := e.UpdateFolder(app.ID, model.UpdateFolderInput{Extension: &up}); err != nil {
			return err
		}
		if got := aliasNames(t, e, "folder", string(app.ID)); len(got) != 1 {
			t.Errorf("aliases after a case-only rename = %v", got)
		}
		// group rename
		gx := "members"
		g, err = e.UpdateGroup(g.ID, model.UpdateGroupInput{Extension: &gx})
		if err != nil {
			return err
		}
		if g.Name != "APP:sub:members" || g.DisplayExtension != "members" {
			t.Errorf("group = %q / %q", g.Name, g.DisplayExtension)
		}
		if got := aliasNames(t, e, "group", string(g.ID)); len(got) == 0 {
			t.Error("group rename left no alias")
		}
		return nil
	})
}

func TestMoveKeepsAliases(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		a, _ := e.CreateFolder(model.CreateFolderInput{Extension: "a"})
		b, _ := e.CreateFolder(model.CreateFolderInput{Extension: "b"})
		sub, _ := e.CreateFolder(model.CreateFolderInput{Parent: a.ID, Extension: "sub"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: sub.ID, Extension: "g"})
		moved, err := e.MoveFolder(sub.ID, b.ID)
		if err != nil {
			return err
		}
		if moved.Name != "b:sub" || *moved.ParentID != b.ID {
			t.Errorf("moved = %+v", moved)
		}
		g, _ = e.Tx.GrpGroup(g.ID)
		if g.Name != "b:sub:g" || g.FolderID != sub.ID {
			t.Errorf("group after the move = %q in %s", g.Name, g.FolderID)
		}
		if got := aliasNames(t, e, "folder", string(sub.ID)); len(got) != 1 || got[0] != "a:sub" {
			t.Errorf("folder aliases = %v", got)
		}
		if got := aliasNames(t, e, "group", string(g.ID)); len(got) != 1 || got[0] != "a:sub:g" {
			t.Errorf("group aliases = %v", got)
		}
		// into itself, into its own subtree
		_, err = e.MoveFolder(b.ID, sub.ID)
		wantCode(t, err, model.Conflict, "move_into_self")
		_, err = e.MoveFolder(b.ID, b.ID)
		wantCode(t, err, model.Conflict, "move_into_self")
		// a name clash at the destination
		if _, err := e.CreateFolder(model.CreateFolderInput{Parent: a.ID, Extension: "sub"}); err == nil {
			return errors.New("a:sub is reserved by the alias of the moved folder; creating it must fail")
		}
		other, _ := e.CreateFolder(model.CreateFolderInput{Parent: a.ID, Extension: "other"})
		clash, _ := e.CreateFolder(model.CreateFolderInput{Parent: b.ID, Extension: "other"})
		_ = clash
		_, err = e.MoveFolder(other.ID, b.ID)
		wantCode(t, err, model.Conflict, "name_taken")
		// group move
		g2, err := e.MoveGroup(g.ID, a.ID)
		if err != nil {
			return err
		}
		if g2.Name != "a:g" || g2.FolderID != a.ID {
			t.Errorf("moved group = %q", g2.Name)
		}
		if got := aliasNames(t, e, "group", string(g.ID)); len(got) != 2 {
			t.Errorf("group aliases after two moves = %v", got)
		}
		// moving a group back to where it was takes its old name back
		if _, err := e.MoveGroup(g.ID, sub.ID); err != nil {
			return err
		}
		return nil
	})
}

func TestCopy(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		a, _ := e.CreateFolder(model.CreateFolderInput{Extension: "a", Description: "src"})
		sub, _ := e.CreateFolder(model.CreateFolderInput{Parent: a.ID, Extension: "sub"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: sub.ID, Extension: "g", Kind: store.KindRole, Requestable: true})
		gd, _ := e.CreateGroup(model.CreateGroupInput{Folder: a.ID, Extension: "dead"})
		if err := e.DeleteGroup(gd.ID); err != nil {
			return err
		}
		dest, _ := e.CreateFolder(model.CreateFolderInput{Extension: "dest"})
		cp, err := e.CopyFolder(a.ID, model.CopyInput{Parent: dest.ID})
		if err != nil {
			return err
		}
		if cp.Name != "dest:a" || cp.Description != "src" || cp.ID == a.ID {
			t.Errorf("copy = %+v", cp)
		}
		cg, err := e.Tx.GrpGroupByName("dest:a:sub:g")
		if err != nil || cg.ID == g.ID || cg.Kind != store.KindRole || !cg.Requestable {
			t.Errorf("copied group = %+v, %v", cg, err)
		}
		if _, err := e.Tx.GrpGroupByName("dest:a:dead"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a deleted group was copied: %v", err)
		}
		// the source is untouched and no aliases appear
		if s, _ := e.Tx.GrpFolder(a.ID); s.Name != "a" || len(aliasNames(t, e, "folder", string(a.ID))) != 0 {
			t.Errorf("source = %+v", s)
		}
		// a second copy under the same name clashes, and nothing is written
		before, _ := e.Tx.GrpFolders(store.GrpFolderFilter{Limit: 500})
		_, err = e.CopyFolder(a.ID, model.CopyInput{Parent: dest.ID})
		wantCode(t, err, model.Conflict, "name_taken")
		after, _ := e.Tx.GrpFolders(store.GrpFolderFilter{Limit: 500})
		if len(before) != len(after) {
			t.Errorf("a refused copy wrote %d folders", len(after)-len(before))
		}
		// a copy under a new extension
		cp2, err := e.CopyFolder(a.ID, model.CopyInput{Parent: dest.ID, Extension: "a2"})
		if err != nil || cp2.Name != "dest:a2" {
			t.Errorf("copy with an extension = %+v, %v", cp2, err)
		}
		_, err = e.CopyFolder(a.ID, model.CopyInput{Parent: sub.ID})
		wantCode(t, err, model.Conflict, "copy_into_self")
		// group copy
		gc, err := e.CopyGroup(g.ID, model.CopyInput{Parent: dest.ID, Extension: "g-copy"})
		if err != nil || gc.Name != "dest:g-copy" || gc.DisplayExtension != "g-copy" {
			t.Errorf("group copy = %+v, %v", gc, err)
		}
		_, err = e.CopyGroup(gd.ID, model.CopyInput{Parent: dest.ID})
		wantCode(t, err, model.Conflict, "group_deleted")
		return nil
	})
}

func TestDeleteAndRestore(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, _ := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		err := e.DeleteFolder(app.ID)
		var me *model.Error
		if !errors.As(err, &me) || me.Code != "folder_not_empty" || me.Extra["groups"] != 1 {
			t.Errorf("DeleteFolder(non-empty) = %v", err)
		}
		if err := e.DeleteGroup(g.ID); err != nil {
			return err
		}
		if err := e.DeleteGroup(g.ID); err != nil { // idempotent
			t.Errorf("second delete = %v", err)
		}
		// deleted groups are hidden, keep their name and still block the folder
		if gs, _ := e.ListGroups(model.GroupQuery{}); len(gs) != 0 {
			t.Errorf("deleted group listed: %d", len(gs))
		}
		if gs, _ := e.ListGroups(model.GroupQuery{IncludeDeleted: true}); len(gs) != 1 {
			t.Errorf("IncludeDeleted listed %d", len(gs))
		}
		_, err = e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		wantCode(t, err, model.Conflict, "name_taken")
		wantCode(t, e.DeleteFolder(app.ID), model.Conflict, "folder_not_empty")
		d := "x"
		_, err = e.UpdateGroup(g.ID, model.UpdateGroupInput{Description: &d})
		wantCode(t, err, model.Conflict, "group_deleted")
		r, err := e.RestoreGroup(g.ID)
		if err != nil || r.Status != "active" {
			t.Errorf("restore = %+v, %v", r, err)
		}
		_, err = e.RestoreGroup(g.ID)
		wantCode(t, err, model.Conflict, "not_deleted")
		// an empty folder is deleted, and its old names are freed with it
		empty, _ := e.CreateFolder(model.CreateFolderInput{Extension: "empty"})
		ext := "empty2"
		if _, err := e.UpdateFolder(empty.ID, model.UpdateFolderInput{Extension: &ext}); err != nil {
			return err
		}
		if err := e.DeleteFolder(empty.ID); err != nil {
			return err
		}
		if _, err := e.CreateFolder(model.CreateFolderInput{Extension: "empty"}); err != nil {
			t.Errorf("the deleted folder's old name is still reserved: %v", err)
		}
		return nil
	})
}

func TestVersionAndStatus(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, _ := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		stale := int64(99)
		d := "x"
		_, err := e.UpdateGroup(g.ID, model.UpdateGroupInput{Description: &d, Version: &stale})
		wantCode(t, err, model.Conflict, "version_conflict")
		_, err = e.UpdateFolder(app.ID, model.UpdateFolderInput{Description: &d, Version: &stale})
		wantCode(t, err, model.Conflict, "version_conflict")
		v := g.Version
		dis := "disabled"
		g2, err := e.UpdateGroup(g.ID, model.UpdateGroupInput{Status: &dis, Version: &v})
		if err != nil || g2.Status != "disabled" || g2.Version != v+1 {
			t.Errorf("disable = %+v, %v", g2, err)
		}
		del := "deleted"
		_, err = e.UpdateGroup(g.ID, model.UpdateGroupInput{Status: &del})
		wantCode(t, err, model.Invalid, "invalid_status")
		long := strings.Repeat("x", model.MaxDescription+1)
		_, err = e.UpdateGroup(g.ID, model.UpdateGroupInput{Description: &long})
		wantCode(t, err, model.Invalid, "invalid_description")
		return nil
	})
}

func TestMirroredFoldersAreReadOnly(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, _ := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		other, _ := e.CreateFolder(model.CreateFolderInput{Extension: "other"})
		// what an importer would leave behind: a mirrored folder
		if err := e.Tx.SetGrpFolderManagedBy(app.ID, store.ManagedByGrouperMirror); err != nil {
			return err
		}
		x := "x"
		for name, err := range map[string]error{
			"create group": func() error {
				_, err := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "n"})
				return err
			}(),
			"create folder": func() error {
				_, err := e.CreateFolder(model.CreateFolderInput{Parent: app.ID, Extension: "n"})
				return err
			}(),
			"rename":       func() error { _, err := e.UpdateFolder(app.ID, model.UpdateFolderInput{Extension: &x}); return err }(),
			"delete":       e.DeleteFolder(app.ID),
			"delete group": e.DeleteGroup(g.ID),
			"move group":   func() error { _, err := e.MoveGroup(g.ID, other.ID); return err }(),
			"move in":      func() error { _, err := e.MoveFolder(other.ID, app.ID); return err }(),
		} {
			wantCode(t, err, model.Conflict, "folder_mirrored")
			_ = name
		}
		return nil
	})
}

func TestEventsAuditedInTheSameTransaction(t *testing.T) {
	f := storetest.TwoTenants(t)
	err := run(t, f, func(e model.Env) error {
		app, err := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		if err != nil {
			return err
		}
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		x := "x"
		_, _ = e.UpdateGroup(g.ID, model.UpdateGroupInput{Extension: &x})
		_ = e.DeleteGroup(g.ID)
		return errors.New("roll back")
	})
	if err == nil {
		t.Fatal("expected the rollback error")
	}
	// the rollback took the events with the data
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "groups.folder.created"})
		if err != nil || len(evs) != 0 {
			t.Errorf("events after a rollback = %d, %v", len(evs), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	must(t, f, func(e model.Env) error {
		app, _ := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		g, _ := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"})
		x := "x"
		_, _ = e.UpdateGroup(g.ID, model.UpdateGroupInput{Extension: &x})
		_ = e.DeleteGroup(g.ID)
		_, _ = e.RestoreGroup(g.ID)
		return nil
	})
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		for _, action := range []string{"groups.folder.created", "groups.group.created", "groups.group.renamed",
			"groups.group.deleted", "groups.group.restored"} {
			evs, err := c.AuditEvents(store.AuditFilter{Action: action})
			if err != nil || len(evs) != 1 {
				t.Errorf("%s events = %d, %v", action, len(evs), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListFolders(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		root, _ := e.EnsureRoot()
		a, _ := e.CreateFolder(model.CreateFolderInput{Extension: "a"})
		ab, _ := e.CreateFolder(model.CreateFolderInput{Parent: a.ID, Extension: "b_c"})
		_, _ = e.CreateFolder(model.CreateFolderInput{Parent: ab.ID, Extension: "d"})
		_, _ = e.CreateFolder(model.CreateFolderInput{Extension: "a_b"}) // '_' must not act as a wildcard
		count := func(q model.FolderQuery) int {
			fs, err := e.ListFolders(q)
			if err != nil {
				t.Fatal(err)
			}
			return len(fs)
		}
		if n := count(model.FolderQuery{Parent: root.ID}); n != 2 {
			t.Errorf("children of root = %d", n)
		}
		if n := count(model.FolderQuery{Parent: root.ID, Scope: "sub"}); n != 4 {
			t.Errorf("below root = %d (the root itself is left out)", n)
		}
		if n := count(model.FolderQuery{Parent: a.ID, Scope: "sub"}); n != 2 {
			t.Errorf("below a = %d", n)
		}
		if n := count(model.FolderQuery{Q: "B_C"}); n != 2 {
			t.Errorf("q=B_C matched %d", n)
		}
		if _, err := e.ListFolders(model.FolderQuery{Parent: a.ID, Scope: "weird"}); err == nil {
			t.Error("bad scope accepted")
		}
		return nil
	})
}
