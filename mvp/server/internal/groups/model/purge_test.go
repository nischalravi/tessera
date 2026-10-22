package model_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func mkFolder(t *testing.T, e model.Env, parent store.FolderID, ext string) *store.Folder {
	t.Helper()
	f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func mkGroup(t *testing.T, e model.Env, folder store.FolderID, ext string) *store.NativeGroup {
	t.Helper()
	g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestFolderNotEmptyCountsDeletedGroups(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, app.ID, "g")
		mkGroup(t, e, app.ID, "h")
		if err := e.DeleteGroup(g.ID); err != nil {
			return err
		}
		err := e.DeleteFolder(app.ID)
		wantCode(t, err, model.Conflict, "folder_not_empty")
		for _, want := range []string{"0 subfolder(s)", "2 group(s) (1 deleted, restore or purge it)", "0 attribute definition(s)"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("message %q lacks %q", err.Error(), want)
			}
		}
		if err.(*model.Error).Extra["deleted_groups"] != 1 {
			t.Errorf("extra = %v", err.(*model.Error).Extra)
		}
		return nil
	})
}

func TestPurgeGroup(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, app.ID, "g")
		member := mkGroup(t, e, app.ID, "member")
		if _, err := e.AddMember(g.ID, model.MemberInput{Group: member.ID}); err != nil {
			return err
		}
		x := "g2"
		if _, err := e.UpdateGroup(g.ID, model.UpdateGroupInput{Extension: &x}); err != nil { // leaves an alias
			return err
		}
		// only a deleted group can be purged
		wantCode(t, e.PurgeGroup(g.ID), model.Conflict, "not_deleted")
		if err := e.DeleteGroup(g.ID); err != nil {
			return err
		}
		if err := e.PurgeGroup(g.ID); err != nil {
			return err
		}
		if _, err := e.Group(g.ID); err == nil {
			t.Error("the purged group is still there")
		}
		wantCode(t, e.PurgeGroup(g.ID), model.NotFound, "not_found")
		// the purged group's names are free again, its member is untouched
		if _, err := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g"}); err != nil {
			t.Errorf("the old name is still reserved: %v", err)
		}
		if _, err := e.CreateGroup(model.CreateGroupInput{Folder: app.ID, Extension: "g2"}); err != nil {
			t.Errorf("the name is still reserved: %v", err)
		}
		if _, err := e.Group(member.ID); err != nil {
			t.Errorf("the member group went too: %v", err)
		}
		if deps, _ := e.Tx.GrpDepsAll(); len(deps) != 0 {
			t.Errorf("edges left: %v", deps)
		}
		return nil
	})
	// the history stays: the audit event and the group's events
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "groups.group.purged"})
		if err != nil || len(evs) != 1 {
			t.Errorf("groups.group.purged events = %d, %v", len(evs), err)
		}
		if evs, err := c.AuditEvents(store.AuditFilter{Action: "groups.group.deleted"}); err != nil || len(evs) != 1 {
			t.Errorf("groups.group.deleted events = %d, %v", len(evs), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeRefusedWhileAnotherGroupUsesIt(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app := mkFolder(t, e, "", "app")
		child := mkGroup(t, e, app.ID, "child")
		parent := mkGroup(t, e, app.ID, "parent")
		factor := mkGroup(t, e, app.ID, "factor")
		other := mkGroup(t, e, app.ID, "other")
		comp := mkGroup(t, e, app.ID, "comp")
		if _, err := e.AddMember(parent.ID, model.MemberInput{Group: child.ID}); err != nil {
			return err
		}
		if _, _, err := e.ConvertToComposite(comp.ID, model.CompositeInput{Op: store.CompUnion, Factors: []store.GroupID{factor.ID, other.ID}}); err != nil {
			return err
		}
		for _, g := range []*store.NativeGroup{child, factor} {
			if err := e.DeleteGroup(g.ID); err != nil {
				return err
			}
		}
		err := e.PurgeGroup(child.ID)
		wantCode(t, err, model.Conflict, "group_in_use")
		if got := err.(*model.Error).Extra["groups"]; !slices.Equal(got.([]string), []string{"app:parent"}) {
			t.Errorf("groups = %v", got)
		}
		wantCode(t, e.PurgeGroup(factor.ID), model.Conflict, "group_in_use")
		// once nothing uses it, the purge goes through
		if _, err := e.RemoveMember(parent.ID, string(child.ID)); err != nil {
			return err
		}
		if err := e.PurgeGroup(child.ID); err != nil {
			t.Errorf("purge after removing the member: %v", err)
		}
		// a composite is purged with its factor rows
		if err := e.DeleteGroup(comp.ID); err != nil {
			return err
		}
		if err := e.PurgeGroup(comp.ID); err != nil {
			t.Errorf("purge a composite: %v", err)
		}
		if err := e.PurgeGroup(factor.ID); err != nil {
			t.Errorf("purge the factor once the composite is gone: %v", err)
		}
		return nil
	})
}

func TestPurgeChecksLikeDelete(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, app.ID, "g")
		if err := e.DeleteGroup(g.ID); err != nil {
			return err
		}
		if err := e.Tx.SetGrpFolderManagedBy(app.ID, store.ManagedByGrouperMirror); err != nil {
			return err
		}
		wantCode(t, e.PurgeGroup(g.ID), model.Conflict, "folder_mirrored")
		if err := e.Tx.SetGrpFolderManagedBy(app.ID, store.ManagedByUI); err != nil {
			return err
		}
		// settings that name it the reviewer, in another folder, stop the purge; settings it owns go with it
		rev := mkGroup(t, e, app.ID, "rev")
		if err := e.DeleteGroup(rev.ID); err != nil {
			return err
		}
		other := mkFolder(t, e, "", "other")
		if err := e.Tx.SetGrpAttestSettings(&store.GrpAttestSettings{OwnerType: "folder", OwnerID: string(other.ID), IntervalDays: 30,
			WindowDays: 7, ReviewerType: "group", ReviewerGroup: &rev.ID, ReminderDays: "[]", OverdueAction: "none", Enabled: true,
			UpdatedBy: "t", UpdatedAt: e.Now}); err != nil {
			return err
		}
		wantCode(t, e.PurgeGroup(rev.ID), model.Conflict, "group_referenced")
		if err := e.Tx.SetGrpGroupPolicy(g.ID, store.ManagedByPolicyRepo, "policy/app.cedar"); err != nil {
			return err
		}
		wantCode(t, e.PurgeGroup(g.ID), model.Conflict, "policy_managed")
		return nil
	})
}

// tree builds app/{a/{g1,g2}, b/{g3}} and nests g2 in g1.
func tree(t *testing.T, e model.Env) (app, a, b *store.Folder, gs []*store.NativeGroup) {
	t.Helper()
	app = mkFolder(t, e, "", "app")
	a = mkFolder(t, e, app.ID, "a")
	b = mkFolder(t, e, app.ID, "b")
	gs = []*store.NativeGroup{mkGroup(t, e, a.ID, "g1"), mkGroup(t, e, a.ID, "g2"), mkGroup(t, e, b.ID, "g3")}
	if _, err := e.AddMember(gs[0].ID, model.MemberInput{Group: gs[1].ID}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestDeleteFolderRecursive(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, _, _, gs := tree(t, e)
		keep := mkFolder(t, e, "", "keep")
		kg := mkGroup(t, e, keep.ID, "kg")
		if err := e.DeleteGroup(gs[2].ID); err != nil { // a deleted group goes too
			return err
		}
		d, err := attrs.CreateDef(e.Attrs(), attrs.DefInput{Folder: app.ID, Extension: "flag", AssignTo: []string{store.AttrOwnerGroup}})
		if err != nil || d == nil {
			return fmt.Errorf("attr def: %v", err)
		}
		plan, err := e.PlanFolderDelete(app.ID)
		if err != nil {
			return err
		}
		if plan.Folders != 3 || plan.ActiveGroups != 2 || plan.DeletedGroups != 1 || plan.AttrDefs != 1 || plan.GroupsWithMembers != 1 ||
			len(plan.Blockers) != 0 || !plan.NeedsApproval {
			t.Errorf("plan = %+v", plan)
		}
		if names := plan.Subtree[0].Name + "," + plan.Subtree[len(plan.Subtree)-1].Name; names != "app:a,app" && names != "app:b,app" {
			t.Errorf("subtree is not deepest first: %v", names)
		}
		_, res, err := e.DeleteFolderRecursive(app.ID)
		if err != nil {
			return err
		}
		if res.Folders != 3 || res.Groups != 3 || res.AttrDefs != 1 || res.Memberships != 1 {
			t.Errorf("result = %+v", res)
		}
		if _, err := e.Folder(app.ID); err == nil {
			t.Error("the folder is still there")
		}
		for _, g := range gs {
			if _, err := e.Group(g.ID); err == nil {
				t.Errorf("group %s is still there", g.Name)
			}
		}
		// the other folder is untouched and the names are free again
		if _, err := e.Group(kg.ID); err != nil {
			t.Errorf("an unrelated group went: %v", err)
		}
		mkFolder(t, e, "", "app")
		return nil
	})
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "groups.folder.deleted_recursive"})
		if err != nil || len(evs) != 1 {
			t.Fatalf("groups.folder.deleted_recursive events = %d, %v", len(evs), err)
		}
		if n, _ := c.AuditEvents(store.AuditFilter{Action: "groups.group.purged"}); len(n) != 3 {
			t.Errorf("purged events = %d", len(n))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func blockerCodes(p *model.DeletePlan) []string {
	var out []string
	for _, b := range p.Blockers {
		out = append(out, b.Kind+":"+b.Code)
	}
	slices.Sort(out)
	return out
}

func TestDeleteFolderRecursiveRefusals(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		app, a, _, gs := tree(t, e)
		// used from outside the tree: a group elsewhere has g3 as a member
		keep := mkFolder(t, e, "", "keep")
		outside := mkGroup(t, e, keep.ID, "outside")
		if _, err := e.AddMember(outside.ID, model.MemberInput{Group: gs[2].ID}); err != nil {
			return err
		}
		plan, err := e.PlanFolderDelete(app.ID)
		if err != nil {
			return err
		}
		if got := blockerCodes(plan); !slices.Equal(got, []string{"group:used_outside"}) {
			t.Errorf("blockers = %v", got)
		}
		_, _, err = e.DeleteFolderRecursive(app.ID)
		wantCode(t, err, model.Conflict, "recursive_delete_blocked")
		if !strings.Contains(err.Error(), "app:b:g3") || !strings.Contains(err.Error(), "keep:outside") {
			t.Errorf("the message does not say which: %v", err)
		}
		if _, err := e.Group(gs[0].ID); err != nil {
			t.Errorf("a refused delete removed something: %v", err)
		}
		// a folder or group that is not UI-managed
		if _, err := e.RemoveMember(outside.ID, string(gs[2].ID)); err != nil {
			return err
		}
		if err := e.Tx.SetGrpFolderManagedBy(a.ID, store.ManagedByLoader); err != nil {
			return err
		}
		plan, _ = e.PlanFolderDelete(app.ID)
		if got := blockerCodes(plan); !slices.Equal(got, []string{"folder:not_ui_managed"}) {
			t.Errorf("blockers = %v", got)
		}
		wantCode(t, func() error { _, _, err := e.DeleteFolderRecursive(app.ID); return err }(), model.Conflict, "recursive_delete_blocked")
		if err := e.Tx.SetGrpFolderManagedBy(a.ID, store.ManagedByUI); err != nil {
			return err
		}
		// an attribute definition assigned to something outside
		d, err := attrs.CreateDef(e.Attrs(), attrs.DefInput{Folder: app.ID, Extension: "flag", AssignTo: []string{store.AttrOwnerGroup}})
		if err != nil {
			return err
		}
		if _, err := attrs.Assign(e.Attrs(), attrs.AssignInput{Owner: attrs.Owner{Type: store.AttrOwnerGroup, ID: string(outside.ID)},
			Name: nameOf(t, e, d)}); err != nil {
			return err
		}
		plan, _ = e.PlanFolderDelete(app.ID)
		if got := blockerCodes(plan); !slices.Equal(got, []string{"attr_def:used_outside"}) {
			t.Errorf("blockers = %v", got)
		}
		// a loader that targets a folder of the tree
		if err := e.Tx.InsertGrpLoader(&store.GrpLoader{Name: "Staff", Type: "csv", Config: `{"path":"a.csv","group":"g","subject_column":"id"}`,
			TargetFolder: a.ID, NameTemplate: "{{.Name}}", OnMissingGroup: "empty", Schedule: "@daily", Failsafe: `{}`,
			CreatedAt: e.Now, UpdatedAt: e.Now}); err != nil {
			return err
		}
		plan, _ = e.PlanFolderDelete(app.ID)
		if got := blockerCodes(plan); !slices.Contains(got, "folder:referenced") {
			t.Errorf("blockers = %v", got)
		}
		// the root cannot be deleted this way
		root, _ := e.EnsureRoot()
		_, err = e.PlanFolderDelete(root.ID)
		wantCode(t, err, model.Conflict, "root_folder")
		return nil
	})
}

func nameOf(t *testing.T, e model.Env, d *store.GrpAttrDef) string {
	t.Helper()
	n := &store.GrpAttrName{DefID: d.ID, Extension: "on", DisplayExtension: "on", CreatedAt: e.Now}
	if err := e.Tx.InsertGrpAttrName(n); err != nil {
		t.Fatal(err)
	}
	return n.ID
}

func TestRecursiveDeleteApprovalThreshold(t *testing.T) {
	f := storetest.TwoTenants(t)
	must(t, f, func(e model.Env) error {
		small := mkFolder(t, e, "", "small")
		mkGroup(t, e, small.ID, "g")
		p, err := e.PlanFolderDelete(small.ID)
		if err != nil || p.NeedsApproval {
			t.Errorf("a small empty tree needs approval: %+v, %v", p, err)
		}
		big := mkFolder(t, e, "", "big")
		for i := 0; i <= model.RecursiveApprovalGroups; i++ {
			mkGroup(t, e, big.ID, fmt.Sprintf("g%d", i))
		}
		p, err = e.PlanFolderDelete(big.ID)
		if err != nil || !p.NeedsApproval || p.TotalGroups() != model.RecursiveApprovalGroups+1 {
			t.Errorf("a big tree needs no approval: %+v, %v", p, err)
		}
		// exactly the limit does not
		if err := e.DeleteGroup(store.GroupID(p.Groups[0].ID)); err != nil {
			return err
		}
		if err := e.PurgeGroup(p.Groups[0].ID); err != nil {
			return err
		}
		if p, _ = e.PlanFolderDelete(big.ID); p.NeedsApproval {
			t.Errorf("%d groups need approval", p.TotalGroups())
		}
		// a group with members does
		m := mkFolder(t, e, "", "populated")
		g1, g2 := mkGroup(t, e, m.ID, "g1"), mkGroup(t, e, m.ID, "g2")
		if _, err := e.AddMember(g1.ID, model.MemberInput{Group: g2.ID}); err != nil {
			return err
		}
		if p, _ = e.PlanFolderDelete(m.ID); !p.NeedsApproval || p.GroupsWithMembers != 1 {
			t.Errorf("a populated tree needs no approval: %+v", p)
		}
		return nil
	})
}

func TestPurgeAndRecursiveAreTenantScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	var aGroup store.GroupID
	var aFolder store.FolderID
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		e := model.Env{Tx: c, Now: storetest.Now}
		fo := mkFolder(t, e, "", "app")
		g := mkGroup(t, e, fo.ID, "g")
		aGroup, aFolder = g.ID, fo.ID
		return e.DeleteGroup(g.ID)
	}); err != nil {
		t.Fatal(err)
	}
	must(t, f, func(e model.Env) error { // tenant B cannot see, purge or delete A's rows
		wantCode(t, e.PurgeGroup(aGroup), model.NotFound, "not_found")
		_, err := e.PlanFolderDelete(aFolder)
		wantCode(t, err, model.NotFound, "not_found")
		_, _, err = e.DeleteFolderRecursive(aFolder)
		wantCode(t, err, model.NotFound, "not_found")
		return nil
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.GrpGroup(aGroup); err != nil {
			t.Errorf("A's group went: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
