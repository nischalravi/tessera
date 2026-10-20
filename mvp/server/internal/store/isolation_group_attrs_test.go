package store_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Attribute framework (issue #50, GR-7): definitions, names, actions, the
// implication closures, assignments and values of a tenant are its own. Another
// tenant's ids look nonexistent, the same names can exist in two tenants, and a
// row that names another tenant's folder, definition, name, action, owner or
// identity is refused by the guard triggers.

type attrIDs struct {
	folder              store.FolderID
	group               store.GroupID
	ident               int64
	membership          string
	def, name1, name2   string
	action              string
	assign, assignOnOne string
	value               string
}

func seedAttrs(t *testing.T, f *storetest.Fixture) map[string]attrIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]attrIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := attrIDs{group: base[tn.Slug].g1, ident: base[tn.Slug].ident, membership: base[tn.Slug].dm}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fo, err := c.GrpFolderByName("app")
			if err != nil {
				return err
			}
			ids.folder = fo.ID
			d := &store.GrpAttrDef{FolderID: fo.ID, Extension: "tags", DisplayExtension: "tags", AttrType: store.AttrTypeAttr,
				ValueType: store.AttrValueString, MultiAssign: true, MultiValued: true,
				AssignTo: []string{store.AttrOwnerGroup, store.AttrOwnerAssignment}, CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrDef(d); err != nil {
				return err
			}
			n1 := &store.GrpAttrName{DefID: d.ID, Extension: "one", DisplayExtension: "one", CreatedAt: storetest.Now}
			n2 := &store.GrpAttrName{DefID: d.ID, Extension: "two", DisplayExtension: "two", CreatedAt: storetest.Now}
			act := &store.GrpAttrAction{DefID: d.ID, Name: "assign", CreatedAt: storetest.Now}
			for _, step := range []error{c.InsertGrpAttrName(n1), c.InsertGrpAttrName(n2), c.InsertGrpAttrAction(act),
				c.ReplaceGrpAttrImplies(store.ImpliesNames, d.ID, []store.GrpAttrImplies{{DefID: d.ID, From: n1.ID, To: n2.ID, Direct: true}})} {
				if step != nil {
					return step
				}
			}
			a := &store.GrpAttrAssign{DefID: d.ID, NameID: n1.ID, ActionID: act.ID, OwnerType: store.AttrOwnerGroup,
				OwnerID: string(ids.group), CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrAssign(a); err != nil {
				return err
			}
			a2 := &store.GrpAttrAssign{DefID: d.ID, NameID: n2.ID, ActionID: act.ID, OwnerType: store.AttrOwnerAssignment,
				OwnerID: a.ID, CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrAssign(a2); err != nil {
				return err
			}
			s := "v1"
			v := &store.GrpAttrValue{AssignID: a.ID, ValueString: &s, Key: "s:v1", CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrValue(v); err != nil {
				return err
			}
			ids.def, ids.name1, ids.name2, ids.action, ids.assign, ids.assignOnOne, ids.value = d.ID, n1.ID, n2.ID, act.ID, a.ID, a2.ID, v.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupAttrTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedAttrs(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	notFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpAttrDef(a.def)
		notFound("GrpAttrDef(A's)", err)
		if d, err := c.GrpAttrDef(b.def); err != nil || d.Name() != "app:tags" || !d.MultiAssign || len(d.AssignTo) != 2 {
			t.Errorf("GrpAttrDef(B's) = %+v, %v", d, err)
		}
		_, err = c.GrpAttrDefByExtension(a.folder, "tags")
		notFound("GrpAttrDefByExtension(A's folder)", err)
		if ds, err := c.GrpAttrDefs(store.GrpAttrDefFilter{}); err != nil || len(ds) != 1 || ds[0].ID != b.def {
			t.Errorf("GrpAttrDefs = %v, %v; want only B's", ds, err)
		}
		if ds, err := c.GrpAttrDefs(store.GrpAttrDefFilter{Prefix: "app", Q: "TAG"}); err != nil || len(ds) != 1 {
			t.Errorf("GrpAttrDefs(app, tag) = %v, %v", ds, err)
		}
		if n, err := c.GrpAttrDefCountIn(a.folder); err != nil || n != 0 {
			t.Errorf("GrpAttrDefCountIn(A's folder) = %d, %v", n, err)
		}
		_, err = c.GrpAttrName(a.name1)
		notFound("GrpAttrName(A's)", err)
		_, err = c.GrpAttrNameByExtension(a.def, "one")
		notFound("GrpAttrNameByExtension(A's def)", err)
		if ns, err := c.GrpAttrNames(a.def, "", 0, 0); err != nil || len(ns) != 0 {
			t.Errorf("GrpAttrNames(A's def) = %d, %v", len(ns), err)
		}
		_, err = c.GrpAttrAction(a.action)
		notFound("GrpAttrAction(A's)", err)
		_, err = c.GrpAttrActionByName(a.def, "assign")
		notFound("GrpAttrActionByName(A's def)", err)
		if as, err := c.GrpAttrActionsOf(a.def); err != nil || len(as) != 0 {
			t.Errorf("GrpAttrActionsOf(A's def) = %d, %v", len(as), err)
		}
		if rows, err := c.GrpAttrImpliesOfDef(store.ImpliesNames, a.def); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrImpliesOfDef(A's) = %d, %v", len(rows), err)
		}
		if rows, err := c.GrpAttrImpliesOf(store.ImpliesNames, a.name1); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrImpliesOf(A's) = %d, %v", len(rows), err)
		}
		if rows, err := c.GrpAttrImpliesOf(store.ImpliesNames, b.name1); err != nil || len(rows) != 1 || rows[0].To != b.name2 || !rows[0].Direct {
			t.Errorf("GrpAttrImpliesOf(B's) = %v, %v", rows, err)
		}
		if rows, err := c.GrpAttrImpliesOfDef(store.ImpliesActions, a.def); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrImpliesOfDef(actions, A's) = %d, %v", len(rows), err)
		}
		if rows, err := c.GrpAttrImpliesOf(store.ImpliesActions, a.action); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrImpliesOf(actions, A's) = %d, %v", len(rows), err)
		}
		_, err = c.GrpAttrAssign(a.assign)
		notFound("GrpAttrAssign(A's)", err)
		if rows, err := c.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: store.AttrOwnerGroup, OwnerID: string(a.group)}); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrAssigns(A's group) = %d, %v", len(rows), err)
		}
		if n, err := c.GrpAttrAssignCount(a.def, "", ""); err != nil || n != 0 {
			t.Errorf("GrpAttrAssignCount(A's def) = %d, %v", n, err)
		}
		if rows, err := c.GrpAttrAssignsByValue(a.name1, store.AttrOwnerGroup, "s:v1"); err != nil || len(rows) != 0 {
			t.Errorf("GrpAttrAssignsByValue(A's name) = %d, %v", len(rows), err)
		}
		if rows, err := c.GrpAttrAssignsByValue(b.name1, store.AttrOwnerGroup, "s:v1"); err != nil || len(rows) != 1 || rows[0].ID != b.assign {
			t.Errorf("GrpAttrAssignsByValue(B's name) = %v, %v", rows, err)
		}
		if vs, err := c.GrpAttrValuesOf(a.assign); err != nil || len(vs) != 0 {
			t.Errorf("GrpAttrValuesOf(A's) = %d, %v", len(vs), err)
		}
		if vs, err := c.GrpAttrValuesOf(b.assign); err != nil || len(vs) != 1 || vs[0].ID != b.value {
			t.Errorf("GrpAttrValuesOf(B's) = %v, %v", vs, err)
		}
		if n, err := c.DeleteGrpAttrValuesOf(a.assign); err != nil || n != 0 {
			t.Errorf("DeleteGrpAttrValuesOf(A's) = %d, %v", n, err)
		}
		notFound("UpdateGrpAttrDef(A's)", c.UpdateGrpAttrDef(&store.GrpAttrDef{ID: a.def, Version: 1}))
		notFound("UpdateGrpAttrName(A's)", c.UpdateGrpAttrName(&store.GrpAttrName{ID: a.name1}))
		notFound("UpdateGrpAttrAssign(A's)", c.UpdateGrpAttrAssign(&store.GrpAttrAssign{ID: a.assign, Version: 1}))
		notFound("DeleteGrpAttrAssign(A's)", c.DeleteGrpAttrAssign(a.assign))
		notFound("DeleteGrpAttrAction(A's)", c.DeleteGrpAttrAction(a.action))
		notFound("DeleteGrpAttrName(A's)", c.DeleteGrpAttrName(a.name1))
		notFound("DeleteGrpAttrDef(A's)", c.DeleteGrpAttrDef(a.def))
		return nil
	})
	// B's replace of its own closure leaves A's rows alone
	inB(t, f, func(c *store.TenantTx) error {
		return c.ReplaceGrpAttrImplies(store.ImpliesNames, b.def, nil)
	})
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if rows, err := c.GrpAttrImpliesOfDef(store.ImpliesNames, a.def); err != nil || len(rows) != 1 {
			t.Errorf("A's closure after B's replace = %d rows, %v", len(rows), err)
		}
		if _, err := c.GrpAttrAssign(a.assign); err != nil {
			t.Errorf("A's assignment: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the same names and actions in both tenants are fine; repeating one within a tenant is not
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.InsertGrpAttrDef(&store.GrpAttrDef{FolderID: b.folder, Extension: "other", DisplayExtension: "other",
			AttrType: store.AttrTypeAttr, ValueType: store.AttrValueMarker, AssignTo: []string{}, CreatedAt: storetest.Now}); err != nil {
			t.Errorf("a second definition: %v", err)
		}
		if err := c.InsertGrpAttrDef(&store.GrpAttrDef{FolderID: b.folder, Extension: "TAGS", DisplayExtension: "TAGS",
			AttrType: store.AttrTypeAttr, ValueType: store.AttrValueMarker, AssignTo: []string{}, CreatedAt: storetest.Now}); err == nil {
			t.Error("a definition was made twice in one folder (case-insensitively)")
		}
		if err := c.InsertGrpAttrName(&store.GrpAttrName{DefID: b.def, Extension: "One", DisplayExtension: "One", CreatedAt: storetest.Now}); err == nil {
			t.Error("a name was made twice in one definition")
		}
		return nil
	})
}

func TestIsolation_GroupAttrCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedAttrs(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	assign := func(mod func(r *store.GrpAttrAssign)) func(c *store.TenantTx) error {
		return func(c *store.TenantTx) error {
			r := &store.GrpAttrAssign{DefID: b.def, NameID: b.name1, ActionID: b.action, OwnerType: store.AttrOwnerGroup,
				OwnerID: string(b.group), CreatedAt: storetest.Now}
			mod(r)
			return c.InsertGrpAttrAssign(r)
		}
	}
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"definition in A's folder": func(c *store.TenantTx) error {
			return c.InsertGrpAttrDef(&store.GrpAttrDef{FolderID: a.folder, Extension: "x", DisplayExtension: "x",
				AttrType: store.AttrTypeAttr, ValueType: store.AttrValueMarker, AssignTo: []string{}, CreatedAt: storetest.Now})
		},
		"definition stamped with A": func(c *store.TenantTx) error {
			return c.InsertGrpAttrDef(&store.GrpAttrDef{TenantID: f.A.ID, FolderID: b.folder, Extension: "x", DisplayExtension: "x",
				AttrType: store.AttrTypeAttr, ValueType: store.AttrValueMarker, AssignTo: []string{}, CreatedAt: storetest.Now})
		},
		"name under A's definition": func(c *store.TenantTx) error {
			return c.InsertGrpAttrName(&store.GrpAttrName{DefID: a.def, Extension: "x", DisplayExtension: "x", CreatedAt: storetest.Now})
		},
		"action of A's definition": func(c *store.TenantTx) error {
			return c.InsertGrpAttrAction(&store.GrpAttrAction{DefID: a.def, Name: "x", CreatedAt: storetest.Now})
		},
		"implication between A's names": func(c *store.TenantTx) error {
			return c.ReplaceGrpAttrImplies(store.ImpliesNames, b.def, []store.GrpAttrImplies{{DefID: b.def, From: a.name1, To: a.name2}})
		},
		"implication under A's definition": func(c *store.TenantTx) error {
			return c.ReplaceGrpAttrImplies(store.ImpliesNames, a.def, []store.GrpAttrImplies{{DefID: a.def, From: b.name1, To: b.name2}})
		},
		"action implication between A's actions": func(c *store.TenantTx) error {
			return c.ReplaceGrpAttrImplies(store.ImpliesActions, b.def, []store.GrpAttrImplies{{DefID: b.def, From: a.action, To: b.action}})
		},
		"assignment of A's definition": assign(func(r *store.GrpAttrAssign) { r.DefID = a.def }),
		"assignment of A's name":       assign(func(r *store.GrpAttrAssign) { r.NameID = a.name1 }),
		"assignment with A's action":   assign(func(r *store.GrpAttrAssign) { r.ActionID = a.action }),
		"on A's group":                 assign(func(r *store.GrpAttrAssign) { r.OwnerID = string(a.group) }),
		"on A's folder": assign(func(r *store.GrpAttrAssign) {
			r.OwnerType, r.OwnerID = store.AttrOwnerFolder, string(a.folder)
		}),
		"on A's identity": assign(func(r *store.GrpAttrAssign) {
			r.OwnerType, r.OwnerID = store.AttrOwnerIdentity, itoa(a.ident)
		}),
		"on A's membership":         assign(func(r *store.GrpAttrAssign) { r.OwnerType, r.OwnerID = store.AttrOwnerMembership, a.membership }),
		"on A's definition":         assign(func(r *store.GrpAttrAssign) { r.OwnerType, r.OwnerID = store.AttrOwnerAttrDef, a.def }),
		"on A's assignment":         assign(func(r *store.GrpAttrAssign) { r.OwnerType, r.OwnerID = store.AttrOwnerAssignment, a.assign }),
		"assignment stamped with A": assign(func(r *store.GrpAttrAssign) { r.TenantID = f.A.ID }),
		"value of A's assignment": func(c *store.TenantTx) error {
			s := "x"
			return c.InsertGrpAttrValue(&store.GrpAttrValue{AssignID: a.assign, ValueString: &s, Key: "s:x", CreatedAt: storetest.Now})
		},
		"value naming A's identity": func(c *store.TenantTx) error {
			return c.InsertGrpAttrValue(&store.GrpAttrValue{AssignID: b.assign, ValueMemberID: &a.ident, Key: "m:1", CreatedAt: storetest.Now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	// the name and action of an assignment must belong to its definition, even in one tenant
	t.Run("name of another definition", func(t *testing.T) {
		err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			d := &store.GrpAttrDef{FolderID: b.folder, Extension: "second", DisplayExtension: "second", AttrType: store.AttrTypeAttr,
				ValueType: store.AttrValueMarker, AssignTo: []string{store.AttrOwnerGroup}, CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrDef(d); err != nil {
				return err
			}
			return c.InsertGrpAttrAssign(&store.GrpAttrAssign{DefID: d.ID, NameID: b.name1, ActionID: b.action,
				OwnerType: store.AttrOwnerGroup, OwnerID: string(b.group), CreatedAt: storetest.Now})
		})
		if err == nil {
			t.Fatal("an assignment of one definition used another's name")
		}
	})
	// an attribute definition can hold privileges (GR-4's table), and only its own tenant's
	t.Run("privilege on A's definition", func(t *testing.T) {
		err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			return c.InsertGrpPrivilege(&store.GrpPrivilege{ObjectType: "attr_def", ObjectID: a.def, Privilege: "attr_view",
				HolderType: store.HolderEveryone, AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now})
		})
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Fatalf("err = %v, want ErrCrossTenant", err)
		}
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertGrpPrivilege(&store.GrpPrivilege{ObjectType: "attr_def", ObjectID: b.def, Privilege: "attr_view",
			HolderType: store.HolderEveryone, AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now})
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// groupAttrsCovered lists the repository methods of GR-7 that the isolation
// tests above exercise.
func groupAttrsCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"InsertGrpAttrDef", "GrpAttrDef", "GrpAttrDefByExtension", "GrpAttrDefs", "GrpAttrDefCountIn",
		"UpdateGrpAttrDef", "DeleteGrpAttrDef", "InsertGrpAttrName", "GrpAttrName", "GrpAttrNameByExtension", "GrpAttrNames",
		"UpdateGrpAttrName", "DeleteGrpAttrName", "InsertGrpAttrAction", "GrpAttrAction", "GrpAttrActionByName", "GrpAttrActionsOf",
		"DeleteGrpAttrAction", "GrpAttrImpliesOfDef", "GrpAttrImpliesOf", "ReplaceGrpAttrImplies", "InsertGrpAttrAssign",
		"GrpAttrAssign", "GrpAttrAssigns", "GrpAttrAssignCount", "GrpAttrAssignsByValue", "UpdateGrpAttrAssign",
		"DeleteGrpAttrAssign", "InsertGrpAttrValue", "GrpAttrValuesOf", "DeleteGrpAttrValuesOf"} {
		m[name] = true
	}
	return m
}
