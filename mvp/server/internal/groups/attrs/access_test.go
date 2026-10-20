package attrs_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func penv(c *store.TenantTx) privs.Env {
	return privs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
}

func grant(t *testing.T, c *store.TenantTx, o privs.Object, p privs.Privilege, identity int64) {
	t.Helper()
	if _, _, err := privs.Grant(penv(c), privs.GrantInput{Object: o, Privilege: p, Holder: privs.IdentityHolder(identity)}); err != nil {
		t.Fatalf("grant %s on %v: %v", p, o, err)
	}
}

func checker(c *store.TenantTx, s privs.Subject) *privs.Checker {
	return privs.NewChecker(c, storetest.Now, nil, s)
}

func as(id int64) privs.Subject { return privs.Subject{Identity: &id} }

// denied checks err is a *privs.DeniedError for the privilege.
func denied(t *testing.T, what string, err error, p privs.Privilege) {
	t.Helper()
	var d *privs.DeniedError
	if !errors.As(err, &d) || d.Privilege != p {
		t.Errorf("%s: err = %v, want denied %s", what, err, p)
	}
}

func allowed(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %v", what, err)
	}
}

// TestAttrPrivileges_AssignNeedsBothSides: assigning a definition to an owner
// needs attr_update on the definition and the owner's own update privilege.
func TestAttrPrivileges_AssignNeedsBothSides(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "any", MultiAssign: true, AssignTo: allTypes()})
		other := def(t, c, w.app, attrs.DefInput{Extension: "other", MultiAssign: true, AssignTo: allTypes()})
		name(t, c, d, "n")
		on := name(t, c, other, "n")
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		m, err := e.AddMember(w.g1, model.MemberInput{Identity: &w.alice})
		if err != nil {
			t.Fatal(err)
		}
		held, err := attrs.Assign(env(c), attrs.AssignInput{Name: on.ID, Owner: group(w.g2)})
		if err != nil {
			t.Fatal(err)
		}
		def := privs.AttrDefObject(d.ID)
		owners := map[string]struct {
			owner attrs.Owner
			side  privs.Object
			priv  privs.Privilege
		}{
			"folder":     {folder(w.foo), privs.FolderObject(w.foo), privs.StemAttrUpdate},
			"group":      {group(w.g1), privs.GroupObject(w.g1), privs.GroupAttrUpdate},
			"membership": {attrs.Owner{Type: store.AttrOwnerMembership, ID: m.Member.ID}, privs.GroupObject(w.g1), privs.Update},
			"attr_def":   {attrs.Owner{Type: store.AttrOwnerAttrDef, ID: other.ID}, privs.AttrDefObject(other.ID), privs.AttrDefAttrUpdate},
			"assignment": {attrs.Owner{Type: store.AttrOwnerAssignment, ID: held.Assign.ID}, privs.AttrDefObject(other.ID), privs.AttrUpdate},
		}
		for typ, tc := range owners {
			// nothing held: the definition's attr_update is asked first
			denied(t, typ+": nothing held", attrs.RequireAssign(checker(c, as(w.ivan)), c, d, tc.owner), privs.AttrUpdate)
		}
		grant(t, c, def, privs.AttrUpdate, w.ivan)
		for typ, tc := range owners {
			// attr_update on the definition is not enough: the owner's privilege is asked next
			denied(t, typ+": definition side only", attrs.RequireAssign(checker(c, as(w.ivan)), c, d, tc.owner), tc.priv)
			grant(t, c, tc.side, tc.priv, w.ivan)
			allowed(t, typ+": both sides", attrs.RequireAssign(checker(c, as(w.ivan)), c, d, tc.owner))
			allowed(t, typ+": change", attrs.RequireChange(checker(c, as(w.ivan)), c, d, tc.owner))
			allowed(t, typ+": unassign", attrs.RequireUnassign(checker(c, as(w.ivan)), c, d, tc.owner))
			// the owner's privilege without the definition's does not do either
			denied(t, typ+": owner side only", attrs.RequireAssign(checker(c, as(w.pat)), c, d, tc.owner), privs.AttrUpdate)
		}
		// an identity has no object privileges: the definition's attr_update is all it takes
		allowed(t, "identity owner", attrs.RequireAssign(checker(c, as(w.ivan)), c, d, attrs.Owner{Type: store.AttrOwnerIdentity, ID: jsonInt(w.pat)}))
		// attr_update implies attr_view, not attr_read or attr_admin
		allowed(t, "view by update", attrs.RequireView(checker(c, as(w.ivan)), d))
		denied(t, "admin by update", attrs.RequireAdmin(checker(c, as(w.ivan)), d), privs.AttrAdmin)
		denied(t, "read by update", attrs.RequireRead(checker(c, as(w.ivan)), c, d, group(w.g1)), privs.AttrRead)
	})
}

func TestAttrPrivileges_ReadNeedsBothSides(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "any", MultiAssign: true, AssignTo: allTypes()})
		canRead := func(s privs.Subject, o attrs.Owner) bool {
			ok, err := attrs.CanRead(checker(c, s), c, d, o)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		g := group(w.g1)
		if canRead(as(w.ivan), g) {
			t.Error("a stranger reads")
		}
		grant(t, c, privs.AttrDefObject(d.ID), privs.AttrRead, w.ivan)
		if canRead(as(w.ivan), g) {
			t.Error("attr_read alone reads the attributes of a group")
		}
		denied(t, "owner side missing", attrs.RequireRead(checker(c, as(w.ivan)), c, d, g), privs.GroupAttrRead)
		grant(t, c, privs.GroupObject(w.g1), privs.GroupAttrRead, w.ivan)
		if !canRead(as(w.ivan), g) {
			t.Error("attr_read and group_attr_read do not read")
		}
		if canRead(as(w.ivan), group(w.g2)) {
			t.Error("a row on g1 reads g2's attributes")
		}
		// group_attr_read alone, without the definition's attr_read
		grant(t, c, privs.GroupObject(w.g2), privs.GroupAttrRead, w.pat)
		if canRead(as(w.pat), group(w.g2)) {
			t.Error("group_attr_read alone reads")
		}
		// attr_view is not attr_read
		grant(t, c, privs.AttrDefObject(d.ID), privs.AttrView, w.alice)
		grant(t, c, privs.GroupObject(w.g1), privs.GroupAttrRead, w.alice)
		if canRead(as(w.alice), g) {
			t.Error("attr_view reads")
		}
		// the auditor role reads everywhere, and writes nowhere
		aud := privs.Subject{Identity: &w.pat, Auditor: true}
		if !canRead(aud, g) || !canRead(aud, folder(w.app)) {
			t.Error("the auditor role does not read attributes")
		}
		denied(t, "auditor write", attrs.RequireAssign(checker(c, aud), c, d, g), privs.AttrUpdate)
		// tenant_admin holds everything
		if !canRead(privs.Subject{TenantAdmin: true}, g) {
			t.Error("tenant_admin does not read")
		}
		// a definition that is deleted or an owner that is missing is not readable
		if canRead(as(w.ivan), attrs.Owner{Type: store.AttrOwnerGroup, ID: "missing"}) {
			t.Error("a missing group is readable")
		}
	})
}

// TestAttrPrivileges_OptInAndOut: attr_optin lets a person assign a definition to
// themselves, attr_optout remove it; neither reaches anyone else.
func TestAttrPrivileges_OptInAndOut(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "me", MultiAssign: true, AssignTo: allTypes()})
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		mine, err := e.AddMember(w.g1, model.MemberInput{Identity: &w.alice})
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := e.AddMember(w.g1, model.MemberInput{Identity: &w.ivan})
		if err != nil {
			t.Fatal(err)
		}
		me := attrs.Owner{Type: store.AttrOwnerIdentity, ID: jsonInt(w.alice)}
		you := attrs.Owner{Type: store.AttrOwnerIdentity, ID: jsonInt(w.ivan)}
		myMembership := attrs.Owner{Type: store.AttrOwnerMembership, ID: mine.Member.ID}
		yourMembership := attrs.Owner{Type: store.AttrOwnerMembership, ID: theirs.Member.ID}
		ck := func() *privs.Checker { return checker(c, as(w.alice)) }
		denied(t, "no privilege", attrs.RequireAssign(ck(), c, d, me), privs.AttrUpdate)
		grant(t, c, privs.AttrDefObject(d.ID), privs.AttrOptin, w.alice)
		allowed(t, "opt in, identity", attrs.RequireAssign(ck(), c, d, me))
		allowed(t, "opt in, membership", attrs.RequireAssign(ck(), c, d, myMembership))
		denied(t, "opt in for another identity", attrs.RequireAssign(ck(), c, d, you), privs.AttrUpdate)
		denied(t, "opt in for another membership", attrs.RequireAssign(ck(), c, d, yourMembership), privs.AttrUpdate)
		denied(t, "opt in on a group", attrs.RequireAssign(ck(), c, d, group(w.g1)), privs.AttrUpdate)
		denied(t, "opt in does not remove", attrs.RequireUnassign(ck(), c, d, me), privs.AttrUpdate)
		denied(t, "opt in does not change", attrs.RequireChange(ck(), c, d, me), privs.AttrUpdate)
		grant(t, c, privs.AttrDefObject(d.ID), privs.AttrOptout, w.alice)
		allowed(t, "opt out", attrs.RequireUnassign(ck(), c, d, me))
		allowed(t, "opt out, membership", attrs.RequireUnassign(ck(), c, d, myMembership))
		denied(t, "opt out for another", attrs.RequireUnassign(ck(), c, d, you), privs.AttrUpdate)
		// an identity-less subject (a machine client) is nobody's own
		denied(t, "no identity", attrs.RequireAssign(checker(c, privs.Subject{}), c, d, me), privs.AttrUpdate)
	})
}

// TestAttrPrivileges_InheritedFromFolders: a folder row applied to attr_defs
// reaches the definitions below it, by scope, and stem_admin reaches all.
func TestAttrPrivileges_InheritedFromFolders(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		inApp := def(t, c, w.app, attrs.DefInput{Extension: "a", AssignTo: allTypes()})
		inFoo := def(t, c, w.foo, attrs.DefInput{Extension: "b", AssignTo: allTypes()})
		has := func(id int64, d *store.GrpAttrDef, p privs.Privilege) bool {
			ok, err := checker(c, as(id)).Has(privs.AttrDefObject(d.ID), p)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		row := func(f store.FolderID, p privs.Privilege, id int64, scope string) {
			t.Helper()
			if _, _, err := privs.Grant(penv(c), privs.GrantInput{Object: privs.FolderObject(f), Privilege: p,
				Holder: privs.IdentityHolder(id), AppliesTo: "attr_defs", Scope: scope}); err != nil {
				t.Fatal(err)
			}
		}
		row(w.app, privs.AttrView, w.ivan, "one")
		row(w.app, privs.AttrAdmin, w.pat, "sub")
		for _, tc := range []struct {
			who  int64
			d    *store.GrpAttrDef
			p    privs.Privilege
			want bool
		}{
			{w.ivan, inApp, privs.AttrView, true}, {w.ivan, inFoo, privs.AttrView, false}, // scope one: children only
			{w.ivan, inApp, privs.AttrRead, false},
			{w.pat, inApp, privs.AttrAdmin, true}, {w.pat, inFoo, privs.AttrAdmin, true}, // scope sub: everything below
			{w.pat, inFoo, privs.AttrDefAttrUpdate, true}, // admin implies it
			{w.alice, inApp, privs.AttrView, false},
		} {
			if got := has(tc.who, tc.d, tc.p); got != tc.want {
				t.Errorf("identity %d %s on %s = %v, want %v", tc.who, tc.p, tc.d.Name(), got, tc.want)
			}
		}
		// attr_* privileges are not group privileges: a row of the wrong kind is not inherited
		if _, _, err := privs.Grant(penv(c), privs.GrantInput{Object: privs.FolderObject(w.app), Privilege: privs.Admin,
			Holder: privs.IdentityHolder(w.alice), AppliesTo: "attr_defs", Scope: "sub"}); err == nil {
			t.Error("a group privilege was granted as inherited by attribute definitions")
		}
		// stem_admin on a folder is every privilege on what is below it
		grant(t, c, privs.FolderObject(w.foo), privs.StemAdmin, w.alice)
		if !has(w.alice, inFoo, privs.AttrAdmin) || has(w.alice, inApp, privs.AttrView) {
			t.Error("stem_admin on foo should reach foo's definitions only")
		}
		// the same privileges are explained like the others
		ex, err := checker(c, as(w.pat)).Explain(privs.AttrDefObject(inFoo.ID))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range ex {
			if e.Privilege == privs.AttrAdmin && e.Allowed && len(e.Paths) > 0 && strings.Contains(e.Paths[0].Text, "`app:foo:b`") {
				found = true
			}
		}
		if !found {
			t.Errorf("Explain(attr_def) = %+v", ex)
		}
	})
}

// TestAttrPrivileges_CreatorEveryoneAndDelete: the creator of a definition
// administers it, the tenant's defaults apply, and the rows go with the definition.
func TestAttrPrivileges_CreatorEveryoneAndDelete(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		set := privs.DefaultSettings()
		set.Defaults = []privs.Default{{ObjectType: privs.AttrDef, Privilege: privs.AttrView}}
		if _, err := privs.SaveSettings(penv(c), set); err != nil {
			t.Fatal(err)
		}
		creator := env(c)
		creator.ByIdentity, creator.TenantAdmin = &w.ivan, false
		d, err := attrs.CreateDef(creator, attrs.DefInput{Folder: w.app, Extension: "mine", AssignTo: allTypes()})
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := checker(c, as(w.ivan)).Has(privs.AttrDefObject(d.ID), privs.AttrAdmin); !ok {
			t.Error("the creator does not administer the definition")
		}
		if ok, _ := checker(c, as(w.pat)).Has(privs.AttrDefObject(d.ID), privs.AttrView); !ok {
			t.Error("the tenant's default (attr_view for everyone) did not apply")
		}
		if ok, _ := checker(c, as(w.pat)).Has(privs.AttrDefObject(d.ID), privs.AttrRead); ok {
			t.Error("everyone reads")
		}
		rows, _ := c.GrpPrivilegesOf("attr_def", d.ID)
		if len(rows) != 2 {
			t.Errorf("rows on the definition = %d, want the creator's and the default", len(rows))
		}
		if err := attrs.DeleteDef(env(c), d.ID); err != nil {
			t.Fatal(err)
		}
		if rows, _ := c.GrpPrivilegesOf("attr_def", d.ID); len(rows) != 0 {
			t.Errorf("%d privilege rows survived the definition", len(rows))
		}
		if ok, _ := checker(c, as(w.ivan)).Has(privs.AttrDefObject(d.ID), privs.AttrAdmin); ok {
			t.Error("a deleted definition is administered")
		}
	})
}

// ---------------------------------------------------------------- object types

func TestObjectTypes(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now, ByIdentity: &w.ivan, TenantAdmin: true}
		if d, n, err := attrs.Builtin(c); err != nil || d != nil || n != nil {
			t.Fatalf("Builtin before any use = %v %v %v", d, n, err)
		}
		if got, err := attrs.ObjectTypesOf(c, group(w.g1)); err != nil || got != nil {
			t.Errorf("ObjectTypesOf before the definition exists = %v, %v", got, err)
		}
		_, err := attrs.SetObjectTypes(env(c), group(w.g1), []string{"ref"})
		wantErr(t, err, attrs.Conflict, "object_types_unavailable")
		if err := e.EnsureObjectTypes(); err != nil {
			t.Fatal(err)
		}
		if err := e.EnsureObjectTypes(); err != nil { // idempotent
			t.Fatal(err)
		}
		d, n, err := attrs.Builtin(c)
		if err != nil || d == nil || n == nil || d.Name() != "etc:objectTypes" || !d.System || !attrs.IsBuiltin(d) {
			t.Fatalf("Builtin = %+v %+v %v", d, n, err)
		}
		if attrs.NameFullName(d, n) != "etc:objectTypes:objectType" {
			t.Errorf("name = %s", attrs.NameFullName(d, n))
		}
		if byName, err := attrs.NameByFullName(c, "etc:objectTypes:objectType"); err != nil || byName.ID != n.ID {
			t.Errorf("NameByFullName = %v, %v", byName, err)
		}
		if _, err := attrs.NameByFullName(c, "etc:objectTypes:nope"); err == nil {
			t.Error("a missing name resolved")
		}
		// the system owns it: no privilege rows went to the acting user
		if rows, _ := c.GrpPrivilegesOf("attr_def", d.ID); len(rows) != 0 {
			t.Errorf("the built-in definition has %d creator rows", len(rows))
		}
		if rows, _ := c.GrpPrivilegesOfHolderIdentity(w.ivan); len(rows) != 0 {
			for _, r := range rows {
				if r.ObjectType == "folder" || r.ObjectType == "attr_def" {
					t.Errorf("the acting user was given %s on the system's %s", r.Privilege, r.ObjectType)
				}
			}
		}
		wantErr(t, attrs.DeleteDef(env(c), d.ID), attrs.Conflict, "system_attr_def")
		wantErr(t, attrs.DeleteName(env(c), n.ID), attrs.Conflict, "system_attr_def")
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{Description: ptr("x")})
		wantErr(t, err, attrs.Conflict, "system_attr_def")

		g := group(w.g1)
		changed, err := attrs.SetObjectTypes(env(c), g, []string{"policy", "ref", "policy"})
		if err != nil || !changed {
			t.Fatalf("SetObjectTypes = %v, %v", changed, err)
		}
		if got, _ := attrs.ObjectTypesOf(c, g); !slices.Equal(got, []string{"ref", "policy"}) { // vocabulary order
			t.Errorf("types = %v", got)
		}
		if changed, err := attrs.SetObjectTypes(env(c), g, []string{"ref", "policy"}); err != nil || changed {
			t.Errorf("an unchanged set = %v, %v", changed, err)
		}
		if _, err := attrs.SetObjectTypes(env(c), g, []string{"bundle"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := attrs.ObjectTypesOf(c, g); !slices.Equal(got, []string{"bundle"}) {
			t.Errorf("types after replace = %v", got)
		}
		// the vocabulary is by kind: a group has no service type, a folder no policy type
		_, err = attrs.SetObjectTypes(env(c), g, []string{"service"})
		wantErr(t, err, attrs.Invalid, "invalid_object_type")
		_, err = attrs.SetObjectTypes(env(c), folder(w.foo), []string{"policy"})
		wantErr(t, err, attrs.Invalid, "invalid_object_type")
		if _, err := attrs.SetObjectTypes(env(c), folder(w.foo), []string{"service", "app"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := attrs.ObjectTypesOf(c, folder(w.foo)); !slices.Equal(got, []string{"service", "app"}) { // vocabulary order
			t.Errorf("folder types = %v", got)
		}
		_, err = attrs.SetObjectTypes(env(c), attrs.Owner{Type: store.AttrOwnerIdentity, ID: "1"}, []string{"ref"})
		wantErr(t, err, attrs.Invalid, "invalid_owner_type")
		// the generic route is held to the same vocabulary
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g2), Values: raw(`"service"`)})
		wantErr(t, err, attrs.Invalid, "invalid_object_type")
		// the vocabularies are the Deployment Guide's twelve
		all := append(attrs.ObjectTypeVocabulary("group"), attrs.ObjectTypeVocabulary("folder")...)
		slices.Sort(all)
		want := strings.Fields("app basis bundle etc intermediate manual org policy ref security service test")
		if !slices.Equal(all, want) {
			t.Errorf("vocabulary = %v", all)
		}
		if attrs.ObjectTypeVocabulary("identity") != nil {
			t.Error("an identity has object types")
		}
		// a copy of a group keeps its types; an empty list removes them
		cp, err := e.CopyGroup(w.g1, model.CopyInput{Parent: w.foo, Extension: "copy"})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := attrs.ObjectTypesOf(c, group(cp.ID)); !slices.Equal(got, []string{"bundle"}) {
			t.Errorf("the copy's types = %v", got)
		}
		if changed, err := attrs.SetObjectTypes(env(c), g, nil); err != nil || !changed {
			t.Errorf("clearing = %v, %v", changed, err)
		}
		if got, _ := attrs.ObjectTypesOf(c, g); len(got) != 0 {
			t.Errorf("types after clearing = %v", got)
		}
		// the etc folder now holds a definition, so it is not empty
		etc, err := c.GrpFolderByName("etc")
		if err != nil {
			t.Fatal(err)
		}
		err = e.DeleteFolder(etc.ID)
		var me *model.Error
		if !errors.As(err, &me) || me.Code != "folder_not_empty" || me.Extra["attr_defs"] != 1 {
			t.Errorf("deleting the etc folder: %v", err)
		}
	})
}

// TestObjectTypes_FolderDeleteRemovesAssignments: the attributes of a folder end with it.
func TestObjectTypes_FolderDeleteRemovesAssignments(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		d := def(t, c, w.app, attrs.DefInput{Extension: "tag", AssignTo: []string{store.AttrOwnerFolder}})
		n := name(t, c, d, "n")
		leaf, err := e.CreateFolder(model.CreateFolderInput{Parent: w.app, Extension: "leaf"})
		if err != nil {
			t.Fatal(err)
		}
		a, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: folder(leaf.ID)})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.DeleteFolder(leaf.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GrpAttrAssign(a.Assign.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the folder's assignment survived it: %v", err)
		}
		// a folder that holds a definition is not empty
		err = e.DeleteFolder(w.app)
		var me *model.Error
		if !errors.As(err, &me) || me.Code != "folder_not_empty" {
			t.Errorf("delete a folder with a definition: %v", err)
		}
	})
}

// ---------------------------------------------------------------- lint

func typed(t *testing.T, c *store.TenantTx, o attrs.Owner, types ...string) {
	t.Helper()
	e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
	if err := e.EnsureObjectTypes(); err != nil {
		t.Fatal(err)
	}
	if _, err := attrs.SetObjectTypes(env(c), o, types); err != nil {
		t.Fatal(err)
	}
}

// memberSeq numbers the identities made by members (each test has its own database).
var memberSeq int

func members(t *testing.T, c *store.TenantTx, g store.GroupID, n int) {
	t.Helper()
	e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
	for i := 0; i < n; i++ {
		memberSeq++
		id, err := c.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("m%d", memberSeq), Name: "M", Type: "person", Status: "active", CreatedAt: storetest.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddMember(g, model.MemberInput{Identity: &id}); err != nil {
			t.Fatal(err)
		}
	}
}

func rules(fs []attrs.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Rule
	}
	slices.Sort(out)
	return out
}

func TestLint_Groups(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		lint := func(id store.GroupID) []attrs.Finding {
			g, err := c.GrpGroup(id)
			if err != nil {
				t.Fatal(err)
			}
			fs, err := attrs.LintGroup(c, g)
			if err != nil {
				t.Fatal(err)
			}
			return fs
		}
		if fs := lint(w.g1); len(fs) != 0 {
			t.Errorf("an untyped group has findings: %v", fs)
		}
		// a policy group with few direct members is fine; with too many it is flagged
		typed(t, c, group(w.g1), "policy")
		if got := rules(lint(w.g1)); !slices.Equal(got, []string{attrs.RuleMissingDataOwner}) {
			t.Errorf("policy, no members = %v", got) // the data owner is unset: info only
		}
		members(t, c, w.g1, attrs.PolicyDirectMax)
		if fs := lint(w.g1); slices.Contains(rules(fs), attrs.RulePolicyDirectMembers) {
			t.Errorf("%d direct members are flagged: %v", attrs.PolicyDirectMax, fs)
		}
		members(t, c, w.g1, 302)
		fs := lint(w.g1)
		var found *attrs.Finding
		for i := range fs {
			if fs[i].Rule == attrs.RulePolicyDirectMembers {
				found = &fs[i]
			}
		}
		if found == nil || found.Severity != attrs.SeverityWarning || !strings.HasPrefix(found.Message, "policy group has 312 direct members") {
			t.Errorf("findings = %+v", fs)
		}
		// a data owner silences the info rule
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		if _, err := e.UpdateGroup(w.g1, model.UpdateGroupInput{DataOwner: ptr("alice")}); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(rules(lint(w.g1)), attrs.RuleMissingDataOwner) {
			t.Error("a group with a data owner is flagged for none")
		}
		// a bundle holds groups: a direct identity is flagged
		typed(t, c, group(w.g2), "bundle")
		if len(lint(w.g2)) != 0 {
			t.Errorf("an empty bundle = %v", lint(w.g2))
		}
		members(t, c, w.g2, 1)
		if got := rules(lint(w.g2)); !slices.Equal(got, []string{attrs.RuleBundleDirectMembers}) {
			t.Errorf("a bundle with a member = %v", got)
		}
		// a group of another type is not subject to these rules
		typed(t, c, group(w.policy), "manual")
		members(t, c, w.policy, 50)
		if got := lint(w.policy); len(got) != 0 {
			t.Errorf("a manual group = %v", got)
		}
	})
}

func TestLint_ServiceFolders(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		f, err := c.GrpFolder(w.foo)
		if err != nil {
			t.Fatal(err)
		}
		lint := func() []string {
			fs, err := attrs.LintFolder(c, f)
			if err != nil {
				t.Fatal(err)
			}
			return rules(fs)
		}
		if got := lint(); len(got) != 0 {
			t.Errorf("an untyped folder = %v", got)
		}
		typed(t, c, folder(w.foo), "service")
		if got := lint(); !slices.Equal(got, []string{attrs.RuleServiceNoPolicy}) {
			t.Errorf("a service with no policy group = %v", got)
		}
		typed(t, c, group(w.policy), "policy")
		if got := lint(); len(got) != 0 {
			t.Errorf("a service with a policy group = %v", got)
		}
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		if err := e.DeleteGroup(w.policy); err != nil {
			t.Fatal(err)
		}
		if got := lint(); !slices.Equal(got, []string{attrs.RuleServiceNoPolicy}) {
			t.Errorf("a service whose policy group is deleted = %v", got)
		}
	})
}

// ---------------------------------------------------------------- services

func TestServices(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		typed(t, c, folder(w.foo), "service")
		typed(t, c, group(w.policy), "policy")
		typed(t, c, group(w.g1), "policy") // outside the service: not part of it
		if _, err := e.AddMember(w.policy, model.MemberInput{Identity: &w.ivan}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddMember(w.g1, model.MemberInput{Identity: &w.alice}); err != nil {
			t.Fatal(err)
		}
		list := func(s privs.Subject, who int64) []attrs.Service {
			out, err := attrs.ServicesFor(checker(c, s), c, nil, storetest.Now, who)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		// the caller must be able to see the folder and the group
		if got := list(as(w.ivan), w.ivan); len(got) != 0 {
			t.Errorf("services without view privileges = %d", len(got))
		}
		grant(t, c, privs.FolderObject(w.foo), privs.StemView, w.ivan)
		if got := list(as(w.ivan), w.ivan); len(got) != 0 {
			t.Errorf("services without view on the group = %d", len(got))
		}
		grant(t, c, privs.GroupObject(w.policy), privs.View, w.ivan)
		got := list(as(w.ivan), w.ivan)
		if len(got) != 1 || got[0].Folder.ID != w.foo || len(got[0].Groups) != 1 || got[0].Groups[0].ID != w.policy {
			t.Fatalf("services = %+v", got)
		}
		// a person who is in no policy group of the service has none
		if got := list(privs.Subject{TenantAdmin: true}, w.pat); len(got) != 0 {
			t.Errorf("a non-member's services = %d", len(got))
		}
		// alice is in a policy group, but not of a service folder
		if got := list(privs.Subject{TenantAdmin: true}, w.alice); len(got) != 0 {
			t.Errorf("a policy group outside the service grants it: %d", len(got))
		}
		// a disabled policy group grants nothing
		if _, err := e.UpdateGroup(w.policy, model.UpdateGroupInput{Status: ptr(store.GroupDisabled)}); err != nil {
			t.Fatal(err)
		}
		if got := list(privs.Subject{TenantAdmin: true}, w.ivan); len(got) != 0 {
			t.Errorf("a disabled policy group grants the service: %d", len(got))
		}
		if _, err := e.UpdateGroup(w.policy, model.UpdateGroupInput{Status: ptr(store.GroupActive)}); err != nil {
			t.Fatal(err)
		}
		if got := list(privs.Subject{TenantAdmin: true}, w.ivan); len(got) != 1 {
			t.Errorf("an enabled policy group: %d", len(got))
		}
	})
}
