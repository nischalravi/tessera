package privs_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// ---------------------------------------------------------------- implication

// implied is design §7.1 closed transitively: what holding each privilege
// gives. The 21 names are the grp_privileges CHECK list (the design's "22" does
// not enumerate a 22nd; see the PR notes).
var implied = map[privs.Privilege]string{
	"admin":             "admin update read view optin optout group_attr_read group_attr_update",
	"update":            "update view",
	"read":              "read view",
	"view":              "view",
	"optin":             "optin view",
	"optout":            "optout view",
	"group_attr_read":   "group_attr_read",
	"group_attr_update": "group_attr_update group_attr_read",

	"stem_admin":       "stem_admin create stem_attr_read stem_attr_update stem_view",
	"create":           "create stem_view",
	"stem_attr_read":   "stem_attr_read",
	"stem_attr_update": "stem_attr_update stem_attr_read",
	"stem_view":        "stem_view",

	"attr_admin":           "attr_admin attr_update attr_read attr_view attr_optin attr_optout attr_def_attr_read attr_def_attr_update",
	"attr_update":          "attr_update attr_view",
	"attr_read":            "attr_read attr_view",
	"attr_view":            "attr_view",
	"attr_optin":           "attr_optin attr_view",
	"attr_optout":          "attr_optout attr_view",
	"attr_def_attr_read":   "attr_def_attr_read",
	"attr_def_attr_update": "attr_def_attr_update attr_def_attr_read",
}

func names(ps []privs.Privilege) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	slices.Sort(out)
	return out
}

func TestImplication(t *testing.T) {
	if got := len(privs.All()); got != len(implied) {
		t.Fatalf("%d privileges, the table has %d", got, len(implied))
	}
	for _, p := range privs.All() {
		want, ok := implied[p]
		if !ok {
			t.Errorf("%s is not in the table", p)
			continue
		}
		t.Run(string(p), func(t *testing.T) {
			w := strings.Fields(want)
			slices.Sort(w)
			if got := names(privs.Implied(p)); !slices.Equal(got, w) {
				t.Errorf("Implied(%s) = %v, want %v", p, got, w)
			}
			for _, q := range privs.All() {
				if got, want := privs.Implies(p, q), slices.Contains(w, string(q)); got != want {
					t.Errorf("Implies(%s, %s) = %v, want %v", p, q, got, want)
				}
				// ImpliedBy is the inverse relation
				if privs.Implies(p, q) != slices.Contains(privs.ImpliedBy(q), p) {
					t.Errorf("ImpliedBy(%s) disagrees with Implies(%s, %s)", q, p, q)
				}
			}
			if privs.ObjectOf(p) == "" || !slices.Contains(privs.For(privs.ObjectOf(p)), p) {
				t.Errorf("%s is on no object type", p)
			}
		})
	}
	if privs.Implies("bogus", "bogus") || privs.Implies(privs.Admin, "bogus") || privs.Valid("bogus") {
		t.Error("an unknown privilege implies or is implied")
	}
}

// TestImplication_SchemaAllowsEveryPrivilege: the CHECK list of 0285 and the
// implication table name the same privileges.
func TestImplication_SchemaAllowsEveryPrivilege(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		for _, p := range privs.All() {
			typ := privs.ObjectOf(p)
			id := map[privs.ObjectType]string{privs.Folder: string(w.app), privs.Group: string(w.g1), privs.AttrDef: "attr-def-1"}[typ]
			row := &store.GrpPrivilege{ObjectType: string(typ), ObjectID: id, Privilege: string(p), HolderType: store.HolderEveryone,
				AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
			if err := c.InsertGrpPrivilege(row); err != nil {
				t.Errorf("the schema refuses %s: %v", p, err)
			}
		}
		bad := &store.GrpPrivilege{ObjectType: "group", ObjectID: string(w.g1), Privilege: "bogus", HolderType: store.HolderEveryone,
			AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
		if err := c.InsertGrpPrivilege(bad); err == nil {
			t.Error("the schema accepts an unknown privilege")
		}
	})
}

// ---------------------------------------------------------------- the world

// world is tenant B with folders app, app:foo, app:foo:deep, groups app:g1,
// app:foo:g2, app:foo:deep:g3 and app:admins, and identities Ivan, Alice, Pat.
type world struct {
	f                 *storetest.Fixture
	app, foo, deep    store.FolderID
	g1, g2, g3, admin store.GroupID
	ivan, alice, pat  int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{f: storetest.TwoTenants(t)}
	w.inTx(t, func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now}
		folder := func(parent store.FolderID, ext string) store.FolderID {
			f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return f.ID
		}
		group := func(folder store.FolderID, ext string) store.GroupID {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return g.ID
		}
		w.app = folder("", "app")
		w.foo = folder(w.app, "foo")
		w.deep = folder(w.foo, "deep")
		w.g1, w.g2, w.g3 = group(w.app, "g1"), group(w.foo, "g2"), group(w.deep, "g3")
		w.admin = group(w.app, "admins")
		ident := func(name string) int64 {
			id, err := c.InsertIdentity(&store.Identity{ExternalID: name, Name: name, Type: "person", Status: "active", CreatedAt: storetest.Now})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		w.ivan, w.alice, w.pat = ident("Ivan"), ident("Alice"), ident("Pat")
	})
	return w
}

func (w *world) inTx(t *testing.T, fn func(c *store.TenantTx)) {
	t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		t.Fatal(err)
	}
}

func env(c *store.TenantTx) privs.Env {
	return privs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
}

func (w *world) grant(t *testing.T, c *store.TenantTx, o privs.Object, p privs.Privilege, h privs.Holder, appliesTo, scope string) *store.GrpPrivilege {
	t.Helper()
	row, _, err := privs.Grant(env(c), privs.GrantInput{Object: o, Privilege: p, Holder: h, AppliesTo: appliesTo, Scope: scope})
	if err != nil {
		t.Fatalf("grant %s on %v: %v", p, o, err)
	}
	return row
}

func (w *world) addMember(t *testing.T, c *store.TenantTx, g store.GroupID, identity int64) {
	t.Helper()
	if _, err := (model.Env{Tx: c, Now: storetest.Now}).AddMember(g, model.MemberInput{Identity: &identity}); err != nil {
		t.Fatal(err)
	}
}

func checker(c *store.TenantTx, s privs.Subject) *privs.Checker {
	return privs.NewChecker(c, storetest.Now, nil, s)
}

func holds(t *testing.T, ck *privs.Checker, o privs.Object, p privs.Privilege) bool {
	t.Helper()
	ok, err := ck.Has(o, p)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func asIdentity(id int64) privs.Subject { return privs.Subject{Identity: &id} }

// ---------------------------------------------------------------- checks

func TestPrivs_DirectAndImplied(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		w.grant(t, c, privs.GroupObject(w.g1), privs.Update, privs.IdentityHolder(w.ivan), "", "")
		ck := checker(c, asIdentity(w.ivan))
		g1 := privs.GroupObject(w.g1)
		for p, want := range map[privs.Privilege]bool{privs.Update: true, privs.View: true, privs.Read: false, privs.Admin: false,
			privs.Optin: false, privs.StemView: false /* a folder privilege: never held on a group */} {
			if got := holds(t, ck, g1, p); got != want {
				t.Errorf("Ivan %s on g1 = %v, want %v", p, got, want)
			}
		}
		if holds(t, ck, privs.GroupObject(w.g2), privs.View) {
			t.Error("a row on g1 gives Ivan view on g2")
		}
		if holds(t, checker(c, asIdentity(w.alice)), g1, privs.Update) || holds(t, checker(c, privs.Subject{}), g1, privs.View) {
			t.Error("Alice, or a subject without an identity, holds Ivan's privilege")
		}
		// an object that does not exist is never held
		if holds(t, checker(c, privs.Subject{Identity: &w.ivan, TenantAdmin: false}), privs.GroupObject("nope"), privs.View) {
			t.Error("a missing group is viewable")
		}
	})
}

// TestPrivs_InheritanceOneVsSub: a folder row with scope one is applied, at
// check time, to the objects whose parent is the folder; scope sub to
// everything below it (K5). Nothing is copied.
func TestPrivs_InheritanceOneVsSub(t *testing.T) {
	w := newWorld(t)
	tests := []struct {
		name      string
		appliesTo string
		scope     string
		priv      privs.Privilege
		on        func() privs.Object
		want      map[string]bool // object name -> held
	}{
		{"groups one", "groups", "one", privs.Read, nil, map[string]bool{"g1": true, "admins": true, "g2": false, "g3": false}},
		{"groups sub", "groups", "sub", privs.Read, nil, map[string]bool{"g1": true, "admins": true, "g2": true, "g3": true}},
		{"folders one", "folders", "one", privs.StemView, nil, map[string]bool{"foo": true, "deep": false}},
		{"folders sub", "folders", "sub", privs.StemView, nil, map[string]bool{"foo": true, "deep": true}},
	}
	groups := map[string]store.GroupID{"g1": w.g1, "admins": w.admin, "g2": w.g2, "g3": w.g3}
	folders := map[string]store.FolderID{"foo": w.foo, "deep": w.deep}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w.inTx(t, func(c *store.TenantTx) {
				row := w.grant(t, c, privs.FolderObject(w.app), tc.priv, privs.IdentityHolder(w.ivan), tc.appliesTo, tc.scope)
				ck := checker(c, asIdentity(w.ivan))
				for name, want := range tc.want {
					o := privs.GroupObject(groups[name])
					if tc.appliesTo == "folders" {
						o = privs.FolderObject(folders[name])
					}
					if got := holds(t, ck, o, tc.priv); got != want {
						t.Errorf("%s %s on %s = %v, want %v", tc.appliesTo, tc.priv, name, got, want)
					}
				}
				// the row applies to what is below the folder, not to the folder
				self := privs.FolderObject(w.app)
				if tc.appliesTo == "groups" {
					if holds(t, ck, self, privs.StemView) {
						t.Error("a row for groups gives privileges on the folder itself")
					}
				} else if holds(t, ck, self, tc.priv) {
					t.Error("a row for folders applies to the folder itself")
				}
				// nothing is copied: the one stored row is the folder's
				if rows, _ := c.GrpPrivilegesOf("group", string(w.g1)); len(rows) != 0 {
					t.Errorf("an inherited privilege was copied onto a group: %d rows", len(rows))
				}
				if err := c.DeleteGrpPrivilege(row.ID); err != nil {
					t.Fatal(err)
				}
				if holds(t, checker(c, asIdentity(w.ivan)), privs.GroupObject(w.g1), privs.Read) {
					t.Error("the privilege outlives its row")
				}
			})
		})
	}
	// a grant must say what it applies to
	w.inTx(t, func(c *store.TenantTx) {
		for name, in := range map[string]privs.GrantInput{
			"inherited on a group": {Object: privs.GroupObject(w.g1), Privilege: privs.Read, Holder: privs.IdentityHolder(w.ivan), AppliesTo: "groups", Scope: "sub"},
			"wrong kind":           {Object: privs.FolderObject(w.app), Privilege: privs.Read, Holder: privs.IdentityHolder(w.ivan), AppliesTo: "folders", Scope: "sub"},
			"self with a scope":    {Object: privs.FolderObject(w.app), Privilege: privs.StemView, Holder: privs.IdentityHolder(w.ivan), AppliesTo: "self", Scope: "one"},
			"no scope":             {Object: privs.FolderObject(w.app), Privilege: privs.Read, Holder: privs.IdentityHolder(w.ivan), AppliesTo: "groups", Scope: "self"},
			"wrong object":         {Object: privs.GroupObject(w.g1), Privilege: privs.StemView, Holder: privs.IdentityHolder(w.ivan)},
		} {
			if _, _, err := privs.Grant(env(c), in); !isKind(err, privs.Invalid) {
				t.Errorf("%s: err = %v, want an invalid grant", name, err)
			}
		}
	})
}

func isKind(err error, k privs.Kind) bool {
	var pe *privs.Error
	return errors.As(err, &pe) && pe.Kind == k
}

func TestPrivs_GroupHolderUsesEffectiveMembership(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		// Ivan is in app:admins, which holds admin on g2
		w.addMember(t, c, w.admin, w.ivan)
		w.grant(t, c, privs.GroupObject(w.g2), privs.Admin, privs.GroupHolder(w.admin), "", "")
		if !holds(t, checker(c, asIdentity(w.ivan)), privs.GroupObject(w.g2), privs.Update) {
			t.Error("a member of the holder group does not hold the privilege")
		}
		if holds(t, checker(c, asIdentity(w.alice)), privs.GroupObject(w.g2), privs.Update) {
			t.Error("a non-member holds the privilege")
		}
		// a nested group: Alice is in a group that is in app:admins
		e := model.Env{Tx: c, Now: storetest.Now}
		if _, err := e.AddMember(w.admin, model.MemberInput{Group: w.g1}); err != nil {
			t.Fatal(err)
		}
		w.addMember(t, c, w.g1, w.alice)
		if !holds(t, checker(c, asIdentity(w.alice)), privs.GroupObject(w.g2), privs.Admin) {
			t.Error("effective (nested) membership does not count")
		}
		// leaving the group ends the privilege
		if _, err := e.RemoveMember(w.admin, strconv.FormatInt(w.ivan, 10)); err != nil {
			t.Fatal(err)
		}
		if holds(t, checker(c, asIdentity(w.ivan)), privs.GroupObject(w.g2), privs.Update) {
			t.Error("the privilege outlives the membership")
		}
	})
}

// TestPrivs_StemAdminCoversBelow: stem_admin on a folder is every privilege on
// what is below it (design §7.2's example), and on nothing outside it.
func TestPrivs_StemAdminCoversBelow(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		w.grant(t, c, privs.FolderObject(w.foo), privs.StemAdmin, privs.IdentityHolder(w.ivan), "", "")
		ck := checker(c, asIdentity(w.ivan))
		for name, tc := range map[string]struct {
			o    privs.Object
			p    privs.Privilege
			want bool
		}{
			"admin on a group of the folder": {privs.GroupObject(w.g2), privs.Admin, true},
			"update on a deeper group":       {privs.GroupObject(w.g3), privs.Update, true},
			"create on a subfolder":          {privs.FolderObject(w.deep), privs.Create, true},
			"stem_admin on the folder":       {privs.FolderObject(w.foo), privs.StemAdmin, true},
			"nothing on a group above":       {privs.GroupObject(w.g1), privs.View, false},
			"nothing on the parent folder":   {privs.FolderObject(w.app), privs.StemView, false},
		} {
			if got := holds(t, ck, tc.o, tc.p); got != tc.want {
				t.Errorf("%s = %v, want %v", name, got, tc.want)
			}
		}
	})
}

func TestPrivs_PlatformRoles(t *testing.T) {
	w := newWorld(t)
	g := privs.GroupObject(w.g1)
	w.inTx(t, func(c *store.TenantTx) {
		for name, tc := range map[string]struct {
			sub  privs.Subject
			want []privs.Privilege
		}{
			"tenant_admin": {privs.Subject{TenantAdmin: true}, privs.For(privs.Group)},
			"auditor":      {privs.Subject{Auditor: true}, []privs.Privilege{privs.Read, privs.View, privs.GroupAttrRead}},
			"viewer":       {privs.Subject{ViewerView: true}, []privs.Privilege{privs.View}},
			"no role":      {privs.Subject{}, nil},
		} {
			ck := checker(c, tc.sub)
			for _, p := range privs.For(privs.Group) {
				if got, want := holds(t, ck, g, p), slices.Contains(tc.want, p); got != want {
					t.Errorf("%s holds %s = %v, want %v", name, p, got, want)
				}
			}
		}
		if !(privs.Subject{TenantAdmin: true}).SeesAll(privs.Folder) || (privs.Subject{}).SeesAll(privs.Group) ||
			!(privs.Subject{Auditor: true}).SeesAll(privs.Group) || !(privs.Subject{ViewerView: true}).SeesAll(privs.Folder) {
			t.Error("SeesAll does not follow the roles")
		}
	})
}

// TestPrivs_ExplainListsAllPaths: every way the identity holds a privilege is
// listed, with how the row reaches the object.
func TestPrivs_ExplainListsAllPaths(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		g2 := privs.GroupObject(w.g2)
		w.addMember(t, c, w.admin, w.ivan)
		w.grant(t, c, g2, privs.Update, privs.IdentityHolder(w.ivan), "", "")                                  // a row of his own
		w.grant(t, c, g2, privs.Admin, privs.GroupHolder(w.admin), "", "")                                     // through a group
		w.grant(t, c, privs.FolderObject(w.app), privs.Update, privs.IdentityHolder(w.ivan), "groups", "sub")  // inherited, sub
		w.grant(t, c, privs.FolderObject(w.foo), privs.StemAdmin, privs.GroupHolder(w.admin), "", "")          // stem_admin above
		w.grant(t, c, privs.FolderObject(w.foo), privs.Update, privs.IdentityHolder(w.alice), "groups", "one") // someone else's: not a path
		w.grant(t, c, privs.FolderObject(w.app), privs.Update, privs.IdentityHolder(w.ivan), "groups", "one")  // scope one on app: g2 is not its child
		ex, err := checker(c, asIdentity(w.ivan)).Explain(g2)
		if err != nil {
			t.Fatal(err)
		}
		if len(ex) != len(privs.For(privs.Group)) {
			t.Fatalf("%d explanations, want one per group privilege", len(ex))
		}
		var update, read *privs.Explanation
		for i := range ex {
			switch ex[i].Privilege {
			case privs.Update:
				update = &ex[i]
			case privs.GroupAttrUpdate:
				if !ex[i].Allowed {
					t.Error("admin through the group does not give group_attr_update")
				}
			case privs.Read:
				read = &ex[i]
			}
		}
		type key struct{ kind, via, priv string }
		var got []key
		for _, p := range update.Paths {
			got = append(got, key{p.Kind, p.Via, p.Row.Privilege})
		}
		want := []key{{"identity", "self", "update"}, {"group", "self", "admin"}, {"identity", "inherited_sub", "update"},
			{"group", "folder_stem_admin", "stem_admin"}}
		slices.SortFunc(got, func(a, b key) int { return strings.Compare(a.kind+a.via+a.priv, b.kind+b.via+b.priv) })
		slices.SortFunc(want, func(a, b key) int { return strings.Compare(a.kind+a.via+a.priv, b.kind+b.via+b.priv) })
		if !slices.Equal(got, want) {
			t.Errorf("update paths = %v, want %v", got, want)
		}
		if !update.Allowed {
			t.Error("update is not allowed")
		}
		for _, p := range update.Paths {
			if p.Text == "" || !strings.Contains(p.Text, "Ivan holds UPDATE on `app:foo:g2`") {
				t.Errorf("path text = %q", p.Text)
			}
		}
		// the stem_admin path names the folder it is held on
		for _, p := range update.Paths {
			if p.Via == "folder_stem_admin" && (p.OverFolder != "app:foo" || !strings.Contains(p.Text, "STEM_ADMIN on folder `app:foo`")) {
				t.Errorf("stem_admin path = %+v", p)
			}
		}
		// read comes only through admin (group) and stem_admin, not through update
		if len(read.Paths) != 2 {
			t.Errorf("read paths = %d, want 2 (admin via the group, stem_admin above)", len(read.Paths))
		}
		// a platform role is a path too
		ex, err = checker(c, privs.Subject{Identity: &w.ivan, TenantAdmin: true}).Explain(g2)
		if err != nil {
			t.Fatal(err)
		}
		if ex[0].Paths[0].Kind != "role" || ex[0].Paths[0].Role != "tenant_admin" {
			t.Errorf("first admin path = %+v, want the tenant_admin role", ex[0].Paths[0])
		}
		// an identity with nothing holds nothing
		ex, err = checker(c, asIdentity(w.pat)).Explain(g2)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range ex {
			if x.Allowed || len(x.Paths) != 0 {
				t.Errorf("Pat holds %s: %+v", x.Privilege, x.Paths)
			}
		}
	})
}

// ---------------------------------------------------------------- everyone

func TestPrivs_EveryoneNeedsTenantAdmin(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		g1 := privs.GroupObject(w.g1)
		in := privs.GrantInput{Object: g1, Privilege: privs.View, Holder: privs.Everyone()}
		notAdmin := env(c)
		notAdmin.TenantAdmin = false
		if _, _, err := privs.Grant(notAdmin, in); !isKind(err, privs.Forbidden) {
			t.Errorf("a grant to everyone without tenant_admin: %v, want forbidden", err)
		}
		if _, err := privs.SaveSettings(notAdmin, privs.DefaultSettings()); !isKind(err, privs.Forbidden) {
			t.Errorf("settings saved without tenant_admin: %v", err)
		}
		// a tenant admin may, for a privilege the policy allows
		if _, created, err := privs.Grant(env(c), in); err != nil || !created {
			t.Fatalf("tenant_admin grant to everyone: %v, created %v", err, created)
		}
		if !holds(t, checker(c, asIdentity(w.pat)), g1, privs.View) || !holds(t, checker(c, privs.Subject{}), g1, privs.View) {
			t.Error("everyone does not hold view")
		}
		if holds(t, checker(c, asIdentity(w.pat)), g1, privs.Read) {
			t.Error("everyone holds read")
		}
		// but not a privilege the policy does not allow, and never an admin one
		for _, p := range []privs.Privilege{privs.Update, privs.Admin} {
			if _, _, err := privs.Grant(env(c), privs.GrantInput{Object: g1, Privilege: p, Holder: privs.Everyone()}); !isKind(err, privs.Invalid) {
				t.Errorf("everyone %s: %v, want refused by the policy", p, err)
			}
		}
		// the policy can widen, but never to an admin-class privilege
		s := privs.DefaultSettings()
		s.EveryoneAllowed = append(s.EveryoneAllowed, privs.Update)
		if _, err := privs.SaveSettings(env(c), s); err != nil {
			t.Fatal(err)
		}
		if _, _, err := privs.Grant(env(c), privs.GrantInput{Object: g1, Privilege: privs.Update, Holder: privs.Everyone()}); err != nil {
			t.Errorf("everyone update after the policy allows it: %v", err)
		}
		s.EveryoneAllowed = append(s.EveryoneAllowed, privs.Admin)
		if _, err := privs.SaveSettings(env(c), s); !isKind(err, privs.Invalid) {
			t.Errorf("a policy that allows admin: %v", err)
		}
		// an inherited grant to everyone is a grant to everyone
		if _, _, err := privs.Grant(notAdmin, privs.GrantInput{Object: privs.FolderObject(w.app), Privilege: privs.View,
			Holder: privs.Everyone(), AppliesTo: "groups", Scope: "sub"}); !isKind(err, privs.Forbidden) {
			t.Errorf("an inherited grant to everyone without tenant_admin: %v", err)
		}
	})
}

func TestSettings(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		got, err := privs.LoadSettings(c)
		if err != nil || len(got.Defaults) != 0 || len(got.EveryoneAllowed) == 0 {
			t.Fatalf("defaults = %+v, %v", got, err)
		}
		bad := map[string]privs.Settings{
			"unknown privilege":  {EveryoneAllowed: []privs.Privilege{"bogus"}},
			"a default outside":  {EveryoneAllowed: []privs.Privilege{privs.View}, Defaults: []privs.Default{{privs.Group, privs.Read}}},
			"wrong object type":  {EveryoneAllowed: []privs.Privilege{privs.View}, Defaults: []privs.Default{{privs.Folder, privs.View}}},
			"attr def, wrong":    {EveryoneAllowed: []privs.Privilege{privs.AttrView}, Defaults: []privs.Default{{privs.AttrDef, privs.View}}},
			"stem_admin default": {EveryoneAllowed: []privs.Privilege{privs.StemAdmin}},
		}
		for name, s := range bad {
			if _, err := privs.SaveSettings(env(c), s); !isKind(err, privs.Invalid) {
				t.Errorf("%s: %v, want invalid", name, err)
			}
		}
		// an attribute definition can have a default from GR-7 on
		if s, err := privs.SaveSettings(env(c), privs.Settings{EveryoneAllowed: []privs.Privilege{privs.AttrView},
			Defaults: []privs.Default{{privs.AttrDef, privs.AttrView}}}); err != nil || len(s.Defaults) != 1 {
			t.Errorf("an attr_view default for attribute definitions: %+v, %v", s, err)
		}
		saved, err := privs.SaveSettings(env(c), privs.Settings{EveryoneAllowed: []privs.Privilege{privs.Read, privs.View, privs.View},
			Defaults: []privs.Default{{privs.Group, privs.View}, {privs.Group, privs.View}}})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(saved.EveryoneAllowed, []privs.Privilege{privs.Read, privs.View}) || len(saved.Defaults) != 1 {
			t.Errorf("not canonical: %+v", saved)
		}
		if again, err := privs.LoadSettings(c); err != nil || !slices.Equal(again.EveryoneAllowed, saved.EveryoneAllowed) {
			t.Errorf("reload = %+v, %v", again, err)
		}
	})
}

// ---------------------------------------------------------------- creator and defaults, events

func TestCreatorAndDefaultPrivileges(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		if _, err := privs.SaveSettings(env(c), privs.Settings{EveryoneAllowed: []privs.Privilege{privs.View, privs.StemView},
			Defaults: []privs.Default{{privs.Group, privs.View}, {privs.Folder, privs.StemView}}}); err != nil {
			t.Fatal(err)
		}
		e := model.Env{Tx: c, Now: storetest.Now, ByIdentity: &w.ivan}
		f, err := e.CreateFolder(model.CreateFolderInput{Parent: w.app, Extension: "mine"})
		if err != nil {
			t.Fatal(err)
		}
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: f.ID, Extension: "team"})
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := c.GrpPrivilegesOf("group", string(g.ID))
		var got []string
		for _, r := range rows {
			got = append(got, r.HolderType+":"+r.Privilege+":"+r.Source)
		}
		slices.Sort(got)
		if want := []string{"everyone:view:creator_default", "identity:admin:creator_default"}; !slices.Equal(got, want) {
			t.Errorf("group rows = %v, want %v", got, want)
		}
		if !holds(t, checker(c, asIdentity(w.ivan)), privs.GroupObject(g.ID), privs.Admin) {
			t.Error("the creator is not admin of the group")
		}
		if !holds(t, checker(c, asIdentity(w.ivan)), privs.FolderObject(f.ID), privs.StemAdmin) {
			t.Error("the creator is not stem_admin of the folder")
		}
		if !holds(t, checker(c, asIdentity(w.pat)), privs.FolderObject(f.ID), privs.StemView) {
			t.Error("the default stem_view for everyone is missing")
		}
		// a creator without an identity link (a tenant admin) gets no row of their own
		g2, err := (model.Env{Tx: c, Now: storetest.Now}).CreateGroup(model.CreateGroupInput{Folder: f.ID, Extension: "other"})
		if err != nil {
			t.Fatal(err)
		}
		if rows, _ := c.GrpPrivilegesOf("group", string(g2.ID)); len(rows) != 1 || rows[0].HolderType != "everyone" {
			t.Errorf("a creator without an identity: %d rows", len(rows))
		}
		// a copy is the copier's own
		cp, err := e.CopyGroup(g2.ID, model.CopyInput{Parent: f.ID, Extension: "copy"})
		if err != nil {
			t.Fatal(err)
		}
		if !holds(t, checker(c, asIdentity(w.ivan)), privs.GroupObject(cp.ID), privs.Admin) {
			t.Error("the copier is not admin of the copy")
		}
	})
}

// TestPrivs_EventsAndAudit: a grant and a revoke each write their change event
// (so the PIT shows when a privilege was held) and their audit event, and a
// deleted folder takes its privileges with it.
func TestPrivs_EventsAndAudit(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		f, err := (model.Env{Tx: c, Now: storetest.Now}).CreateFolder(model.CreateFolderInput{Extension: "tmp"})
		if err != nil {
			t.Fatal(err)
		}
		r1 := w.grant(t, c, privs.FolderObject(f.ID), privs.Create, privs.IdentityHolder(w.ivan), "", "")
		r2 := w.grant(t, c, privs.FolderObject(f.ID), privs.StemView, privs.IdentityHolder(w.alice), "", "")
		if again, created, err := privs.Grant(env(c), privs.GrantInput{Object: privs.FolderObject(f.ID), Privilege: privs.Create,
			Holder: privs.IdentityHolder(w.ivan)}); err != nil || created || again.ID != r1.ID {
			t.Errorf("repeating a grant: %v, created %v", err, created)
		}
		open := func() (n int) {
			ps, err := c.GrpPitPrivileges()
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range ps {
				if p.EndAt == nil {
					n++
				}
			}
			return n
		}
		if n := open(); n != 2 {
			t.Fatalf("open PIT privilege intervals = %d, want 2", n)
		}
		if _, err := privs.Revoke(env(c), r1.ID); err != nil {
			t.Fatal(err)
		}
		if n := open(); n != 1 {
			t.Errorf("open intervals after a revoke = %d, want 1", n)
		}
		if _, err := privs.Revoke(env(c), r1.ID); !isKind(err, privs.NotFound) {
			t.Errorf("revoking twice: %v", err)
		}
		if err := (model.Env{Tx: c, Now: storetest.Now}).DeleteFolder(f.ID); err != nil {
			t.Fatal(err)
		}
		if rows, _ := c.GrpPrivilegesOf("folder", string(f.ID)); len(rows) != 0 {
			t.Errorf("a deleted folder keeps %d privileges", len(rows))
		}
		if n := open(); n != 0 {
			t.Errorf("open intervals after the folder is deleted = %d", n)
		}
		_ = r2
		for action, want := range map[string]int{"groups.privilege.granted": 2, "groups.privilege.revoked": 2} {
			evs, err := c.AuditEvents(store.AuditFilter{Action: action})
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != want {
				t.Errorf("%s audit events = %d, want %d", action, len(evs), want)
			}
		}
	})
}

func TestGrant_Refusals(t *testing.T) {
	w := newWorld(t)
	w.inTx(t, func(c *store.TenantTx) {
		g1 := privs.GroupObject(w.g1)
		for name, tc := range map[string]struct {
			in   privs.GrantInput
			kind privs.Kind
		}{
			"unknown privilege":               {privs.GrantInput{Object: g1, Privilege: "bogus", Holder: privs.IdentityHolder(w.ivan)}, privs.Invalid},
			"unknown holder":                  {privs.GrantInput{Object: g1, Privilege: privs.View, Holder: privs.Holder{Type: "robot"}}, privs.Invalid},
			"unknown identity":                {privs.GrantInput{Object: g1, Privilege: privs.View, Holder: privs.IdentityHolder(99999)}, privs.NotFound},
			"unknown group":                   {privs.GrantInput{Object: g1, Privilege: privs.View, Holder: privs.GroupHolder("nope")}, privs.NotFound},
			"unknown object":                  {privs.GrantInput{Object: privs.GroupObject("nope"), Privilege: privs.View, Holder: privs.IdentityHolder(w.ivan)}, privs.NotFound},
			"attribute def":                   {privs.GrantInput{Object: privs.AttrDefObject("x"), Privilege: privs.AttrView, Holder: privs.IdentityHolder(w.ivan)}, privs.NotFound},
			"group privilege on a definition": {privs.GrantInput{Object: privs.AttrDefObject("x"), Privilege: privs.View, Holder: privs.IdentityHolder(w.ivan)}, privs.Invalid},
		} {
			if _, _, err := privs.Grant(env(c), tc.in); !isKind(err, tc.kind) {
				t.Errorf("%s: %v, want kind %d", name, err, tc.kind)
			}
		}
		// a mirrored folder is read-only (K11), and a deleted group takes no grants
		if err := c.SetGrpFolderManagedBy(w.foo, store.ManagedByGrouperMirror); err != nil {
			t.Fatal(err)
		}
		if _, _, err := privs.Grant(env(c), privs.GrantInput{Object: privs.GroupObject(w.g2), Privilege: privs.View,
			Holder: privs.IdentityHolder(w.ivan)}); !isKind(err, privs.Conflict) {
			t.Errorf("a grant in a mirrored folder: %v", err)
		}
		if err := (model.Env{Tx: c, Now: storetest.Now}).DeleteGroup(w.g1); err != nil {
			t.Fatal(err)
		}
		if _, _, err := privs.Grant(env(c), privs.GrantInput{Object: g1, Privilege: privs.View, Holder: privs.IdentityHolder(w.ivan)}); !isKind(err, privs.Conflict) {
			t.Errorf("a grant on a deleted group: %v", err)
		}
	})
}
