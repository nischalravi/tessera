package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group privileges (issue #47, GR-4): a tenant's privilege rows and settings are
// its own. Another tenant's privilege, group or identity ids look nonexistent,
// the same grant can exist in two tenants, and a row that names another
// tenant's folder, group or identity (or a platform user linked to another
// tenant's identity) is refused by the guard triggers.

type privIDs struct {
	g1     store.GroupID
	folder store.FolderID
	ident  int64
	row    string // a group row held by an identity
	rowG   string // a folder row held by g1
	user   uuid.UUID
}

func seedGroupPrivs(t *testing.T, f *storetest.Fixture) map[string]privIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]privIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := privIDs{g1: base[tn.Slug].g1, ident: base[tn.Slug].ident}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fo, err := c.GrpFolderByName("app")
			if err != nil {
				return err
			}
			ids.folder = fo.ID
			r1 := &store.GrpPrivilege{ObjectType: "group", ObjectID: string(ids.g1), Privilege: "admin", HolderType: store.HolderIdentity,
				HolderIdentity: &ids.ident, AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
			if err := c.InsertGrpPrivilege(r1); err != nil {
				return err
			}
			g := ids.g1
			r2 := &store.GrpPrivilege{ObjectType: "folder", ObjectID: string(ids.folder), Privilege: "read", HolderType: store.HolderGroup,
				HolderGroup: &g, AppliesTo: "groups", Scope: "sub", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
			if err := c.InsertGrpPrivilege(r2); err != nil {
				return err
			}
			ids.row, ids.rowG = r1.ID, r2.ID
			if err := c.SetGrpPrivSettings(`{"everyone_allowed":["view"],"defaults":[],"for":"`+tn.Slug+`"}`, storetest.Now, nil); err != nil {
				return err
			}
			u := &store.PlatformUser{DisplayName: "U " + tn.Slug, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			ids.user = u.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupPrivilegeTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupPrivs(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	ctx := context.Background()
	isNotFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpPrivilege(a.row)
		isNotFound("GrpPrivilege(A's)", err)
		if own, err := c.GrpPrivilege(b.row); err != nil || own.HolderIdentity == nil || *own.HolderIdentity != b.ident {
			t.Errorf("GrpPrivilege(B's) = %+v, %v", own, err)
		}
		if rows, err := c.GrpPrivilegesOf("group", string(a.g1)); err != nil || len(rows) != 0 {
			t.Errorf("GrpPrivilegesOf(A's group) = %d rows, %v", len(rows), err)
		}
		if rows, err := c.GrpPrivilegesOf("group", string(b.g1)); err != nil || len(rows) != 1 || rows[0].ID != b.row {
			t.Errorf("GrpPrivilegesOf(B's group) = %v, %v", rows, err)
		}
		if rows, err := c.GrpPrivilegesOfHolderGroup(a.g1); err != nil || len(rows) != 0 {
			t.Errorf("GrpPrivilegesOfHolderGroup(A's) = %d rows, %v", len(rows), err)
		}
		if rows, err := c.GrpPrivilegesOfHolderIdentity(a.ident); err != nil || len(rows) != 0 {
			t.Errorf("GrpPrivilegesOfHolderIdentity(A's) = %d rows, %v", len(rows), err)
		}
		// the natural key of A's row finds nothing in B
		_, err = c.FindGrpPrivilege(&store.GrpPrivilege{ObjectType: "group", ObjectID: string(a.g1), Privilege: "admin",
			HolderType: store.HolderIdentity, HolderIdentity: &a.ident, AppliesTo: "self", Scope: "self"})
		isNotFound("FindGrpPrivilege(A's)", err)
		isNotFound("DeleteGrpPrivilege(A's)", c.DeleteGrpPrivilege(a.row))
		isNotFound("SetPlatformUserIdentity(A's user)", c.SetPlatformUserIdentity(a.user, &b.ident))
		s, err := c.GrpPrivSettings()
		if err != nil || s.Body != `{"everyone_allowed":["view"],"defaults":[],"for":"tenant-b"}` {
			t.Errorf("GrpPrivSettings = %+v, %v; want B's own", s, err)
		}
		return nil
	})
	// B's writes leave A's rows and settings alone
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SetGrpPrivSettings(`{"everyone_allowed":[],"defaults":[]}`, storetest.Now, nil); err != nil {
			t.Error(err)
		}
		return c.DeleteGrpPrivilege(b.row)
	})
	err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if _, err := c.GrpPrivilege(a.row); err != nil {
			t.Errorf("A's row after B's delete: %v", err)
		}
		if s, err := c.GrpPrivSettings(); err != nil || s.Body != `{"everyone_allowed":["view"],"defaults":[],"for":"tenant-a"}` {
			t.Errorf("A's settings after B's save = %+v, %v", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the same grant in both tenants is fine: the unique indexes start with tenant_id
	inB(t, f, func(c *store.TenantTx) error {
		r := &store.GrpPrivilege{ObjectType: "group", ObjectID: string(b.g1), Privilege: "admin", HolderType: store.HolderIdentity,
			HolderIdentity: &b.ident, AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
		if err := c.InsertGrpPrivilege(r); err != nil {
			t.Errorf("B repeats the grant A has: %v", err)
		}
		// but within a tenant a grant is made once
		dup := *r
		dup.ID = ""
		if err := c.InsertGrpPrivilege(&dup); err == nil {
			t.Error("a grant was made twice in one tenant")
		}
		return nil
	})
}

func TestIsolation_GroupPrivilegeCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupPrivs(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	row := func(mod func(r *store.GrpPrivilege)) func(c *store.TenantTx) error {
		return func(c *store.TenantTx) error {
			r := &store.GrpPrivilege{ObjectType: "group", ObjectID: string(b.g1), Privilege: "view", HolderType: store.HolderEveryone,
				AppliesTo: "self", Scope: "self", Source: store.PrivSourceAPI, CreatedAt: storetest.Now}
			mod(r)
			return c.InsertGrpPrivilege(r)
		}
	}
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"on A's group": row(func(r *store.GrpPrivilege) { r.ObjectID = string(a.g1) }),
		"on A's folder": row(func(r *store.GrpPrivilege) {
			r.ObjectType, r.ObjectID, r.Privilege = "folder", string(a.folder), "stem_view"
		}),
		"held by A's identity": row(func(r *store.GrpPrivilege) {
			r.HolderType, r.HolderIdentity = store.HolderIdentity, &a.ident
		}),
		"held by A's group": row(func(r *store.GrpPrivilege) {
			g := a.g1
			r.HolderType, r.HolderGroup = store.HolderGroup, &g
		}),
		"stamped with A": row(func(r *store.GrpPrivilege) { r.TenantID = f.A.ID }),
		"user linked to A's identity": func(c *store.TenantTx) error {
			return c.SetPlatformUserIdentity(b.user, &a.ident)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	// the link to the tenant's own identity works, and null removes it
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SetPlatformUserIdentity(b.user, &b.ident); err != nil {
			t.Fatal(err)
		}
		if u, err := c.PlatformUser(b.user); err != nil || u.IdentityID == nil || *u.IdentityID != b.ident {
			t.Errorf("linked user = %+v, %v", u, err)
		}
		if err := c.SetPlatformUserIdentity(b.user, nil); err != nil {
			t.Fatal(err)
		}
		if u, _ := c.PlatformUser(b.user); u.IdentityID != nil {
			t.Error("the link was not removed")
		}
		return nil
	})
}

// groupPrivsCovered lists the repository methods of GR-4 that
// TestIsolation_GroupPrivilegeTables exercises.
func groupPrivsCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"InsertGrpPrivilege", "GrpPrivilege", "GrpPrivilegesOf", "FindGrpPrivilege", "DeleteGrpPrivilege",
		"GrpPrivilegesOfHolderGroup", "GrpPrivilegesOfHolderIdentity", "GrpPrivSettings", "SetGrpPrivSettings",
		"SetPlatformUserIdentity", "IdentityLinkRequest", "PutIdentityLinkRequest", "DeleteIdentityLinkRequest"} {
		m[name] = true
	}
	return m
}

// TestIsolation_IdentityLinkRequests (#357): a pending link change is the
// tenant's own. Another tenant's request looks nonexistent and cannot be
// deleted, and a request naming another tenant's user or identity is refused.
func TestIsolation_IdentityLinkRequests(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupPrivs(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	exp := storetest.Now.Add(time.Hour)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		x := ids[tn.Slug]
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.SetPlatformUserIdentity(x.user, &x.ident); err != nil {
				return err
			}
			return c.PutIdentityLinkRequest(&store.IdentityLinkRequest{UserID: x.user, PreviousIdentityID: &x.ident,
				RequestedByUserID: x.user, RequestedBy: "admin " + tn.Slug, RequestedAt: storetest.Now, ExpiresAt: exp})
		}); err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.IdentityLinkRequest(a.user); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("IdentityLinkRequest(A's user) = %v, want ErrNotFound", err)
		}
		r, err := c.IdentityLinkRequest(b.user)
		if err != nil || r.RequestedBy != "admin "+f.B.Slug || r.IdentityID != nil || r.PreviousIdentityID == nil ||
			*r.PreviousIdentityID != b.ident || !r.ExpiresAt.Equal(exp) {
			t.Errorf("IdentityLinkRequest(B's user) = %+v, %v", r, err)
		}
		// replacing B's own request works
		r.IdentityID, r.RequestedBy = &b.ident, "other admin"
		if err := c.PutIdentityLinkRequest(r); err != nil {
			t.Fatal(err)
		}
		if r, err := c.IdentityLinkRequest(b.user); err != nil || r.RequestedBy != "other admin" || r.IdentityID == nil {
			t.Errorf("replaced request = %+v, %v", r, err)
		}
		// deleting A's request from B is a no-op
		return c.DeleteIdentityLinkRequest(a.user)
	})
	for name, r := range map[string]store.IdentityLinkRequest{
		"for A's user":         {UserID: a.user, RequestedByUserID: b.user},
		"by A's user":          {UserID: b.user, RequestedByUserID: a.user},
		"to A's identity":      {UserID: b.user, RequestedByUserID: b.user, IdentityID: &a.ident},
		"against A's identity": {UserID: b.user, RequestedByUserID: b.user, PreviousIdentityID: &a.ident},
	} {
		t.Run(name, func(t *testing.T) {
			r.RequestedBy, r.RequestedAt, r.ExpiresAt = "x", storetest.Now, exp
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.PutIdentityLinkRequest(&r) })
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		r, err := c.IdentityLinkRequest(a.user)
		if err != nil || r.RequestedBy != "admin "+f.A.Slug {
			t.Errorf("A's request after B's calls = %+v, %v", r, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.DeleteIdentityLinkRequest(b.user); err != nil {
			t.Fatal(err)
		}
		if _, err := c.IdentityLinkRequest(b.user); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("after delete: %v", err)
		}
		return nil
	})
}
