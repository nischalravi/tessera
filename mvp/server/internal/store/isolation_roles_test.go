package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Business role isolation (issue #161): a tenant sees and changes only its
// own roles, entitlements, versions, members and role requests; another
// tenant's ids look nonexistent and rows naming them are refused by the
// guard triggers.

type roleRows struct {
	user  *store.PlatformUser
	role  string
	req   string
	group int64
	alice int64
	edge  int64
}

func seedRoleRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) roleRows {
	t.Helper()
	r := roleRows{role: "role-" + tag, req: "rreq-" + tag, group: tn.IDs["group:okta:eng"], alice: tn.IDs["alice"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "role admin " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		uid := r.user.ID.String()
		if err := c.InsertBusinessRole(&store.BusinessRole{ID: r.role, Key: "engineer", Name: "Engineer " + tag, Risk: "low",
			Status: store.RoleActive, Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.SetRoleEntitlements(r.role, []int64{r.group}); err != nil {
			return err
		}
		ref := `{"commit":"c-` + tag + `"}`
		if err := c.AddRoleVersion(&store.RoleVersion{RoleID: r.role, Version: 1, Snapshot: "{}", ChangedBy: &uid,
			Actor: "x", ChangedAt: storetest.Now, PolicyRef: &ref}); err != nil {
			return err
		}
		if err := c.InsertRoleRequest(&store.RoleRequest{ID: r.req, RoleID: r.role, BeneficiaryID: r.alice,
			RequestedBy: uid, Justification: "x", RequestedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.AddRoleMember(&store.RoleMember{RoleID: r.role, IdentityID: r.alice, Source: store.MemberManual,
			AssignedBy: &uid, AssignedAt: storetest.Now}); err != nil {
			return err
		}
		var err error
		r.edge, err = c.InsertEdge(&store.GrantEdge{Src: key("account", tn.IDs["acct:okta:alice"]),
			Dst: key("group", tn.IDs["group:okta:payments-clerks"]), Relation: "member_of", Source: "role", CreatedAt: storetest.Now})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func roleFixture(t *testing.T) (*storetest.Fixture, roleRows, roleRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedRoleRows(t, f.DB, f.A, "a"), seedRoleRows(t, f.DB, f.B, "b")
}

func TestIsolation_RoleReads(t *testing.T) {
	f, a, b := roleFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if rs, err := c.BusinessRoles(); err != nil || len(rs) != 1 || rs[0].ID != b.role {
			t.Errorf("BusinessRoles = %v, %v", rs, err)
		}
		if _, err := c.BusinessRole(a.role); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BusinessRole(A's) = %v", err)
		}
		if _, err := c.BusinessRoleByName("Engineer a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BusinessRoleByName(A's) = %v", err)
		}
		// the same key in two tenants is two roles: each tenant resolves it to its own
		if r, err := c.BusinessRoleByKey("engineer"); err != nil || r.ID != b.role {
			t.Errorf("BusinessRoleByKey(engineer) = %v, %v; want B's role", r, err)
		}
		if _, err := c.BusinessRoleByKey("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BusinessRoleByKey(nope) = %v", err)
		}
		if vs, err := c.RoleVersions(b.role); err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || *vs[0].PolicyRef != `{"commit":"c-b"}` {
			t.Errorf("RoleVersions(B's) policy_ref = %v, %v", vs, err)
		}
		if es, err := c.AllRoleEntitlements(); err != nil || len(es) != 1 || es[0].RoleID != b.role {
			t.Errorf("AllRoleEntitlements = %v, %v", es, err)
		}
		if gs, err := c.RoleEntitlements(a.role); err != nil || len(gs) != 0 {
			t.Errorf("RoleEntitlements(A's) = %v, %v", gs, err)
		}
		if vs, err := c.RoleVersions(a.role); err != nil || len(vs) != 0 {
			t.Errorf("RoleVersions(A's) = %v, %v", vs, err)
		}
		if ms, err := c.AllRoleMembers(); err != nil || len(ms) != 1 || ms[0].RoleID != b.role {
			t.Errorf("AllRoleMembers = %v, %v", ms, err)
		}
		if ms, err := c.RoleMembers(a.role); err != nil || len(ms) != 0 {
			t.Errorf("RoleMembers(A's) = %v, %v", ms, err)
		}
		if ms, err := c.IdentityRoles(a.alice); err != nil || len(ms) != 0 {
			t.Errorf("IdentityRoles(A's) = %v, %v", ms, err)
		}
		if _, err := c.RoleRequest(a.req); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RoleRequest(A's) = %v", err)
		}
		if qs, err := c.RoleRequests(store.RoleRequestFilter{}); err != nil || len(qs) != 1 || qs[0].ID != b.req {
			t.Errorf("RoleRequests = %v, %v", qs, err)
		}
		if qs, err := c.RoleRequests(store.RoleRequestFilter{InvolvingUser: a.user.ID.String(), InvolvingIdentity: a.alice}); err != nil || len(qs) != 0 {
			t.Errorf("RoleRequests(A's user) = %v, %v", qs, err)
		}
		if es, err := c.EdgesTo(key("group", f.A.IDs["group:okta:payments-clerks"])); err != nil || len(es) != 0 {
			t.Errorf("EdgesTo(A's group) = %v, %v", es, err)
		}
		return nil
	})
}

// roleMutations change one of A's rows (or point B's at A's); run in B they
// fail and leave A alone.
var roleMutations = map[string]func(c *store.TenantTx, a, b roleRows) error{
	"InsertBusinessRole": func(c *store.TenantTx, a, b roleRows) error {
		return c.InsertBusinessRole(&store.BusinessRole{ID: "x", Name: "x", Risk: "low", Status: store.RoleActive,
			Version: 1, OwnerIdentityID: &a.alice, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"SaveBusinessRole": func(c *store.TenantTx, a, _ roleRows) error {
		return c.SaveBusinessRole(&store.BusinessRole{ID: a.role, Name: "taken", Risk: "high", Status: store.RoleRetired,
			Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"SetRoleEntitlements": func(c *store.TenantTx, a, b roleRows) error {
		if err := c.SetRoleEntitlements(b.role, []int64{a.group}); err != nil {
			return err
		}
		return errors.New("accepted another tenant's group")
	},
	"SetRoleEntitlements(A's role)": func(c *store.TenantTx, a, b roleRows) error {
		return c.SetRoleEntitlements(a.role, []int64{b.group})
	},
	"AddRoleVersion": func(c *store.TenantTx, a, _ roleRows) error {
		return c.AddRoleVersion(&store.RoleVersion{RoleID: a.role, Version: 9, Snapshot: "{}", Actor: "x", ChangedAt: storetest.Now})
	},
	"AddRoleMember": func(c *store.TenantTx, a, b roleRows) error {
		return c.AddRoleMember(&store.RoleMember{RoleID: b.role, IdentityID: a.alice, Source: store.MemberManual, AssignedAt: storetest.Now})
	},
	"DeleteRoleMember": func(c *store.TenantTx, a, _ roleRows) error {
		if err := c.DeleteRoleMember(a.role, a.alice); err != nil {
			return err
		}
		return store.ErrNotFound // nothing to delete in B; A's dump proves the member stayed
	},
	"InsertRoleRequest": func(c *store.TenantTx, a, b roleRows) error {
		return c.InsertRoleRequest(&store.RoleRequest{ID: "x", RoleID: a.role, BeneficiaryID: b.alice,
			RequestedBy: b.user.ID.String(), Justification: "x", RequestedAt: storetest.Now})
	},
	"SaveRoleRequest": func(c *store.TenantTx, a, _ roleRows) error {
		return c.SaveRoleRequest(&store.RoleRequest{ID: a.req, Status: store.RequestCancelled}, store.RequestPending)
	},
	"DeleteRoleEdge": func(c *store.TenantTx, a, _ roleRows) error {
		if err := c.DeleteRoleEdge(a.edge); err != nil {
			return err
		}
		return store.ErrNotFound
	},
}

func TestIsolation_RoleMutationsScoped(t *testing.T) {
	for name, fn := range roleMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := roleFixture(t)
			before := roleDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Logf("%s across tenants = %v", name, err)
			}
			if after := roleDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestRoles_VersionsAppendOnlyAndPendingUnique(t *testing.T) {
	f, a, _ := roleFixture(t)
	ctx := context.Background()
	// a second pending request for the same person and role is refused
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.InsertRoleRequest(&store.RoleRequest{ID: "dup", RoleID: a.role, BeneficiaryID: a.alice,
			RequestedBy: a.user.ID.String(), Justification: "x", RequestedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a second pending role request was accepted")
	}
	// a stale version does not save
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveBusinessRole(&store.BusinessRole{ID: a.role, Name: "x", Risk: "low", Status: store.RoleActive,
			Version: 3, UpdatedAt: storetest.Now}, 2)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SaveBusinessRole at a stale version = %v, want ErrNotFound", err)
	}
	// the same version twice is refused (versions are unique per role)
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.AddRoleVersion(&store.RoleVersion{RoleID: a.role, Version: 1, Snapshot: "{}", Actor: "x", ChangedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a duplicate version was accepted")
	}
}

func roleDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		roles, err := c.BusinessRoles()
		if err != nil {
			return err
		}
		ents, err := c.AllRoleEntitlements()
		if err != nil {
			return err
		}
		members, err := c.AllRoleMembers()
		if err != nil {
			return err
		}
		reqs, err := c.RoleRequests(store.RoleRequestFilter{})
		if err != nil {
			return err
		}
		var vs []*store.RoleVersion
		for _, r := range roles {
			v, err := c.RoleVersions(r.ID)
			if err != nil {
				return err
			}
			vs = append(vs, v...)
		}
		b, err := json.Marshal([]any{roles, ents, members, reqs, vs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func rolesCovered() map[string]bool {
	out := map[string]bool{}
	for k := range roleMutations {
		out[k] = true
	}
	for _, k := range []string{"BusinessRoles", "BusinessRole", "BusinessRoleByName", "BusinessRoleByKey", "AllRoleEntitlements",
		"RoleEntitlements", "RoleVersions", "AllRoleMembers", "RoleMembers", "IdentityRoles", "RoleRequest",
		"RoleRequests", "EdgesTo"} {
		out[k] = true // TestIsolation_RoleReads
	}
	return out
}

// A role key is unique within a tenant: a second role with it is refused, a role with no key is not
// constrained, and the same key in another tenant is fine (roleFixture gives both tenants "engineer").
func TestIsolation_RoleKeyUniquePerTenant(t *testing.T) {
	f, _, _ := roleFixture(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertBusinessRole(&store.BusinessRole{ID: "dup", Key: "engineer", Name: "Dup", Risk: "low",
			Status: store.RoleActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a second role with the key engineer was saved in one tenant")
	}
	inA(t, f, func(c *store.TenantTx) error {
		for _, id := range []string{"n1", "n2"} {
			if err := c.InsertBusinessRole(&store.BusinessRole{ID: id, Name: "No key " + id, Risk: "low", Status: store.RoleActive,
				Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
				t.Errorf("a role without a key was refused: %v", err)
			}
		}
		return nil
	})
}
