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

// Role memberships in reviews (issue #214): a tenant sees and changes only
// its own exclusions, membership items and schedule role scopes; rows naming
// another tenant's roles, people, items or templates are refused by the guard
// triggers.

type revRoleRows struct {
	roleRows
	item int64
	tmpl string
}

func seedRevRoleRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) revRoleRows {
	t.Helper()
	r := revRoleRows{roleRows: seedRoleRows(t, db, tn, tag), tmpl: "rtmpl-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		var err error
		r.item, err = c.InsertMembershipItem(&store.ReviewItem{CampaignID: tn.IDs["campaign"], IdentityID: r.alice,
			EdgeSrc: "role:" + r.role, EdgeDst: key("identity", r.alice), GrantLabel: "Role " + tag, Reasons: []string{"role_review"},
			Context: json.RawMessage(`{}`)}, r.role, store.MemberManual)
		if err != nil {
			return err
		}
		uid := r.user.ID.String()
		if err := c.InsertRoleExclusion(&store.RoleExclusion{RoleID: r.role, IdentityID: r.alice, Reason: "x", Version: 1,
			ExcludedBy: &uid, ExcludedActor: "x", ExcludedAt: storetest.Now, ReviewItemID: &r.item}); err != nil {
			return err
		}
		if err := c.InsertReviewTemplate(&store.ReviewTemplate{ID: r.tmpl, Name: "Roles " + tag, UnusedDays: 60, DurationDays: 14,
			ReminderDays: 3, CloseOut: "revoke", EscalationDays: 7, Recurrence: "once", CreatedAt: storetest.Now,
			UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.SetReviewTemplateRoles(r.tmpl, []string{r.role})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func revRoleFixture(t *testing.T) (*storetest.Fixture, revRoleRows, revRoleRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedRevRoleRows(t, f.DB, f.A, "a"), seedRevRoleRows(t, f.DB, f.B, "b")
}

func TestIsolation_ReviewRoleReads(t *testing.T) {
	f, a, b := revRoleFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if xs, err := c.AllRoleExclusions(); err != nil || len(xs) != 1 || xs[0].RoleID != b.role {
			t.Errorf("AllRoleExclusions = %v, %v", xs, err)
		}
		if xs, err := c.RoleExclusions(a.role); err != nil || len(xs) != 0 {
			t.Errorf("RoleExclusions(A's) = %v, %v", xs, err)
		}
		if _, err := c.ReviewItemRole(a.item); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReviewItemRole(A's) = %v", err)
		}
		if rs, err := c.ReviewItemRole(b.item); err != nil || rs.RoleID != b.role {
			t.Errorf("ReviewItemRole(B's) = %v, %v", rs, err)
		}
		if rs, err := c.CampaignItemRoles(f.A.IDs["campaign"]); err != nil || len(rs) != 0 {
			t.Errorf("CampaignItemRoles(A's) = %v, %v", rs, err)
		}
		if rs, err := c.FlaggedRoleItems(a.role); err != nil || len(rs) != 0 {
			t.Errorf("FlaggedRoleItems(A's) = %v, %v", rs, err)
		}
		if ids, err := c.ReviewTemplateRoles(a.tmpl); err != nil || len(ids) != 0 {
			t.Errorf("ReviewTemplateRoles(A's) = %v, %v", ids, err)
		}
		if ids, err := c.ReviewTemplateRoles(b.tmpl); err != nil || len(ids) != 1 || ids[0] != b.role {
			t.Errorf("ReviewTemplateRoles(B's) = %v, %v", ids, err)
		}
		return nil
	})
}

var revRoleMutations = map[string]func(c *store.TenantTx, a, b revRoleRows, af, bf storetest.Tenant) error{
	"InsertRoleExclusion": func(c *store.TenantTx, a, b revRoleRows, _, _ storetest.Tenant) error {
		return c.InsertRoleExclusion(&store.RoleExclusion{RoleID: a.role, IdentityID: b.alice, Reason: "x", Version: 7,
			ExcludedActor: "x", ExcludedAt: storetest.Now})
	},
	"InsertRoleExclusion(A's person)": func(c *store.TenantTx, a, b revRoleRows, _, _ storetest.Tenant) error {
		return c.InsertRoleExclusion(&store.RoleExclusion{RoleID: b.role, IdentityID: a.alice, Reason: "x", Version: 7,
			ExcludedActor: "x", ExcludedAt: storetest.Now})
	},
	"RemoveRoleExclusion": func(c *store.TenantTx, a, _ revRoleRows, _, _ storetest.Tenant) error {
		return c.RemoveRoleExclusion(a.role, a.alice, 2, storetest.Now, nil, "x")
	},
	"DecideMembershipItem": func(c *store.TenantTx, a, _ revRoleRows, _, _ storetest.Tenant) error {
		applied, err := c.DecideMembershipItem(a.item, "revoke", nil, storetest.Now, store.UserRef{}, store.ResolveFlag)
		if err == nil && !applied {
			err = store.ErrNotFound
		}
		return err
	},
	"InsertMembershipItem": func(c *store.TenantTx, a, b revRoleRows, af, _ storetest.Tenant) error {
		_, err := c.InsertMembershipItem(&store.ReviewItem{CampaignID: af.IDs["campaign"], IdentityID: b.alice,
			EdgeSrc: "role:" + b.role, EdgeDst: key("identity", b.alice), GrantLabel: "x", Reasons: []string{"x"},
			Context: json.RawMessage(`{}`)}, b.role, store.MemberManual)
		return err
	},
	"InsertMembershipItem(A's role)": func(c *store.TenantTx, a, b revRoleRows, _, bf storetest.Tenant) error {
		_, err := c.InsertMembershipItem(&store.ReviewItem{CampaignID: bf.IDs["campaign"], IdentityID: b.alice,
			EdgeSrc: "role:" + a.role, EdgeDst: key("identity", b.alice), GrantLabel: "x", Reasons: []string{"x"},
			Context: json.RawMessage(`{}`)}, a.role, store.MemberManual)
		return err
	},
	"SetReviewTemplateRoles": func(c *store.TenantTx, a, _ revRoleRows, _, _ storetest.Tenant) error {
		return c.SetReviewTemplateRoles(a.tmpl, []string{a.role})
	},
	"SetReviewTemplateRoles(A's role)": func(c *store.TenantTx, a, b revRoleRows, _, _ storetest.Tenant) error {
		return c.SetReviewTemplateRoles(b.tmpl, []string{a.role})
	},
}

func TestIsolation_ReviewRoleMutationsScoped(t *testing.T) {
	for name, fn := range revRoleMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := revRoleFixture(t)
			before := revRoleDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b, f.A, f.B) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if revRoleDump(t, f.DB, f.A.ID, a) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// The exclusion list is append-only and an active exclusion is unique.
func TestReviewRoles_ExclusionsAppendOnlyAndUnique(t *testing.T) {
	f, a, _ := revRoleFixture(t)
	ctx := context.Background()
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.InsertRoleExclusion(&store.RoleExclusion{RoleID: a.role, IdentityID: a.alice, Reason: "again", Version: 2,
			ExcludedActor: "x", ExcludedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a second active exclusion of the same person was accepted")
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.RemoveRoleExclusion(a.role, a.alice, 2, storetest.Now, nil, "back in")
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		xs, err := c.RoleExclusions(a.role)
		if err != nil || len(xs) != 1 || xs[0].Active() || xs[0].RemovedVersion == nil || *xs[0].RemovedVersion != 2 {
			t.Errorf("RoleExclusions after removal = %+v, %v", xs, err)
		}
		// versions are unique per role
		return c.InsertRoleExclusion(&store.RoleExclusion{RoleID: a.role, IdentityID: a.alice, Reason: "x", Version: 1,
			ExcludedActor: "x", ExcludedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a duplicate exclusion version was accepted")
	}
}

func revRoleDump(t *testing.T, db *store.DB, tid tenancy.ID, a revRoleRows) string {
	t.Helper()
	out := roleDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		xs, err := c.AllRoleExclusions()
		if err != nil {
			return err
		}
		ir, err := c.ReviewItemRole(a.item)
		if err != nil {
			return err
		}
		ids, err := c.ReviewTemplateRoles(a.tmpl)
		if err != nil {
			return err
		}
		it, err := c.Item(a.item)
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{xs, ir, ids, it})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func reviewRolesCovered() map[string]bool {
	out := map[string]bool{}
	for k := range revRoleMutations {
		out[k] = true
	}
	for _, k := range []string{"AllRoleExclusions", "RoleExclusions", "ReviewItemRole", "CampaignItemRoles", "FlaggedRoleItems",
		"ReviewTemplateRoles"} {
		out[k] = true // TestIsolation_ReviewRoleReads
	}
	return out
}
