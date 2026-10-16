package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group rules (issue #56, GR-13): a tenant's rules and settings are its own.
// Another tenant's rule, group and platform user ids look nonexistent, and a
// rule that names another tenant's folder, group or user is refused by the
// guard triggers.

type ruleIDs struct {
	g1      store.GroupID
	folder  store.FolderID
	ident   int64
	user    uuid.UUID
	rule    string // a rule owned by g1
	folder1 string // a rule owned by the folder
}

func newRule(owner, ownerID, scope, by string) *store.GrpRule {
	return &store.GrpRule{OwnerType: owner, OwnerID: ownerID, Scope: scope, Name: "r", Trigger: "membership.direct.added",
		Conditions: "[]", Action: "veto", Params: `{"message":"no"}`, Enabled: true, CreatedBy: by, CreatedAt: storetest.Now,
		UpdatedBy: by, UpdatedAt: storetest.Now, ActiveSeq: 7}
}

func seedGroupRules(t *testing.T, f *storetest.Fixture) map[string]ruleIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]ruleIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := ruleIDs{g1: base[tn.Slug].g1, ident: base[tn.Slug].ident}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fo, err := c.GrpFolderByName("app")
			if err != nil {
				return err
			}
			ids.folder = fo.ID
			u := &store.PlatformUser{DisplayName: "U " + tn.Slug, CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			ids.user = u.ID
			r1 := newRule("group", string(ids.g1), "self", u.ID.String())
			if err := c.InsertGrpRule(r1); err != nil {
				return err
			}
			r2 := newRule("folder", string(ids.folder), "sub", u.ID.String())
			r2.Action = "no_self_add"
			r2.Params = "{}"
			if err := c.InsertGrpRule(r2); err != nil {
				return err
			}
			ids.rule, ids.folder1 = r1.ID, r2.ID
			return c.SetGrpRuleSettings(tn.Slug == f.A.Slug, storetest.Now, nil)
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupRuleTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupRules(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	ctx := context.Background()
	isNotFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpRule(a.rule)
		isNotFound("GrpRule(A's)", err)
		if own, err := c.GrpRule(b.rule); err != nil || own.OwnerID != string(b.g1) || own.Scope != "self" || !own.Enabled || own.ActiveSeq != 7 {
			t.Errorf("GrpRule(B's) = %+v, %v", own, err)
		}
		if rows, err := c.GrpRulesOf("group", string(a.g1)); err != nil || len(rows) != 0 {
			t.Errorf("GrpRulesOf(A's group) = %d rows, %v", len(rows), err)
		}
		if rows, err := c.GrpRulesOf("folder", string(b.folder)); err != nil || len(rows) != 1 || rows[0].ID != b.folder1 {
			t.Errorf("GrpRulesOf(B's folder) = %v, %v", rows, err)
		}
		// the enabled rules are B's two, never A's four
		if rows, err := c.GrpRulesEnabled("", ""); err != nil || len(rows) != 2 {
			t.Errorf("GrpRulesEnabled = %d rows, %v; want B's 2", len(rows), err)
		}
		if rows, err := c.GrpRulesEnabled("membership.direct.added", "no_self_add"); err != nil || len(rows) != 1 {
			t.Errorf("GrpRulesEnabled(trigger, action) = %d rows, %v; want 1", len(rows), err)
		}
		// an update and a delete of A's rule find nothing
		r := newRule("group", string(b.g1), "self", b.user.String())
		r.ID = a.rule
		isNotFound("UpdateGrpRule(A's)", c.UpdateGrpRule(r))
		isNotFound("DeleteGrpRule(A's)", c.DeleteGrpRule(a.rule))
		if n, err := c.DeleteGrpRulesOf("group", string(a.g1)); err != nil || n != 0 {
			t.Errorf("DeleteGrpRulesOf(A's group) = %d, %v", n, err)
		}
		if gs, err := c.GrpDirectIdentityGroups(store.MembersListID(c.Tenant()), a.ident, storetest.Now); err != nil || len(gs) != 0 {
			t.Errorf("GrpDirectIdentityGroups(A's identity) = %v, %v", gs, err)
		}
		s, err := c.GrpRuleSettings()
		if err != nil || s.EmailEnabled {
			t.Errorf("GrpRuleSettings = %+v, %v; want B's own (email off)", s, err)
		}
		return nil
	})
	// B's writes leave A's rules and settings alone
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SetGrpRuleSettings(true, storetest.Now, nil); err != nil {
			t.Error(err)
		}
		if n, err := c.DeleteGrpRulesOf("group", string(b.g1)); err != nil || n != 1 {
			t.Errorf("DeleteGrpRulesOf(B's group) = %d, %v", n, err)
		}
		r := newRule("folder", string(b.folder), "one", b.user.String())
		r.ID, r.Name, r.Enabled = b.folder1, "renamed", false
		return c.UpdateGrpRule(r)
	})
	err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if r, err := c.GrpRule(a.rule); err != nil || r.Name != "r" {
			t.Errorf("A's rule after B's writes = %+v, %v", r, err)
		}
		if r, err := c.GrpRule(a.folder1); err != nil || r.Name != "r" || r.Scope != "sub" || !r.Enabled {
			t.Errorf("A's folder rule after B's update = %+v, %v", r, err)
		}
		if s, err := c.GrpRuleSettings(); err != nil || !s.EmailEnabled {
			t.Errorf("A's settings after B's save = %+v, %v", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_GroupRuleCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupRules(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	row := func(mod func(r *store.GrpRule)) func(c *store.TenantTx) error {
		return func(c *store.TenantTx) error {
			r := newRule("group", string(b.g1), "self", b.user.String())
			mod(r)
			return c.InsertGrpRule(r)
		}
	}
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"owned by A's group": row(func(r *store.GrpRule) { r.OwnerID = string(a.g1) }),
		"owned by A's folder": row(func(r *store.GrpRule) {
			r.OwnerType, r.OwnerID, r.Scope = "folder", string(a.folder), "sub"
		}),
		"created by A's user": row(func(r *store.GrpRule) { r.CreatedBy = a.user.String() }),
		"saved by A's user":   row(func(r *store.GrpRule) { r.UpdatedBy = a.user.String() }),
		"stamped with A":      row(func(r *store.GrpRule) { r.TenantID = f.A.ID }),
		"updated to A's group": func(c *store.TenantTx) error {
			r := newRule("group", string(b.g1), "self", a.user.String())
			r.ID = b.rule
			return c.UpdateGrpRule(r)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	// a group rule has scope self and a folder rule one or sub; the table says so
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"a group rule with scope sub": row(func(r *store.GrpRule) { r.Scope = "sub" }),
		"a folder rule with scope self": row(func(r *store.GrpRule) {
			r.OwnerType, r.OwnerID = "folder", string(b.folder)
		}),
		"conditions that are not JSON": row(func(r *store.GrpRule) { r.Conditions = "{" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err == nil {
				t.Fatal("the table accepted the row")
			}
		})
	}
}

// groupRulesCovered lists the repository methods of GR-13 that
// TestIsolation_GroupRuleTables exercises.
func groupRulesCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"InsertGrpRule", "GrpRule", "UpdateGrpRule", "DeleteGrpRule", "DeleteGrpRulesOf", "GrpRulesOf",
		"GrpRulesEnabled", "GrpRuleSettings", "SetGrpRuleSettings", "GrpDirectIdentityGroups"} {
		m[name] = true
	}
	return m
}
