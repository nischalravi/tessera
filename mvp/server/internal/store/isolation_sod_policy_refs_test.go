package store_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// SoD policy ref isolation (issue #652, AC-6): a tenant sees only its own records, and a record naming another
// tenant's ruleset is refused.

func seedSodRef(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) string {
	t.Helper()
	id := "rs-ref-" + tag
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertSodRuleset(&store.SodRuleset{ID: id, Key: "k-" + tag, Name: "Ruleset " + tag, Enabled: true,
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.AddSodPolicyRef(&store.SodPolicyRef{RulesetID: id, RulesetVersion: 1, PolicyRef: `{"commit":"c-` + tag + `"}`,
			Actor: "x", AppliedAt: store.RT(storetest.Now)})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIsolation_SodPolicyRefs(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedSodRef(t, f.DB, f.A, "a"), seedSodRef(t, f.DB, f.B, "b")
	inB(t, f, func(c *store.TenantTx) error {
		rs, err := c.SodPolicyRefs()
		if err != nil || len(rs) != 1 || rs[0].RulesetID != b || rs[0].PolicyRef != `{"commit":"c-b"}` {
			t.Errorf("SodPolicyRefs = %+v, %v; want only B's", rs, err)
		}
		return nil
	})
	// a record naming A's ruleset, written as B, is refused
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.AddSodPolicyRef(&store.SodPolicyRef{RulesetID: a, RulesetVersion: 9, PolicyRef: "{}", Actor: "x",
			AppliedAt: store.RT(storetest.Now)})
	})
	if err == nil {
		t.Error("a policy ref naming another tenant's ruleset was accepted")
	}
	err = f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		rs, err := c.SodPolicyRefs()
		if err == nil && (len(rs) != 1 || rs[0].RulesetID != a) {
			t.Errorf("A's refs after B's refused write = %+v", rs)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sodPolicyRefsCovered() map[string]bool {
	return map[string]bool{"SodPolicyRefs": true, "AddSodPolicyRef": true} // TestIsolation_SodPolicyRefs
}
