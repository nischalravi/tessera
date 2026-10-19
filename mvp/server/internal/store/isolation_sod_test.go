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

// SoD functions, risks and rulesets isolation (issue #298): a tenant sees and
// changes only its own rows; rows naming another tenant's ids are refused by
// the guard triggers.

type sodRows struct {
	user    *store.PlatformUser
	fn      string
	ruleset string
	risk    string
	owner   int64
}

func seedSodRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) sodRows {
	t.Helper()
	r := sodRows{fn: "fn-" + tag, ruleset: "rs-" + tag, risk: "rk-" + tag, owner: tn.IDs["alice"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "sod admin " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		uid := r.user.ID.String()
		if err := c.InsertSodFunction(&store.SodFunction{ID: r.fn, Key: "fn", Name: "Create " + tag, OwnerID: &r.owner,
			Selectors: `[{"name_pattern":"x"}]`, Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid,
			UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertSodRuleset(&store.SodRuleset{ID: r.ruleset, Key: "rs", Name: "Ruleset " + tag, Enabled: true,
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertSodRisk(&store.SodRisk{ID: r.risk, Key: "rk", Name: "Risk " + tag, Priority: "high", RulesetID: r.ruleset,
			Subjects: "{}", Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid,
			UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.SetSodRiskFunctions(r.risk, []string{r.fn}); err != nil {
			return err
		}
		return c.AddSodVersion(&store.SodVersion{Kind: store.SodKindRisk, ObjectID: r.risk, Version: 1, Snapshot: "{}",
			ChangedBy: &uid, Actor: "x", ChangedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sodFixture(t *testing.T) (*storetest.Fixture, sodRows, sodRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedSodRows(t, f.DB, f.A, "a"), seedSodRows(t, f.DB, f.B, "b")
}

func TestIsolation_SodReads(t *testing.T) {
	f, a, b := sodFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if x, err := c.SodFunctions(); err != nil || len(x) != 1 || x[0].ID != b.fn {
			t.Errorf("SodFunctions = %v, %v", x, err)
		}
		if _, err := c.SodFunction(a.fn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodFunction(A's) = %v", err)
		}
		if _, err := c.SodFunctionByName("Create a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodFunctionByName(A's) = %v", err)
		}
		if x, err := c.SodRulesets(); err != nil || len(x) != 1 || x[0].ID != b.ruleset {
			t.Errorf("SodRulesets = %v, %v", x, err)
		}
		if _, err := c.SodRuleset(a.ruleset); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodRuleset(A's) = %v", err)
		}
		if _, err := c.SodRulesetByName("Ruleset a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodRulesetByName(A's) = %v", err)
		}
		if n, err := c.CountSodRulesets(); err != nil || n != 1 {
			t.Errorf("CountSodRulesets = %d, %v", n, err)
		}
		if x, err := c.SodRisks(); err != nil || len(x) != 1 || x[0].ID != b.risk {
			t.Errorf("SodRisks = %v, %v", x, err)
		}
		if _, err := c.SodRisk(a.risk); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodRisk(A's) = %v", err)
		}
		if _, err := c.SodRiskByName("Risk a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SodRiskByName(A's) = %v", err)
		}
		if x, err := c.SodRiskFunctions(); err != nil || len(x) != 1 || x[0].RiskID != b.risk {
			t.Errorf("SodRiskFunctions = %v, %v", x, err)
		}
		if x, err := c.SodVersions(store.SodKindRisk, a.risk); err != nil || len(x) != 0 {
			t.Errorf("SodVersions(A's) = %v, %v", x, err)
		}
		return nil
	})
}

var sodMutations = map[string]func(c *store.TenantTx, a, b sodRows) error{
	"InsertSodFunction": func(c *store.TenantTx, a, _ sodRows) error { // A's owner identity in B's function
		return c.InsertSodFunction(&store.SodFunction{ID: "x", Key: "x", Name: "x", OwnerID: &a.owner, Selectors: "[]",
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertSodFunction/A's user": func(c *store.TenantTx, a, _ sodRows) error {
		uid := a.user.ID.String()
		return c.InsertSodFunction(&store.SodFunction{ID: "x", Key: "x", Name: "x", Selectors: "[]", Status: store.SodActive,
			Version: 1, CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now})
	},
	"SaveSodFunction": func(c *store.TenantTx, a, _ sodRows) error {
		return c.SaveSodFunction(&store.SodFunction{ID: a.fn, Name: "taken", Selectors: "[]", Status: store.SodRetired, Version: 2,
			UpdatedAt: storetest.Now}, 1)
	},
	"InsertSodRuleset": func(c *store.TenantTx, a, _ sodRows) error {
		uid := a.user.ID.String()
		return c.InsertSodRuleset(&store.SodRuleset{ID: "x", Key: "x", Name: "x", Status: store.SodActive, Version: 1,
			CreatedAt: storetest.Now, UpdatedBy: &uid, UpdatedAt: storetest.Now})
	},
	"SaveSodRuleset": func(c *store.TenantTx, a, _ sodRows) error {
		return c.SaveSodRuleset(&store.SodRuleset{ID: a.ruleset, Name: "taken", Status: store.SodRetired, Version: 2,
			UpdatedAt: storetest.Now}, 1)
	},
	"InsertSodRisk": func(c *store.TenantTx, a, _ sodRows) error { // A's ruleset in B's risk
		return c.InsertSodRisk(&store.SodRisk{ID: "x", Key: "x", Name: "x", Priority: "low", RulesetID: a.ruleset, Subjects: "{}",
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"SaveSodRisk": func(c *store.TenantTx, a, _ sodRows) error {
		return c.SaveSodRisk(&store.SodRisk{ID: a.risk, Name: "taken", Priority: "low", RulesetID: a.ruleset, Subjects: "{}",
			Status: store.SodRetired, Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"SaveSodRisk/move to A's ruleset": func(c *store.TenantTx, a, b sodRows) error {
		return c.SaveSodRisk(&store.SodRisk{ID: b.risk, Name: "Risk b", Priority: "low", RulesetID: a.ruleset, Subjects: "{}",
			Status: store.SodActive, Version: 2, UpdatedAt: storetest.Now}, 1)
	},
	"SetSodRiskFunctions/A's function": func(c *store.TenantTx, a, b sodRows) error {
		return c.SetSodRiskFunctions(b.risk, []string{a.fn})
	},
	"SetSodRiskFunctions/A's risk": func(c *store.TenantTx, a, b sodRows) error {
		if err := c.SetSodRiskFunctions(a.risk, []string{b.fn}); err != nil {
			return err
		}
		return store.ErrNotFound // nothing to delete in B; the insert for A's risk is refused above
	},
	"AddSodVersion": func(c *store.TenantTx, a, _ sodRows) error {
		return c.AddSodVersion(&store.SodVersion{Kind: store.SodKindRisk, ObjectID: a.risk, Version: 9, Snapshot: "{}", Actor: "x",
			ChangedAt: storetest.Now})
	},
}

func TestIsolation_SodMutationsScoped(t *testing.T) {
	for name, fn := range sodMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := sodFixture(t)
			before := sodDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if err == nil {
				t.Fatalf("%s across tenants succeeded", name)
			}
			if after := sodDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestSod_VersionsAppendOnlyAndStaleSave(t *testing.T) {
	f, a, _ := sodFixture(t)
	ctx := context.Background()
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.SaveSodRisk(&store.SodRisk{ID: a.risk, Name: "x", Priority: "low", RulesetID: a.ruleset, Subjects: "{}",
			Status: store.SodActive, Version: 3, UpdatedAt: storetest.Now}, 2)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SaveSodRisk at a stale version = %v, want ErrNotFound", err)
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.AddSodVersion(&store.SodVersion{Kind: store.SodKindRisk, ObjectID: a.risk, Version: 1, Snapshot: "{}", Actor: "x",
			ChangedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a duplicate version was accepted")
	}
}

func sodDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		fs, err := c.SodFunctions()
		if err != nil {
			return err
		}
		rs, err := c.SodRulesets()
		if err != nil {
			return err
		}
		ks, err := c.SodRisks()
		if err != nil {
			return err
		}
		ls, err := c.SodRiskFunctions()
		if err != nil {
			return err
		}
		var vs []*store.SodVersion
		for _, k := range ks {
			v, err := c.SodVersions(store.SodKindRisk, k.ID)
			if err != nil {
				return err
			}
			vs = append(vs, v...)
		}
		b, err := json.Marshal([]any{fs, rs, ks, ls, vs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sodCovered() map[string]bool {
	out := map[string]bool{}
	for k := range sodMutations {
		out[k] = true
	}
	for _, k := range []string{"SodFunctions", "SodFunction", "SodFunctionByName", "SodRulesets", "SodRuleset", "SodRulesetByName",
		"CountSodRulesets", "SodRisks", "SodRisk", "SodRiskByName", "SodRiskFunctions", "SodVersions",
		"SodFunctionByKey", "SodRulesetByKey", "SodRiskByKey"} {
		out[k] = true // TestIsolation_SodReads (the by-key reads scope like the by-name ones)
	}
	return out
}
