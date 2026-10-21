package store_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Ruleset remediation defaults (schema/0381_sod_remediation.sql, issue #298): a
// tenant sees and changes only its own rows, and a row naming another tenant's
// ruleset or approver is refused.

func seedRemediation(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, tag string, r sodCtlRows) {
	t.Helper()
	err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		return c.PutSodRulesetRemediation(&store.SodRulesetRemediation{RulesetID: r.ruleset, Options: `["revoke"]`, EscalateTo: &r.owner,
			UpdatedBy: "admin " + tag, UpdatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_SodRulesetRemediation(t *testing.T) {
	f, a, b := sodCtlFixture(t)
	seedRemediation(t, f, f.A, "a", a)
	seedRemediation(t, f, f.B, "b", b)
	inB(t, f, func(c *store.TenantTx) error {
		rows, err := c.SodRulesetRemediations()
		if err != nil || len(rows) != 1 || rows[0].RulesetID != b.ruleset || rows[0].UpdatedBy != "admin b" ||
			rows[0].EscalateTo == nil || *rows[0].EscalateTo != b.owner || rows[0].Options != `["revoke"]` {
			t.Errorf("B sees %+v, %v", rows, err)
		}
		return nil
	})
	// replacing B's row leaves A's alone
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutSodRulesetRemediation(&store.SodRulesetRemediation{RulesetID: b.ruleset, Options: `[]`, UpdatedBy: "again", UpdatedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		rows, err := c.SodRulesetRemediations()
		if err != nil || len(rows) != 1 || rows[0].Options != `["revoke"]` || rows[0].UpdatedBy != "admin a" {
			t.Errorf("A's row after B's save: %+v, %v", rows, err)
		}
		return nil
	})
}

func TestIsolation_SodRulesetRemediationRefusesOtherTenantsRefs(t *testing.T) {
	for name, fn := range map[string]func(a, b sodCtlRows) *store.SodRulesetRemediation{
		"A's ruleset": func(a, b sodCtlRows) *store.SodRulesetRemediation {
			return &store.SodRulesetRemediation{RulesetID: a.ruleset, Options: `[]`, UpdatedBy: "x", UpdatedAt: storetest.Now}
		},
		"A's approver": func(a, b sodCtlRows) *store.SodRulesetRemediation {
			return &store.SodRulesetRemediation{RulesetID: b.ruleset, Options: `[]`, EscalateTo: &a.owner, UpdatedBy: "x", UpdatedAt: storetest.Now}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, a, b := sodCtlFixture(t)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.PutSodRulesetRemediation(fn(a, b)) })
			if err == nil {
				t.Fatalf("a row naming %s was accepted", name)
			}
			inA(t, f, func(c *store.TenantTx) error {
				if rows, err := c.SodRulesetRemediations(); err != nil || len(rows) != 0 {
					t.Errorf("A has %+v, %v", rows, err)
				}
				return nil
			})
		})
	}
}

func TestSodRulesetRemediation_OptionsMustBeJSON(t *testing.T) {
	f, a, _ := sodCtlFixture(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutSodRulesetRemediation(&store.SodRulesetRemediation{RulesetID: a.ruleset, Options: `revoke,mitigate`, UpdatedBy: "x", UpdatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("options that are not JSON were accepted")
	}
}

// sodRemediationCovered lists the methods the ruleset remediation isolation tests exercise.
func sodRemediationCovered() map[string]bool {
	return map[string]bool{"SodRulesetRemediations": true, "PutSodRulesetRemediation": true}
}
