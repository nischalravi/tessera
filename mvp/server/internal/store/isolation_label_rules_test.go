package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Label settings and identity rules (schema/0765_tenant_label_settings.sql, 0766_identity_rules.sql): one row per
// tenant, read and written only through the tenant's own handle.

func TestIsolation_LabelSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	put := func(tn storetest.Tenant, lang, labels, by string) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutLabelSettings(&store.LabelSettingsRow{DefaultLanguage: lang, EmailLogo: true, Labels: labels, UpdatedBy: by}, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(f.A, "de-DE", `{"group":"team"}`, "admin a")
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.LabelSettings(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's label settings: %v", err)
		}
		return nil
	})
	put(f.B, "fr-FR", `{}`, "admin b")
	put(f.B, "ja-JP", `{"guest":"visitor"}`, "admin b")
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.LabelSettings()
		if err != nil || r.DefaultLanguage != "de-DE" || r.Version != 1 || r.UpdatedBy != "admin a" || r.Labels != `{"group":"team"}` || !r.EmailLogo {
			t.Errorf("A's settings changed by B's saves: %+v %v", r, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		r, err := c.LabelSettings()
		if err != nil || r.DefaultLanguage != "ja-JP" || r.Version != 2 || r.Labels != `{"guest":"visitor"}` {
			t.Errorf("B's settings: %+v %v", r, err)
		}
		return nil
	})
	// the table's own checks refuse values the API would never send
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.PutLabelSettings(&store.LabelSettingsRow{Labels: `not json`, UpdatedBy: "x"}, storetest.Now)
	})
	if err == nil {
		t.Error("labels that are not JSON were accepted")
	}
}

func TestIsolation_IdentityRules(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	put := func(tn storetest.Tenant, svc int, auth, by string) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutIdentityRules(&store.IdentityRulesRow{CorrelationOrder: `["email"]`, Authoritative: auth, DormantServiceDays: svc,
				DormantAIAgentDays: 45, UpdatedBy: by}, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(f.A, 10, `{"title":"workday"}`, "admin a")
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.IdentityRules(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's identity rules: %v", err)
		}
		return nil
	})
	put(f.B, 20, `{}`, "admin b")
	put(f.B, 21, `{}`, "admin b")
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.IdentityRules()
		if err != nil || r.DormantServiceDays != 10 || r.Version != 1 || r.UpdatedBy != "admin a" || r.Authoritative != `{"title":"workday"}` {
			t.Errorf("A's rules changed by B's saves: %+v %v", r, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		r, err := c.IdentityRules()
		if err != nil || r.DormantServiceDays != 21 || r.DormantAIAgentDays != 45 || r.Version != 2 {
			t.Errorf("B's rules: %+v %v", r, err)
		}
		return nil
	})
	for name, row := range map[string]store.IdentityRulesRow{
		"zero days":    {CorrelationOrder: `[]`, Authoritative: `{}`, DormantServiceDays: 0, DormantAIAgentDays: 30},
		"huge days":    {CorrelationOrder: `[]`, Authoritative: `{}`, DormantServiceDays: 30, DormantAIAgentDays: 4000},
		"not json":     {CorrelationOrder: `x`, Authoritative: `{}`, DormantServiceDays: 30, DormantAIAgentDays: 30},
		"not json too": {CorrelationOrder: `[]`, Authoritative: `x`, DormantServiceDays: 30, DormantAIAgentDays: 30},
	} {
		row.UpdatedBy = "x"
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.PutIdentityRules(&row, storetest.Now) }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func labelRulesCovered() map[string]bool {
	return map[string]bool{"LabelSettings": true, "PutLabelSettings": true, "IdentityRules": true, "PutIdentityRules": true}
}
