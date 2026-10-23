package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Recently added authentication methods and the help-desk reset (issue #477):
// settings, IdP risk signals and an identity's methods are per tenant; a risk
// signal naming another tenant's identity is refused.

func seedHelpdeskRisk(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for i, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.PutHelpdeskSettings(&store.HelpdeskSettings{RecentMethodDays: 10 + i, RecentMethodAction: store.HelpdeskRecentBlock},
				"admin-"+tn.Slug, storetest.Now); err != nil {
				return err
			}
			if err := c.InsertHelpdeskIdPRisk(&store.HelpdeskIdPRisk{IdentityID: tn.IDs["alice"], Kind: "auth_method_added",
				Source: "entra", Detail: "risk of " + tn.Slug, OccurredAt: storetest.Now}, storetest.Now); err != nil {
				return err
			}
			enrolled := storetest.Now.Add(-time.Hour)
			return c.ReplaceAuthMethods("okta", []store.AuthMethod{{AccountID: tn.IDs["acct:okta:alice"], ExternalID: "m1", Strength: "otp",
				Kind: "totp", Label: "phone of " + tn.Slug, EnrolledAt: &enrolled, ObservedAt: storetest.Now}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_HelpdeskRiskReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedHelpdeskRisk(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		s, err := c.HelpdeskSettings()
		if err != nil || s.RecentMethodDays != 11 || s.UpdatedBy != "admin-"+f.B.Slug {
			t.Errorf("HelpdeskSettings = %+v, %v", s, err)
		}
		if rs, err := c.HelpdeskIdPRisks(f.A.IDs["alice"]); err != nil || len(rs) != 0 {
			t.Errorf("HelpdeskIdPRisks(A's alice) = %v, %v", rs, err)
		}
		if rs, err := c.HelpdeskIdPRisks(f.B.IDs["alice"]); err != nil || len(rs) != 1 || rs[0].Detail != "risk of "+f.B.Slug {
			t.Errorf("HelpdeskIdPRisks(B's alice) = %v, %v", rs, err)
		}
		if ms, err := c.AuthMethodsOfIdentity(f.A.IDs["alice"]); err != nil || len(ms) != 0 {
			t.Errorf("AuthMethodsOfIdentity(A's alice) = %v, %v", ms, err)
		}
		if ms, err := c.AuthMethodsOfIdentity(f.B.IDs["alice"]); err != nil || len(ms) != 1 || ms[0].Label != "phone of "+f.B.Slug {
			t.Errorf("AuthMethodsOfIdentity(B's alice) = %v, %v", ms, err)
		}
		return nil
	})
}

// A tenant that never saved settings has the defaults, and saving is an upsert
// that touches only its own row.
func TestHelpdeskSettingsDefaultsAndUpsert(t *testing.T) {
	f := storetest.TwoTenants(t)
	inA(t, f, func(c *store.TenantTx) error {
		s, err := c.HelpdeskSettings()
		if err != nil || s.RecentMethodDays != 7 || s.RecentMethodAction != store.HelpdeskRecentRequireApproval || s.UpdatedAt != nil {
			t.Errorf("defaults = %+v, %v", s, err)
		}
		for _, d := range []int{3, 30} {
			if err := c.PutHelpdeskSettings(&store.HelpdeskSettings{RecentMethodDays: d, RecentMethodAction: store.HelpdeskRecentOff}, "x", storetest.Now); err != nil {
				t.Fatal(err)
			}
		}
		if s, err = c.HelpdeskSettings(); err != nil || s.RecentMethodDays != 30 || s.RecentMethodAction != store.HelpdeskRecentOff {
			t.Errorf("after upsert = %+v, %v", s, err)
		}
		// the table refuses an out-of-range window and an unknown action
		if err := c.PutHelpdeskSettings(&store.HelpdeskSettings{RecentMethodDays: 0, RecentMethodAction: store.HelpdeskRecentOff}, "x", storetest.Now); err == nil {
			t.Error("a window of 0 days was accepted")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.HelpdeskSettings(); err != nil || s.UpdatedAt != nil {
			t.Errorf("B's settings = %+v, %v (A's save leaked)", s, err)
		}
		return nil
	})
}

func TestIsolation_HelpdeskRiskCrossTenantReference(t *testing.T) {
	f := storetest.TwoTenants(t)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertHelpdeskIdPRisk(&store.HelpdeskIdPRisk{IdentityID: f.A.IDs["alice"], Kind: "auth_method_added", OccurredAt: storetest.Now}, storetest.Now)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Fatalf("err = %v, want ErrCrossTenant", err)
	}
}

func helpdeskRiskCovered() map[string]bool {
	return map[string]bool{"HelpdeskSettings": true, "PutHelpdeskSettings": true, "InsertHelpdeskIdPRisk": true,
		"HelpdeskIdPRisks": true, "AuthMethodsOfIdentity": true} // the tests above
}
