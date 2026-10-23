package idrules_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/idrules"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestCheck(t *testing.T) {
	ok := func(mod func(*idrules.Rules)) idrules.Rules {
		r := idrules.Defaults()
		mod(&r)
		return r
	}
	systems := []string{"okta", "workday"}
	cases := []struct {
		name string
		r    idrules.Rules
		code string // "" accepted
	}{
		{"defaults", idrules.Defaults(), ""},
		{"email only", ok(func(r *idrules.Rules) { r.CorrelationOrder = []string{"email"} }), ""},
		{"email first", ok(func(r *idrules.Rules) { r.CorrelationOrder = []string{"email", "external_id"} }), ""},
		{"no keys", ok(func(r *idrules.Rules) { r.CorrelationOrder = nil }), "invalid_correlation_order"},
		{"unknown key", ok(func(r *idrules.Rules) { r.CorrelationOrder = []string{"username"} }), "invalid_correlation_order"},
		{"repeated key", ok(func(r *idrules.Rules) { r.CorrelationOrder = []string{"email", "email"} }), "invalid_correlation_order"},
		{"source of a connection", ok(func(r *idrules.Rules) { r.Authoritative = map[string]string{"department": "workday"} }), ""},
		{"unknown attribute", ok(func(r *idrules.Rules) { r.Authoritative = map[string]string{"salary": "workday"} }), "invalid_attribute"},
		{"unknown system", ok(func(r *idrules.Rules) { r.Authoritative = map[string]string{"title": "sap"} }), "unknown_source"},
		{"malformed system", ok(func(r *idrules.Rules) { r.Authoritative = map[string]string{"title": "x; DROP"} }), "invalid_source"},
		{"service days 0", ok(func(r *idrules.Rules) { r.DormantServiceDays = 0 }), "invalid_dormancy"},
		{"agent days too long", ok(func(r *idrules.Rules) { r.DormantAIAgentDays = 3651 }), "invalid_dormancy"},
		{"bounds", ok(func(r *idrules.Rules) { r.DormantServiceDays, r.DormantAIAgentDays = 1, 3650 }), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Check(systems)
			var ce *cfgerr.Error
			switch {
			case tc.code == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.code != "" && (!errors.As(err, &ce) || ce.Code != tc.code):
				t.Errorf("err = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestSaveVersionsAndAudits(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		r, v, err := idrules.Load(c)
		if err != nil || v != 0 || r.DormantServiceDays != 30 || len(r.CorrelationOrder) != 2 {
			t.Fatalf("defaults = %+v v%d %v", r, v, err)
		}
		r.DormantServiceDays = 90
		r.CorrelationOrder = []string{"email", "external_id"}
		if _, v, err = idrules.Save(c, r, 0, "admin", now); err != nil || v != 1 {
			t.Fatalf("save = v%d %v", v, err)
		}
		// a stale version is a conflict, and changes nothing
		r.DormantServiceDays = 7
		var ce *cfgerr.Error
		if _, _, err = idrules.Save(c, r, 0, "admin", now); !errors.As(err, &ce) || ce.Code != "version_conflict" {
			t.Fatalf("stale save = %v", err)
		}
		got, v, err := idrules.Load(c)
		if err != nil || v != 1 || got.DormantServiceDays != 90 || got.CorrelationOrder[0] != "email" {
			t.Fatalf("after = %+v v%d %v", got, v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// the other tenant still has the defaults
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if r, v, err := idrules.Load(c); err != nil || v != 0 || r.DormantServiceDays != 30 {
			t.Errorf("B = %+v v%d %v", r, v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
