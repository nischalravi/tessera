package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Conditional access isolation (issue #163): a tenant sees and changes only
// its own network ranges, policies and device signals; another tenant's ids
// look nonexistent, and a signal naming another tenant's user is refused.

type condAccessRows struct {
	user   *store.PlatformUser
	nr     *store.NetworkRange
	policy *store.AccessPolicy
}

func seedAccessRows(t *testing.T, db *store.DB, tid tenancy.ID, tag string) condAccessRows {
	t.Helper()
	now := storetest.Now
	var r condAccessRows
	err := db.InTenant(context.Background(), tid, func(c *store.TenantTx) error {
		email := tag + "-access@example.com"
		r.user = &store.PlatformUser{Email: &email, DisplayName: "user " + tag, CreatedAt: now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		r.nr = &store.NetworkRange{Name: "corp " + tag, CIDRs: []string{"10.0.0.0/8"}, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertNetworkRange(r.nr); err != nil {
			return err
		}
		acr := "urn:tessera:acr:phr"
		r.policy = &store.AccessPolicy{Name: "policy " + tag, Scope: store.AccessScopePrivileged, Mode: store.AccessModeEnforce,
			Outcome: store.AccessStepUp, StepUpACR: &acr, StepUpMaxAge: 300, NetworkOp: store.NetworkNotIn,
			NetworkRangeIDs: []uuid.UUID{r.nr.ID}, Device: store.DeviceAny, Priority: 10, CreatedAt: now, UpdatedAt: now}
		if err := c.InsertAccessPolicy(r.policy); err != nil {
			return err
		}
		return c.SetDeviceSignal(&store.DeviceSignal{UserID: r.user.ID, Status: store.DeviceNonCompliant,
			Source: store.DeviceSourceManual, Reason: tag, SetAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func condAccessFixture(t *testing.T) (*storetest.Fixture, condAccessRows, condAccessRows) {
	f := storetest.TwoTenants(t)
	return f, seedAccessRows(t, f.DB, f.A.ID, "a"), seedAccessRows(t, f.DB, f.B.ID, "b")
}

// condAccessMutations change one of A's rows; run in B they must fail ErrNotFound.
var condAccessMutations = map[string]func(c *store.TenantTx, a condAccessRows) error{
	"UpdateNetworkRange": func(c *store.TenantTx, a condAccessRows) error {
		n := *a.nr
		n.Name, n.UpdatedAt = "hijacked", storetest.Now
		return c.UpdateNetworkRange(&n)
	},
	"DeleteNetworkRange": func(c *store.TenantTx, a condAccessRows) error { return c.DeleteNetworkRange(a.nr.ID) },
	"UpdateAccessPolicy": func(c *store.TenantTx, a condAccessRows) error {
		p := *a.policy
		p.Mode, p.UpdatedAt = store.AccessModeDisabled, storetest.Now
		return c.UpdateAccessPolicy(&p)
	},
	"DeleteAccessPolicy": func(c *store.TenantTx, a condAccessRows) error { return c.DeleteAccessPolicy(a.policy.ID) },
	"ClearDeviceSignal":  func(c *store.TenantTx, a condAccessRows) error { return c.ClearDeviceSignal(a.user.ID) },
}

func TestIsolation_AccessRows(t *testing.T) {
	f, a, b := condAccessFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if rs, err := c.NetworkRanges(); err != nil || len(rs) != 1 || rs[0].ID != b.nr.ID {
			t.Errorf("NetworkRanges in B: %v %v", rs, err)
		}
		if ps, err := c.AccessPolicies(); err != nil || len(ps) != 1 || ps[0].ID != b.policy.ID {
			t.Errorf("AccessPolicies in B: %v %v", ps, err)
		}
		if n, err := c.CountAccessPolicies(); err != nil || n != 1 {
			t.Errorf("CountAccessPolicies in B = %d %v, want 1", n, err)
		}
		if ss, err := c.DeviceSignals(); err != nil || len(ss) != 1 || ss[0].UserID != b.user.ID {
			t.Errorf("DeviceSignals in B: %v %v", ss, err)
		}
		for name, get := range map[string]func() error{
			"NetworkRange": func() error { _, err := c.NetworkRange(a.nr.ID); return err },
			"AccessPolicy": func() error { _, err := c.AccessPolicy(a.policy.ID); return err },
			"DeviceSignal": func() error { _, err := c.DeviceSignal(a.user.ID); return err },
		} {
			if err := get(); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s of A's row in B = %v, want ErrNotFound", name, err)
			}
		}
		// own rows round-trip
		p, err := c.AccessPolicy(b.policy.ID)
		if err != nil || p.TenantID != f.B.ID || p.StepUpACR == nil || len(p.NetworkRangeIDs) != 1 || p.NetworkRangeIDs[0] != b.nr.ID {
			t.Errorf("own policy: %+v %v", p, err)
		}
		return nil
	})
	for name, fn := range condAccessMutations {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a) })
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s(A's row) in B = %v, want ErrNotFound", name, err)
			}
		})
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if n, err := c.NetworkRange(a.nr.ID); err != nil || n.Name != "corp a" {
			t.Errorf("A's range changed: %+v %v", n, err)
		}
		if p, err := c.AccessPolicy(a.policy.ID); err != nil || p.Mode != store.AccessModeEnforce {
			t.Errorf("A's policy changed: %+v %v", p, err)
		}
		if _, err := c.DeviceSignal(a.user.ID); err != nil {
			t.Errorf("A's signal removed: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_AccessInsertsRefused: a row stamped with another tenant, or a
// signal about another tenant's user, is refused; names are unique per
// tenant, not globally.
func TestIsolation_AccessInsertsRefused(t *testing.T) {
	f, a, b := condAccessFixture(t)
	now := storetest.Now
	in := func(fn func(c *store.TenantTx) error) error { return f.DB.InTenant(context.Background(), f.B.ID, fn) }
	if err := in(func(c *store.TenantTx) error {
		return c.InsertNetworkRange(&store.NetworkRange{TenantID: f.A.ID, Name: "x", CIDRs: []string{}, CreatedAt: now, UpdatedAt: now})
	}); !errors.Is(err, store.ErrNoTenant) && !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("range stamped A in B: %v", err)
	}
	if err := in(func(c *store.TenantTx) error {
		return c.InsertAccessPolicy(&store.AccessPolicy{TenantID: f.A.ID, Name: "x", Scope: store.AccessScopeSignin,
			Mode: store.AccessModeEnforce, Outcome: store.AccessDeny, NetworkOp: store.NetworkAny, Device: store.DeviceAny,
			CreatedAt: now, UpdatedAt: now})
	}); !errors.Is(err, store.ErrNoTenant) && !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("policy stamped A in B: %v", err)
	}
	if err := in(func(c *store.TenantTx) error {
		return c.SetDeviceSignal(&store.DeviceSignal{UserID: a.user.ID, Status: store.DeviceCompliant,
			Source: store.DeviceSourceManual, SetAt: now})
	}); !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("signal about A's user in B: %v, want ErrCrossTenant", err)
	}
	if err := in(func(c *store.TenantTx) error {
		return c.SetDeviceSignal(&store.DeviceSignal{UserID: b.user.ID, Status: store.DeviceCompliant,
			Source: store.DeviceSourceManual, SetBy: &a.user.ID, SetAt: now})
	}); !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("signal set by A's user in B: %v, want ErrCrossTenant", err)
	}
	// the same name in each tenant was accepted by the fixture; a repeat in B is a duplicate
	if err := in(func(c *store.TenantTx) error {
		return c.InsertNetworkRange(&store.NetworkRange{Name: b.nr.Name, CIDRs: []string{}, CreatedAt: now, UpdatedAt: now})
	}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate range name: %v", err)
	}
	if err := in(func(c *store.TenantTx) error {
		p := *b.policy
		p.ID = uuid.New()
		return c.InsertAccessPolicy(&p)
	}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate policy name: %v", err)
	}
	// the schema's own rules: a step-up policy names its ACR, a network condition its ranges
	for name, p := range map[string]*store.AccessPolicy{
		"step_up without acr": {Name: "r1", Scope: store.AccessScopeSignin, Mode: store.AccessModeEnforce,
			Outcome: store.AccessStepUp, NetworkOp: store.NetworkAny, Device: store.DeviceAny},
		"deny with acr": {Name: "r2", Scope: store.AccessScopeSignin, Mode: store.AccessModeEnforce,
			Outcome: store.AccessDeny, StepUpACR: sp("urn:tessera:acr:phr"), NetworkOp: store.NetworkAny, Device: store.DeviceAny},
		"network in without ranges": {Name: "r3", Scope: store.AccessScopeSignin, Mode: store.AccessModeEnforce,
			Outcome: store.AccessDeny, NetworkOp: store.NetworkIn, Device: store.DeviceAny},
		"unknown scope": {Name: "r4", Scope: "everything", Mode: store.AccessModeEnforce, Outcome: store.AccessDeny,
			NetworkOp: store.NetworkAny, Device: store.DeviceAny},
	} {
		p.CreatedAt, p.UpdatedAt = now, now
		if err := in(func(c *store.TenantTx) error { return c.InsertAccessPolicy(p) }); err == nil {
			t.Errorf("%s: the schema accepted it", name)
		}
	}
}

func TestAccessSignalReplacesAndExpires(t *testing.T) {
	f, _, b := condAccessFixture(t)
	exp := storetest.Now.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.SetDeviceSignal(&store.DeviceSignal{UserID: b.user.ID, Status: store.DeviceCompliant,
			Source: store.DeviceSourceCAEP, SetAt: storetest.Now, ExpiresAt: &exp}); err != nil {
			return err
		}
		s, err := c.DeviceSignal(b.user.ID)
		if err != nil || s.Status != store.DeviceCompliant || s.Source != store.DeviceSourceCAEP || s.ExpiresAt == nil || !s.ExpiresAt.Equal(exp) {
			t.Errorf("replaced signal: %+v %v", s, err)
		}
		if ss, _ := c.DeviceSignals(); len(ss) != 1 {
			t.Errorf("a signal per user: %d", len(ss))
		}
		if err := c.ClearDeviceSignal(b.user.ID); err != nil {
			return err
		}
		if err := c.ClearDeviceSignal(b.user.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second clear: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func accessCovered() map[string]bool {
	out := map[string]bool{}
	for k := range condAccessMutations {
		out[k] = true
	}
	for _, k := range []string{"NetworkRanges", "NetworkRange", "AccessPolicies", "AccessPolicy", "CountAccessPolicies",
		"DeviceSignals", "DeviceSignal", "InsertNetworkRange", "InsertAccessPolicy", "SetDeviceSignal"} {
		out[k] = true // TestIsolation_AccessRows, TestIsolation_AccessInsertsRefused
	}
	return out
}
