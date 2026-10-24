package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Per-client rate limit overrides (issue #587): a tenant sets, reads and clears
// only its own clients' limits, and cannot name another tenant's client.

func TestIsolation_APIClientLimits(t *testing.T) {
	f, a, b := oauthFixture(t)
	inA(t, f, func(c *store.TenantTx) error {
		return c.SetAPIClientLimit(a.machine.ClientID, 7, 70, storetest.Now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.APIClientLimit(a.machine.ClientID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("A's limit read in B = %v, want ErrNotFound", err)
		}
		if _, err := c.APIClientLimit(b.machine.ClientID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's own limit before it is set = %v, want ErrNotFound", err)
		}
		// clearing A's client from B touches nothing of A's
		return c.ClearAPIClientLimit(a.machine.ClientID)
	})
	inA(t, f, func(c *store.TenantTx) error {
		l, err := c.APIClientLimit(a.machine.ClientID)
		if err != nil || l.Burst != 7 || l.PerMinute != 70 || !l.UpdatedAt.Equal(storetest.Now) {
			t.Errorf("A's limit after B's clear = %+v, %v", l, err)
		}
		return nil
	})
}

func TestIsolation_APIClientLimitsCrossTenantReference(t *testing.T) {
	f, a, _ := oauthFixture(t)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.SetAPIClientLimit(a.machine.ClientID, 1, 1, storetest.Now)
	})
	if err == nil {
		t.Fatal("B set a limit for A's client")
	}
}

func TestAPIClientLimits_UpsertAndClear(t *testing.T) {
	f, a, _ := oauthFixture(t)
	later := storetest.Now.Add(time.Hour)
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.SetAPIClientLimit(a.machine.ClientID, 5, 50, storetest.Now); err != nil {
			return err
		}
		return c.SetAPIClientLimit(a.machine.ClientID, 9, 90, later)
	})
	inA(t, f, func(c *store.TenantTx) error {
		l, err := c.APIClientLimit(a.machine.ClientID)
		if err != nil || l.Burst != 9 || l.PerMinute != 90 || !l.UpdatedAt.Equal(later) {
			t.Errorf("limit = %+v, %v", l, err)
		}
		return c.ClearAPIClientLimit(a.machine.ClientID)
	})
	inA(t, f, func(c *store.TenantTx) error {
		if _, err := c.APIClientLimit(a.machine.ClientID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("after clear: %v", err)
		}
		return nil
	})
	// the schema bounds the values
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.SetAPIClientLimit(a.machine.ClientID, 0, 10, storetest.Now)
	})
	if err == nil {
		t.Error("burst 0 accepted")
	}
}

func apiClientLimitsCovered() map[string]bool {
	return map[string]bool{"APIClientLimit": true, "SetAPIClientLimit": true, "ClearAPIClientLimit": true} // the tests above
}
