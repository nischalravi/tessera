package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// MFA posture (issue #109): methods, source status, app sign-in signals and
// daily snapshots are visible and replaceable only inside their own tenant,
// and a row cannot point at another tenant's account.

func mfaCovered() map[string]bool {
	return map[string]bool{"AuthMethods": true, "AuthMethodSources": true, "AccountAuthSignalRows": true, "MFASnapshots": true, // TestIsolation_MFAReads
		"ReplaceAuthMethods": true, "PutAuthMethodSource": true, "PutAccountAuthSignals": true, "PutMFASnapshot": true} // TestIsolation_MFAWritesScoped
}

func seedMFA(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			acct := tn.IDs["acct:okta:alice"]
			if err := c.ReplaceAuthMethods("okta", []store.AuthMethod{{AccountID: acct, ExternalID: "m1", Strength: "phishing_resistant",
				Kind: "passkey", Label: "key-" + tn.Slug, EnrolledAt: &storetest.Now, ObservedAt: storetest.Now}}); err != nil {
				return err
			}
			if err := c.PutAuthMethodSource(store.AuthMethodSource{System: "okta", Status: "ok", Detail: "d-" + tn.Slug,
				UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.PutAccountAuthSignals(store.AccountAuthSignals{AccountID: acct, HasLocalPassword: bp(true),
				ObservedAt: storetest.Now}); err != nil {
				return err
			}
			n := 3
			if tn.ID == f.B.ID {
				n = 7
			}
			return c.PutMFASnapshot(store.MFASnapshot{Date: "2026-10-08", Dimension: "all", GroupKey: "all", Total: n, PasskeyEnrolled: n})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_MFAReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedMFA(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		ms, err := c.AuthMethods()
		if err != nil || len(ms) != 1 || ms[0].Label != "key-"+f.B.Slug || ms[0].AccountID != f.B.IDs["acct:okta:alice"] {
			t.Errorf("AuthMethods = %+v, %v", ms, err)
		}
		src, err := c.AuthMethodSources()
		if err != nil || len(src) != 1 || src[0].Detail != "d-"+f.B.Slug {
			t.Errorf("AuthMethodSources = %+v, %v", src, err)
		}
		sig, err := c.AccountAuthSignalRows()
		if err != nil || len(sig) != 1 || sig[0].AccountID != f.B.IDs["acct:okta:alice"] || sig[0].HasLocalPassword == nil ||
			!*sig[0].HasLocalPassword || sig[0].MFAEnabled != nil || sig[0].SSOEnforced != nil {
			t.Errorf("AccountAuthSignalRows = %+v, %v (unknown flags must stay NULL)", sig, err)
		}
		snaps, err := c.MFASnapshots("2000-01-01")
		if err != nil || len(snaps) != 1 || snaps[0].Total != 7 {
			t.Errorf("MFASnapshots = %+v, %v", snaps, err)
		}
		if later, err := c.MFASnapshots("2026-10-09"); err != nil || len(later) != 0 {
			t.Errorf("MFASnapshots(since later) = %+v, %v", later, err)
		}
		return nil
	})
}

func TestIsolation_MFAWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedMFA(t, f)
	// B replaces its okta methods with none, and overwrites its source, signal and snapshot: A's stay.
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.ReplaceAuthMethods("okta", nil); err != nil {
			return err
		}
		if err := c.PutAuthMethodSource(store.AuthMethodSource{System: "okta", Status: "unavailable", Detail: "b2", UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.PutAccountAuthSignals(store.AccountAuthSignals{AccountID: f.B.IDs["acct:okta:alice"], ObservedAt: storetest.Now}); err != nil {
			return err
		}
		return c.PutMFASnapshot(store.MFASnapshot{Date: "2026-10-08", Dimension: "all", GroupKey: "all", Total: 99})
	})
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		ms, _ := c.AuthMethods()
		src, _ := c.AuthMethodSources()
		sig, _ := c.AccountAuthSignalRows()
		snaps, _ := c.MFASnapshots("2000-01-01")
		if len(ms) != 1 || ms[0].Label != "key-"+f.A.Slug || len(src) != 1 || src[0].Status != "ok" ||
			len(sig) != 1 || sig[0].HasLocalPassword == nil || len(snaps) != 1 || snaps[0].Total != 3 {
			t.Errorf("A's MFA rows changed by B: %+v %+v %+v %+v", ms, src, sig, snaps)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if ms, _ := c.AuthMethods(); len(ms) != 0 {
			t.Errorf("B's methods after replace = %+v", ms)
		}
		return nil
	})
}

// A method or signal in B that names A's account is refused by the guard triggers.
func TestIsolation_MFACrossTenantAccountRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := f.A.IDs["acct:okta:alice"]
	for name, fn := range map[string]func(*store.TenantTx) error{
		"ReplaceAuthMethods": func(c *store.TenantTx) error {
			return c.ReplaceAuthMethods("okta", []store.AuthMethod{{AccountID: a, ExternalID: "x", Strength: "otp", Kind: "totp",
				ObservedAt: storetest.Now}})
		},
		"PutAccountAuthSignals": func(c *store.TenantTx) error {
			return c.PutAccountAuthSignals(store.AccountAuthSignals{AccountID: a, ObservedAt: storetest.Now})
		},
	} {
		err := f.DB.InTenant(context.Background(), f.B.ID, fn)
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s: err = %v, want ErrCrossTenant", name, err)
		}
	}
}
