package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Signing-key isolation (design §14.4, threat E6): a tenant sees, and can
// change, only its own keys; another tenant's kid looks nonexistent.

func keyFor(tid tenancy.ID, kid, status string) *store.TenantSigningKey {
	return &store.TenantSigningKey{KID: kid, TenantID: tid, Purpose: store.KeyPurposeAccessToken, Alg: "ES256",
		PublicJWK: []byte(`{"kty":"EC"}`), PrivateKeyEnc: []byte{1, 2, 3}, Status: status, CreatedAt: storetest.Now}
}

func seedKeys(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		prefix := "b"
		if tn.ID == f.A.ID {
			prefix = "a"
		}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			for _, k := range []*store.TenantSigningKey{keyFor(tn.ID, prefix+"-active", store.KeyActive),
				keyFor(tn.ID, prefix+"-next", store.KeyNext)} {
				if err := c.InsertSigningKey(k); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// keyMutations change one key by kid; called in B with A's kid they must
// return ErrNotFound and leave A's key alone.
var keyMutations = map[string]func(c *store.TenantTx, kid string) error{
	"ActivateSigningKey": func(c *store.TenantTx, kid string) error { return c.ActivateSigningKey(kid, storetest.Now) },
	"RetireSigningKey":   func(c *store.TenantTx, kid string) error { return c.RetireSigningKey(kid, storetest.Now) },
	"RevokeSigningKey":   func(c *store.TenantTx, kid string) error { return c.RevokeSigningKey(kid, storetest.Now) },
}

func TestIsolation_SigningKeys(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedKeys(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		ks, err := c.SigningKeys(store.KeyPurposeAccessToken)
		if err != nil {
			return err
		}
		if len(ks) != 2 {
			t.Fatalf("B sees %d keys, want its own 2", len(ks))
		}
		for _, k := range ks {
			if k.TenantID != f.B.ID || k.KID[0] != 'b' {
				t.Errorf("B sees key %s of tenant %s", k.KID, k.TenantID)
			}
		}
		for _, kid := range []string{"a-active", "a-next"} {
			if _, err := c.SigningKey(kid); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("SigningKey(%s) in B = %v, want ErrNotFound", kid, err)
			}
		}
		if k, err := c.SigningKey("b-active"); err != nil || k.Status != store.KeyActive {
			t.Errorf("own key: %v", err)
		}
		return nil
	})
	for name, fn := range keyMutations {
		t.Run(name, func(t *testing.T) {
			for _, kid := range []string{"a-active", "a-next"} {
				err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, kid) })
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("%s(%s) in B = %v, want ErrNotFound", name, kid, err)
				}
			}
		})
	}
	err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		for kid, want := range map[string]string{"a-active": store.KeyActive, "a-next": store.KeyNext} {
			k, err := c.SigningKey(kid)
			if err != nil {
				return err
			}
			if k.Status != want || k.RetiredAt != nil || k.ActivatedAt != nil {
				t.Errorf("A's key %s changed by B: %+v", kid, k)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// InsertSigningKey stamped with tenant A inside B is refused.
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertSigningKey(keyFor(f.A.ID, "x", store.KeyRetired))
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("InsertSigningKey for A in B = %v, want ErrCrossTenant", err)
	}
}

// TestSigningKeyInvariants: one active and one next key per tenant and
// purpose (unique indexes), and transitions are compare-and-set.
func TestSigningKeyInvariants(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedKeys(t, f)
	ctx := context.Background()
	in := func(fn func(c *store.TenantTx) error) error { return f.DB.InTenant(ctx, f.B.ID, fn) }
	for _, st := range []string{store.KeyActive, store.KeyNext} {
		if err := in(func(c *store.TenantTx) error { return c.InsertSigningKey(keyFor(f.B.ID, "b-2-"+st, st)) }); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second %s key: %v, want ErrDuplicate", st, err)
		}
	}
	if err := in(func(c *store.TenantTx) error { return c.InsertSigningKey(keyFor(f.B.ID, "b-active", store.KeyNext)) }); err == nil {
		t.Error("duplicate kid accepted")
	}
	if err := in(func(c *store.TenantTx) error { return c.InsertSigningKey(keyFor(f.B.ID, "b-r", store.KeyRetired)) }); err == nil {
		t.Error("a new key inserted as retired")
	}
	// next cannot activate while another key is active
	if err := in(func(c *store.TenantTx) error { return c.ActivateSigningKey("b-next", storetest.Now) }); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("activate with an active key present: %v", err)
	}
	later := storetest.Now.Add(time.Hour)
	if err := in(func(c *store.TenantTx) error {
		if err := c.RetireSigningKey("b-active", later); err != nil {
			return err
		}
		if err := c.ActivateSigningKey("b-next", later); err != nil {
			return err
		}
		if err := c.RetireSigningKey("b-active", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("retiring a retired key: %v", err)
		}
		if err := c.RevokeSigningKey("b-active", later.Add(time.Hour)); err != nil {
			return err
		}
		if err := c.RevokeSigningKey("b-active", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoking a revoked key: %v", err)
		}
		k, err := c.SigningKey("b-active")
		if err != nil {
			return err
		}
		if k.Status != store.KeyRevoked || k.RetiredAt == nil || !k.RetiredAt.Equal(later) {
			t.Errorf("revoked key: %+v", k)
		}
		k, err = c.SigningKey("b-next")
		if err != nil {
			return err
		}
		if k.Status != store.KeyActive || k.ActivatedAt == nil || !k.ActivatedAt.Equal(later) {
			t.Errorf("activated key: %+v", k)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformKeys(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	k := store.PlatformKey{KID: "platform-1", Purpose: store.KeyPurposeAuditCheckpoint, Alg: "EdDSA",
		PublicJWK: []byte(`{"kty":"OKP"}`), PrivateKeyEnc: []byte{9}, CreatedAt: storetest.Now}
	err := f.DB.InSystem(ctx, "test", func(s *store.SystemTx) error {
		if err := s.InsertPlatformKey(k); err != nil {
			return err
		}
		k2 := k
		k2.KID = "platform-2"
		if err := s.InsertPlatformKey(k2); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second active platform key: %v", err)
		}
		if err := s.RetirePlatformKey("platform-1"); err != nil {
			return err
		}
		if err := s.RetirePlatformKey("platform-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("retire twice: %v", err)
		}
		if err := s.InsertPlatformKey(k2); err != nil {
			return err
		}
		ks, err := s.PlatformKeys(store.KeyPurposeAuditCheckpoint)
		if err != nil {
			return err
		}
		if len(ks) != 2 || ks[0].Status != store.KeyRetired || ks[1].Status != store.KeyActive ||
			string(ks[0].PrivateKeyEnc) != "\x09" {
			t.Errorf("platform keys: %+v", ks)
		}
		// revoke: a retired or active key once; never again, never unknown
		for _, kid := range []string{"platform-1", "platform-2"} {
			if err := s.RevokePlatformKey(kid); err != nil {
				return err
			}
			if err := s.RevokePlatformKey(kid); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("revoke %s twice: %v", kid, err)
			}
			if err := s.RetirePlatformKey(kid); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("retire revoked %s: %v", kid, err)
			}
		}
		if err := s.RevokePlatformKey("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("revoke unknown: %v", err)
		}
		if ks, err = s.PlatformKeys(store.KeyPurposeAuditCheckpoint); err != nil {
			return err
		}
		if len(ks) != 2 || ks[0].Status != store.KeyRevoked || ks[1].Status != store.KeyRevoked {
			t.Errorf("after revoke: %+v", ks)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReservedSlugs (L8): "platform" and "platform-*" cannot be tenant slugs
// (their key ids would look like platform key ids); similar names can.
func TestReservedSlugs(t *testing.T) {
	for s, want := range map[string]bool{"platform": false, "platform-eu": false, "_platform": false, "PLATFORM": false,
		"platforms": true, "my-platform": true, "larkspur": true, "platformx": true} {
		if got := store.ValidSlug(s); got != want {
			t.Errorf("ValidSlug(%q) = %t, want %t", s, got, want)
		}
	}
	f := storetest.TwoTenants(t)
	for _, s := range []string{"platform", "platform-eu"} {
		err := f.DB.InSystem(context.Background(), "test", func(sys *store.SystemTx) error {
			_, err := sys.CreateTenant(store.Tenant{Slug: s, Name: "x"})
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "invalid tenant slug") {
			t.Errorf("CreateTenant(%q) = %v, want refused", s, err)
		}
	}
}

func keysCovered() map[string]bool {
	out := keys(keyMutations)
	// Covered by TestIsolation_SigningKeys.
	out["SigningKeys"], out["SigningKey"], out["InsertSigningKey"] = true, true, true
	return out
}
