package store_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Config transport isolation (issue #170): signing keys, trusted signers and
// import records are per tenant.

func TestIsolation_ConfigTransport(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	pub := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertConfigSigningKey(&store.ConfigSigningKey{KID: "cfg-a", PublicKey: pub(1), PrivateSealed: []byte("x"), CreatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertTrustedSigner(&store.TrustedSigner{KID: "dev-a", PublicKey: pub(2), Label: "dev", AddedAt: now}); err != nil {
			return err
		}
		return c.InsertConfigImport(&store.ConfigImport{ID: "imp-a", BundleHash: "h", SignerKID: "dev-a", Source: "dev", ExportedAt: now,
			Summary: "{}", AppliedAt: now})
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ActiveConfigSigningKey(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ActiveConfigSigningKey = %v", err)
		}
		if ss, err := c.TrustedSigners(); err != nil || len(ss) != 0 {
			t.Errorf("TrustedSigners = %v, %v", ss, err)
		}
		if _, err := c.TrustedSigner("dev-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TrustedSigner(A's) = %v", err)
		}
		if err := c.DeleteTrustedSigner("dev-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteTrustedSigner(A's) = %v", err)
		}
		if is, err := c.ConfigImports(); err != nil || len(is) != 0 {
			t.Errorf("ConfigImports = %v, %v", is, err)
		}
		// B may trust the same kid independently
		return c.InsertTrustedSigner(&store.TrustedSigner{KID: "dev-a", PublicKey: pub(3), Label: "b's view", AddedAt: now})
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	inA(t, f, func(c *store.TenantTx) error {
		s, err := c.TrustedSigner("dev-a")
		if err != nil || !bytes.Equal(s.PublicKey, pub(2)) {
			t.Errorf("A's signer = %+v, %v", s, err)
		}
		// one active signing key per tenant
		if err := c.InsertConfigSigningKey(&store.ConfigSigningKey{KID: "cfg-a2", PublicKey: pub(4), PrivateSealed: []byte("y"), CreatedAt: now}); err == nil {
			t.Error("a second active key was accepted")
		}
		return nil
	})
}

func transportCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"ActiveConfigSigningKey", "InsertConfigSigningKey", "TrustedSigners", "TrustedSigner", "InsertTrustedSigner",
		"DeleteTrustedSigner", "InsertConfigImport", "ConfigImports"} {
		out[k] = true // TestIsolation_ConfigTransport
	}
	return out
}
