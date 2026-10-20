package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Certificate and branding isolation (schema/0410, 0411): a tenant sees and moves only its own rows, and a
// certificate cannot point at another tenant's connection.

func seedSAMLConn(t *testing.T, f *storetest.Fixture, b bool, name string) *store.IdPConnection {
	t.Helper()
	conn := &store.IdPConnection{Name: name, Protocol: "saml", Profile: store.ProfileGenericSAML, Status: "active",
		CreatedAt: storetest.Now, UpdatedAt: storetest.Now}
	fn := func(c *store.TenantTx) error { return c.InsertIdPConnection(conn) }
	if b {
		inB(t, f, fn)
	} else {
		inA(t, f, fn)
	}
	return conn
}

func testCert(id, purpose, status string, idp *string) *store.TenantCertificate {
	c := &store.TenantCertificate{ID: id, Purpose: purpose, Label: "cert " + id, IdPConnectionID: idp, Status: status,
		CertPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", Subject: "CN=" + id, Issuer: "CN=ca",
		SANs: []string{"DNS:" + id + ".example"}, NotBefore: storetest.Now, NotAfter: storetest.Now.AddDate(1, 0, 0),
		Fingerprint: strings.Repeat(id[:1], 64), KeyAlgorithm: "RSA-2048", SigAlgorithm: "SHA256-RSA", CreatedBy: "tester",
		CreatedAt: storetest.Now}
	if status != store.CertRetired {
		c.KeySealed = []byte("sealed-" + id)
	}
	return c
}

func TestIsolation_Certificates(t *testing.T) {
	f := storetest.TwoTenants(t)
	connA := seedSAMLConn(t, f, false, "saml a")
	connB := seedSAMLConn(t, f, true, "saml b")
	ia, ib := connA.ID.String(), connB.ID.String()
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertCertificate(testCert("a-next", store.CertSAMLSP, store.CertNext, &ia)); err != nil {
			return err
		}
		return c.InsertCertificate(testCert("a-mtls", store.CertMTLSClient, store.CertActive, nil))
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.InsertCertificate(testCert("b-sign", store.CertSigning, store.CertActive, nil))
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if cs, err := c.Certificates(); err != nil || len(cs) != 1 || cs[0].ID != "b-sign" {
			t.Errorf("Certificates = %v, %v", cs, err)
		}
		if _, err := c.Certificate("a-next"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Certificate(A's) = %v", err)
		}
		if _, err := c.CertificateKey("a-next"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CertificateKey(A's) = %v", err)
		}
		if _, err := c.NextSAMLCertificate(connA.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("NextSAMLCertificate(A's connection) = %v", err)
		}
		for name, err := range map[string]error{
			"ActivateCertificate": c.ActivateCertificate("a-next", storetest.Now),
			"RetireCertificate":   c.RetireCertificate("a-mtls", storetest.Now),
			"SetIdPSPKey":         c.SetIdPSPKey(connA.ID, []byte("x"), "pem", storetest.Now),
		} {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s(A's) = %v", name, err)
			}
		}
		// a row that points at A's connection is refused by the guard
		if err := c.InsertCertificate(testCert("b-ref", store.CertSAMLSP, store.CertNext, &ia)); err == nil {
			t.Error("a certificate for another tenant's connection was stored")
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	// the same fingerprint may exist in two tenants; one waiting key per connection
	inB(t, f, func(c *store.TenantTx) error {
		same := testCert("a-dup", store.CertMTLSClient, store.CertActive, nil)
		same.Fingerprint = strings.Repeat("a", 64)
		if err := c.InsertCertificate(same); err != nil {
			t.Errorf("same fingerprint in another tenant: %v", err)
		}
		if err := c.InsertCertificate(testCert("b-1", store.CertSAMLSP, store.CertNext, &ib)); err != nil {
			t.Errorf("first waiting key: %v", err)
		}
		if err := c.InsertCertificate(testCert("b-2", store.CertSAMLSP, store.CertNext, &ib)); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second waiting key = %v, want ErrDuplicate", err)
		}
		return nil
	})
}

func TestCertificateLifecycleStore(t *testing.T) {
	f := storetest.TwoTenants(t)
	conn := seedSAMLConn(t, f, false, "saml")
	id := conn.ID.String()
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertCertificate(testCert("x-next", store.CertSAMLSP, store.CertNext, &id)); err != nil {
			return err
		}
		if n, err := c.NextSAMLCertificate(conn.ID); err != nil || n.ID != "x-next" || len(n.SANs) != 1 {
			t.Errorf("NextSAMLCertificate = %v, %v", n, err)
		}
		if err := c.ActivateCertificate("x-next", storetest.Now); err != nil {
			t.Fatal(err)
		}
		if err := c.ActivateCertificate("x-next", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("activating twice = %v", err)
		}
		if err := c.RetireCertificate("x-next", storetest.Now); err != nil {
			t.Fatal(err)
		}
		if k, err := c.CertificateKey("x-next"); err != nil || len(k) != 0 {
			t.Errorf("a retired certificate keeps its key: %q, %v", k, err)
		}
		if err := c.RetireCertificate("x-next", storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("retiring twice = %v", err)
		}
		return nil
	})
}

func TestIsolation_Branding(t *testing.T) {
	f := storetest.TwoTenants(t)
	logo := &store.BrandingLogo{Data: []byte("png-bytes-a"), Type: "image/png", Width: 64, Height: 64, SHA256: strings.Repeat("a", 64)}
	inA(t, f, func(c *store.TenantTx) error {
		return c.PutBranding(&store.TenantBranding{DisplayName: "Alpha", PrimaryColor: "#0f6cbd", OnPrimaryColor: "#ffffff",
			UpdatedBy: "alice", UpdatedAt: storetest.Now}, logo, true)
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.Branding(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Branding(B) = %v", err)
		}
		if _, err := c.BrandingLogo(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BrandingLogo(B) = %v", err)
		}
		if n, err := c.BrandName(); err != nil || n != "" {
			t.Errorf("BrandName(B) = %q, %v", n, err)
		}
		return c.PutBranding(&store.TenantBranding{DisplayName: "Beta", PrimaryColor: "#000000", OnPrimaryColor: "#ffffff",
			UpdatedBy: "bob", UpdatedAt: storetest.Now}, nil, false)
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	inA(t, f, func(c *store.TenantTx) error {
		b, err := c.Branding()
		if err != nil || b.DisplayName != "Alpha" || b.LogoType != "image/png" || b.LogoWidth != 64 {
			t.Errorf("Branding(A) = %+v, %v", b, err)
		}
		// a colour change keeps the logo; removing it clears it
		if err := c.PutBranding(&store.TenantBranding{DisplayName: "Alpha 2", PrimaryColor: "#111111", OnPrimaryColor: "#ffffff",
			UpdatedBy: "alice", UpdatedAt: storetest.Now}, nil, false); err != nil {
			t.Fatal(err)
		}
		if l, err := c.BrandingLogo(); err != nil || string(l.Data) != "png-bytes-a" {
			t.Errorf("logo after a colour change = %v, %v", l, err)
		}
		if err := c.PutBranding(&store.TenantBranding{DisplayName: "Alpha 2", PrimaryColor: "#111111", OnPrimaryColor: "#ffffff",
			UpdatedBy: "alice", UpdatedAt: storetest.Now}, nil, true); err != nil {
			t.Fatal(err)
		}
		if _, err := c.BrandingLogo(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("logo after removal = %v", err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if n, err := c.BrandName(); err != nil || n != "Beta" {
			t.Errorf("BrandName(B) = %q, %v", n, err)
		}
		return nil
	})
}
