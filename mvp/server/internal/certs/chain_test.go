package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  string
}

func newCert(t *testing.T, cn string, isCA bool, parent *ca, notAfter time.Time) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: t0.Add(-time.Hour),
		NotAfter: notAfter, BasicConstraintsValid: true, IsCA: isCA, DNSNames: []string{cn + ".example"}}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, issuer := crypto.Signer(key), tmpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func keyPEM(t *testing.T, c *ca) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func TestParseMTLS_ChainAndTrustAnchors(t *testing.T) {
	later := t0.AddDate(1, 0, 0)
	root := newCert(t, "root", true, nil, later.AddDate(5, 0, 0))
	inter := newCert(t, "inter", true, root, later.AddDate(3, 0, 0))
	leaf := newCert(t, "leaf", false, inter, later)
	other := newCert(t, "other-root", true, nil, later)
	key := keyPEM(t, leaf)

	p, err := ParseMTLS(leaf.pem+inter.pem, root.pem, key, t0)
	if err != nil {
		t.Fatalf("a leaf with its intermediate and a root as trust anchor: %v", err)
	}
	if strings.Count(p.CertPEM, "BEGIN CERTIFICATE") != 2 || strings.Count(p.TrustPEM, "BEGIN CERTIFICATE") != 1 || p.Info.Subject != "CN=leaf" {
		t.Errorf("parsed = %q / %q / %s", p.CertPEM, p.TrustPEM, p.Info.Subject)
	}
	if bytesKey := string(p.KeyPEM); !strings.Contains(bytesKey, "PRIVATE KEY") {
		t.Error("no key returned to seal")
	}
	if pool, err := TrustPool(p.TrustPEM); err != nil || pool == nil {
		t.Errorf("trust pool = %v, %v", pool, err)
	}
	if pool, err := TrustPool(""); err != nil || pool != nil {
		t.Errorf("no anchors must mean the system roots: %v, %v", pool, err)
	}
	// a single certificate with no anchors is still a valid upload
	if p, err := ParseMTLS(leaf.pem, "", key, t0); err != nil || p.TrustPEM != "" {
		t.Errorf("single certificate: %v %q", err, p.TrustPEM)
	}

	expired := newCert(t, "old-root", true, nil, t0.Add(-time.Minute))
	expiredInter := newCert(t, "old-inter", true, root, t0.Add(-time.Minute))
	leafOfExpired := newCert(t, "leaf2", false, expiredInter, later)
	notCA := newCert(t, "not-ca", false, root, later)
	leafOfNotCA := newCert(t, "leaf3", false, notCA, later)
	keyBlock := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	many := strings.Repeat(inter.pem, MaxChainCerts)
	for name, c := range map[string]struct {
		chain, trust, key, code string
	}{
		"issuer first":                      {inter.pem + leaf.pem, "", key, "bad_chain"},
		"an intermediate that did not sign": {leaf.pem + other.pem, "", key, "bad_chain"},
		"a non-CA intermediate":             {leafOfNotCA.pem + notCA.pem, "", keyPEM(t, leafOfNotCA), "bad_chain"},
		"an expired intermediate":           {leafOfExpired.pem + expiredInter.pem, "", keyPEM(t, leafOfExpired), "cert_expired"},
		"a key in the chain":                {leaf.pem + keyBlock, "", key, "bad_pem"},
		"too long a chain":                  {leaf.pem + many, "", key, "bad_pem"},
		"the wrong key":                     {leaf.pem, "", keyPEM(t, inter), "key_mismatch"},
		"a leaf as trust anchor":            {leaf.pem, leaf.pem, key, "bad_trust_anchor"},
		"an expired trust anchor":           {leaf.pem, expired.pem, key, "cert_expired"},
		"a key as trust anchor":             {leaf.pem, keyBlock, key, "bad_pem"},
		"garbage as trust anchors":          {leaf.pem, "not pem", key, "bad_pem"},
		"no certificate":                    {"", "", key, "bad_pem"},
		"too many anchors":                  {leaf.pem, strings.Repeat(root.pem, MaxTrustAnchors+1), key, "bad_pem"},
	} {
		_, err := ParseMTLS(c.chain, c.trust, c.key, t0)
		var ce *Error
		if err == nil || !asError(err, &ce) || ce.Code != c.code {
			t.Errorf("%s: err = %v, want code %s", name, err, c.code)
		}
	}
	big := strings.Repeat("A", MaxPEMBytes+1)
	if _, err := ParseMTLS(leaf.pem, big, key, t0); err == nil {
		t.Error("an oversized trust bundle was accepted")
	}
}

func asError(err error, out **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*out = e
	}
	return ok
}
