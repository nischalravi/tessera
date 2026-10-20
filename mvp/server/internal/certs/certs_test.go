package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

type spec struct {
	bits      int // RSA bits; 0 with ec set uses ECDSA P-256
	ec        bool
	notBefore time.Time
	notAfter  time.Time
	sig       x509.SignatureAlgorithm
}

// mk makes a self-signed certificate and returns it with its key as PKCS#8 PEM.
func mk(t *testing.T, s spec) (certPEM, keyPEM string, key crypto.Signer) {
	t.Helper()
	if s.notBefore.IsZero() {
		s.notBefore = t0.Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = t0.AddDate(1, 0, 0)
	}
	if s.bits == 0 && !s.ec {
		s.bits = 2048
	}
	var err error
	if s.ec {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, s.bits)
	}
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://sp.example/metadata")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "sp.example", Organization: []string{"Larkspur"}},
		NotBefore: s.notBefore, NotAfter: s.notAfter, DNSNames: []string{"sp.example"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.7")},
		EmailAddresses: []string{"ops@sp.example"}, URIs: []*url.URL{u}, SignatureAlgorithm: s.sig}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), key
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func TestParse(t *testing.T) {
	goodC, goodK, goodKey := mk(t, spec{})
	otherC, _, _ := mk(t, spec{})
	_, otherK, _ := mk(t, spec{})
	ecC, ecK, _ := mk(t, spec{ec: true})
	weakC, weakK, _ := mk(t, spec{bits: 1024})
	oldC, oldK, _ := mk(t, spec{notBefore: t0.AddDate(-2, 0, 0), notAfter: t0.AddDate(0, 0, -1)})
	sha1C, sha1K, _ := mk(t, spec{sig: x509.SHA1WithRSA})
	rsaPKCS1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(goodKey.(*rsa.PrivateKey))}))
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	_ = otherC

	for _, tc := range []struct {
		name     string
		cert     string
		key      string
		samlSP   bool
		wantCode string
	}{
		{"valid RSA", goodC, goodK, false, ""},
		{"valid RSA for SAML", goodC, goodK, true, ""},
		{"valid PKCS#1 key", goodC, rsaPKCS1, false, ""},
		{"valid EC", ecC, ecK, false, ""},
		{"EC key refused for a SAML SP", ecC, ecK, true, "key_not_rsa"},
		{"key of another certificate", goodC, otherK, false, "key_mismatch"},
		{"RSA 1024", weakC, weakK, false, "weak_key"},
		{"expired", oldC, oldK, false, "cert_expired"},
		{"SHA-1 signature", sha1C, sha1K, false, "weak_signature"},
		{"not PEM", "not a certificate", goodK, false, "bad_pem"},
		{"key where the certificate goes", goodK, goodK, false, "bad_pem"},
		{"two certificates", goodC + goodC, goodK, false, "bad_pem"},
		{"empty certificate", "", goodK, false, "bad_pem"},
		{"empty key", goodC, "", false, "bad_pem"},
		{"encrypted key", goodC, encrypted, false, "bad_key"},
		{"certificate as the key", goodC, goodC, false, "bad_key"},
		{"too large", goodC + strings.Repeat("#", MaxPEMBytes), goodK, false, "cert_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.cert, tc.key, t0, tc.samlSP)
			if got := code(err); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (%v)", got, tc.wantCode, err)
			}
			if err != nil {
				return
			}
			if !strings.Contains(string(p.KeyPEM), "BEGIN PRIVATE KEY") {
				t.Errorf("the key is not re-encoded as PKCS#8: %q", p.KeyPEM[:30])
			}
			if len(p.Info.Fingerprint) != 64 || p.Info.Subject == "" {
				t.Errorf("info = %+v", p.Info)
			}
		})
	}
}

func TestDescribeFields(t *testing.T) {
	c, k, _ := mk(t, spec{})
	p, err := Parse(c, k, t0, true)
	if err != nil {
		t.Fatal(err)
	}
	i := p.Info
	if i.KeyAlgorithm != "RSA-2048" || !strings.Contains(i.Subject, "sp.example") || i.Issuer != i.Subject {
		t.Errorf("info = %+v", i)
	}
	want := map[string]bool{"DNS:sp.example": true, "IP:10.0.0.7": true, "email:ops@sp.example": true, "URI:https://sp.example/metadata": true}
	for _, s := range i.SANs {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("missing SANs %v in %v", want, i.SANs)
	}
	if !i.NotAfter.After(i.NotBefore) || i.SigAlgorithm == "" {
		t.Errorf("dates or signature: %+v", i)
	}
}

func TestBucket(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		left time.Duration
		want int
	}{
		{90 * day, 0}, {31 * day, 0}, {30 * day, ExpiryWarn30}, {8 * day, ExpiryWarn30}, {7 * day, ExpiryWarn7}, {time.Hour, ExpiryWarn7},
		{-time.Hour, ExpiryWarn7}, {-40 * day, ExpiryWarn7},
	} {
		if got := Bucket(t0, t0.Add(tc.left)); got != tc.want {
			t.Errorf("Bucket(%v left) = %d, want %d", tc.left, got, tc.want)
		}
	}
	if d := DaysLeft(t0, t0.Add(-36*time.Hour)); d != -2 {
		t.Errorf("DaysLeft(-36h) = %d", d)
	}
	if d := DaysLeft(t0, t0.Add(10*24*time.Hour+time.Hour)); d != 10 {
		t.Errorf("DaysLeft(10d1h) = %d", d)
	}
}
