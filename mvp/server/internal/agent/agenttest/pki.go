// Package agenttest holds test helpers for the Directory Agent: a throwaway CA
// and a server certificate for the agent listener. It is imported only by
// tests.
package agenttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PKI is a CA and a server certificate (for localhost and 127.0.0.1) signed by
// it, written to files as the agent listener's configuration expects.
type PKI struct {
	CAPEM    []byte
	CertFile string
	KeyFile  string
}

// NewPKI creates a CA and a server certificate in a temporary directory.
func NewPKI(tb testing.TB) *PKI {
	tb.Helper()
	must := func(err error) {
		tb.Helper()
		if err != nil {
			tb.Fatal(err)
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tessera agent test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	must(err)
	ca, err := x509.ParseCertificate(caDER)
	must(err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	must(err)
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	dir := tb.TempDir()
	p := &PKI{CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}
	must(os.WriteFile(p.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(os.WriteFile(p.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600))
	return p
}
