package safehttp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// clientPKI makes a CA and a client certificate it signed.
func clientPKI(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tessera-client"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// WithClientTLS gives a safehttp client a TLS client certificate and trust anchors without loosening its guard.
func TestWithClientTLS(t *testing.T) {
	clientCAs, pair := clientPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	serverRoots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	base, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: serverRoots})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := get(base, srv.URL); err == nil {
		t.Fatal("a client without a certificate was served by a server that requires one")
	}
	withCert, ok := safehttp.WithClientTLS(base, []tls.Certificate{pair}, nil)
	if !ok {
		t.Fatal("WithClientTLS refused a safehttp client")
	}
	if r, err := get(withCert, srv.URL); err != nil || string(r.Body) != "tessera-client" {
		t.Fatalf("with the certificate: %v %v", r, err)
	}
	// trust anchors replace the roots: the server's own CA is trusted, and then a client given another CA's pool is not
	if r, err := get(mustTLS(t, base, pair, serverRoots), srv.URL); err != nil || string(r.Body) != "tessera-client" {
		t.Fatalf("with the server's CA as trust anchor: %v %v", r, err)
	}
	if _, err := get(mustTLS(t, base, pair, clientCAs), srv.URL); err == nil {
		t.Error("a client that trusts only another CA accepted the server certificate")
	}
	// the original client is untouched
	if _, err := get(base, srv.URL); err == nil {
		t.Error("the original client gained the certificate")
	}
	// the guard still applies to the copy
	if _, err := get(withCert, "https://169.254.169.254/latest/meta-data"); err == nil || !strings.Contains(err.Error(), "safehttp:") {
		t.Errorf("metadata address through the copy: %v", err)
	}
	if _, err := get(withCert, "http://example.com/"); err == nil || !strings.Contains(err.Error(), "https only") {
		t.Errorf("plain http through the copy: %v", err)
	}
	if got, ok := safehttp.WithClientTLS(http.DefaultClient, []tls.Certificate{pair}, nil); ok || got != http.DefaultClient {
		t.Error("a client that is not a safehttp client was accepted")
	}
}

func mustTLS(t *testing.T, c *http.Client, pair tls.Certificate, roots *x509.CertPool) *http.Client {
	t.Helper()
	out, ok := safehttp.WithClientTLS(c, []tls.Certificate{pair}, roots)
	if !ok {
		t.Fatal("WithClientTLS refused a safehttp client")
	}
	return out
}
