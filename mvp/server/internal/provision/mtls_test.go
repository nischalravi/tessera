package provision_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/certs"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

type pkiCert struct {
	c   *x509.Certificate
	key *ecdsa.PrivateKey
	pem string
}

func mkCert(t *testing.T, cn string, isCA bool, parent *pkiCert, now time.Time, ip net.IP) *pkiCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: isCA,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	issuer, signer := tmpl, crypto.Signer(key)
	if parent != nil {
		issuer, signer = parent.c, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pkiCert{c: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// A connection with an mTLS certificate (a chain and trust anchors) reaches a target that demands a client
// certificate and has a private CA; without it the operation cannot be sent, and a dry run uses the certificate too.
func TestEngine_PresentsTheConnectionsMTLSCertificate(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	now := e.now
	clientRoot := mkCert(t, "client root", true, nil, now, nil)
	clientInter := mkCert(t, "client intermediate", true, clientRoot, now, nil)
	clientLeaf := mkCert(t, "tessera-client", false, clientInter, now, nil)
	serverCA := mkCert(t, "server ca", true, nil, now, nil)
	serverCert := mkCert(t, "scim.internal", false, serverCA, now, net.ParseIP("127.0.0.1"))

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientRoot.c)
	tlsSrv := httptest.NewUnstartedServer(e.fake.Handler())
	tlsSrv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.c.Raw}, PrivateKey: serverCert.key}}}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	e.srv = tlsSrv
	e.setTarget(true, provision.Settings{})

	// no certificate: the target is unreachable, so the operation is not verified
	op := e.submit(target.DisableAccount, "mtls:none")
	e.run()
	if got := e.op(op.ID); got.Status == provision.Verified {
		t.Fatalf("an operation reached a target that requires a client certificate without one: %+v", got)
	}
	if _, active := e.fake.Active(aliceName); !active {
		t.Fatal("the target changed without a client certificate")
	}

	// a dry run without the certificate says why it cannot show anything
	dry, err := e.eng.DryRun(t.Context(), e.f.A.ID, e.conn, target.Request{Kind: target.DisableAccount, Key: "dry", Account: target.Account{Username: aliceName}})
	if err != nil || dry.Error == "" || dry.Writes() != 0 {
		t.Errorf("dry run without a certificate: %+v, %v", dry, err)
	}

	// upload the chain with the private CA as trust anchor, for this connection
	var up *store.TenantCertificate
	e.inA(func(tx *store.TenantTx) error {
		kb, _ := x509.MarshalPKCS8PrivateKey(clientLeaf.key)
		var err error
		up, err = certs.UploadCertificate(tx, e.sealer, certs.Upload{Purpose: store.CertMTLSClient, Label: "SCIM mTLS", ConnectionID: &e.conn,
			CertPEM: clientLeaf.pem + clientInter.pem, TrustPEM: serverCA.pem,
			KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))}, "admin", now)
		return err
	})
	if up == nil || up.TrustPEM == "" {
		t.Fatalf("uploaded = %+v", up)
	}
	// the operation is waiting for its next attempt (no backoff in tests)
	if got := e.op(op.ID); got.Status != provision.Queued || got.Attempts != 1 {
		t.Fatalf("the operation without a certificate = %+v", got)
	}
	st := e.run()
	if got := e.op(op.ID); got.Status != provision.Verified || st.Verified == 0 {
		t.Fatalf("with the certificate: op %+v stats %+v", got, st)
	}
	if _, active := e.fake.Active(aliceName); active {
		t.Error("the target still shows the user active")
	}

	// a dry run presents the certificate too, and still sends no write
	e.fake.AddUser("bob@larkspur.example", "Bob", true)
	dry, err = e.eng.DryRun(t.Context(), e.f.A.ID, e.conn, target.Request{Kind: target.DisableAccount, Key: "dry2", Account: target.Account{Username: "bob@larkspur.example"}})
	if err != nil || dry.Error != "" || dry.Writes() != 1 {
		t.Fatalf("dry run with the certificate: %+v, %v", dry, err)
	}
	if _, active := e.fake.Active("bob@larkspur.example"); !active {
		t.Error("the dry run changed the target")
	}
	// a retired certificate is no longer presented
	e.inA(func(tx *store.TenantTx) error { _, err := certs.Retire(tx, up.ID, "admin", e.now); return err })
	e.fake.AddUser("carol@larkspur.example", "Carol", true)
	op2 := submitFor(e, "carol@larkspur.example", "mtls:retired")
	e.run()
	if got := e.op(op2.ID); got.Status == provision.Verified {
		t.Errorf("a retired certificate was still presented: %+v", got)
	}
	if _, active := e.fake.Active("carol@larkspur.example"); !active {
		t.Error("the target changed after the certificate was retired")
	}
}

func submitFor(e *env, user, key string) *store.ProvOp {
	e.t.Helper()
	var op *store.ProvOp
	e.inA(func(c *store.TenantTx) error {
		var err error
		op, _, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: target.DisableAccount,
			Account: target.Account{Username: user}, Source: provision.SourceAPI, Key: key, Completion: "test.mark", Data: map[string]int{"n": 1}})
		return err
	})
	return op
}
