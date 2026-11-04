package wire_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce/sffake"
)

// A Salesforce connection's stored base URL and sealed credential build the connector: the
// integration user signs in with the stored client, the connector replaces an env-configured one,
// an override is refused outside dev and a refusal never echoes the credential.
func TestSalesforceConnectorIsBuiltFromTheStoredConfig(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	fk := sffake.New("3MVG9-key", "tessera@acme.example", &k.PublicKey)
	fk.Now = func() time.Time { return t0 }
	fk.Set("User", sffake.Row{"Id": "005000000000001AAA", "Username": "ada@acme.example", "Email": "ada@acme.example", "Name": "Ada", "IsActive": true, "UserType": "Standard"})
	srv, n := serve(t, fk)
	n.Endpoints = map[string]string{"TESSERA_SALESFORCE_BASE_URL": srv.URL}
	b, _ := json.Marshal(map[string]string{"client_id": "3MVG9-key", "username": "tessera@acme.example", "private_key": pemText})
	p := governed.Params{Type: governed.Salesforce, BaseURL: "https://acme.my.salesforce.com", Secret: string(b)}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "salesforce" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens, reads, _ := fk.Counts(); tokens != 1 || reads == 0 {
		t.Errorf("tokens %d reads %d, want the stored client to sign in and read", tokens, reads)
	}

	n.RT = connsync.Runtime{Env: config.Prod}
	if _, err := wire.Connector(p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
		t.Errorf("prod with an override: %v", err)
	}
	n.Endpoints = nil
	p.Secret = "SECRET-VALUE"
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("plain credential: %v", err)
	}
	p.Secret = string(b)
	p.BaseURL = "https://169.254.169.254"
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("metadata host: %v", err)
	}
}
