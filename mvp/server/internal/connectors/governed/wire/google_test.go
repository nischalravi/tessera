package wire_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

// googleFake is a Workspace customer with three users: two in /Eng and /Fin, one elsewhere.
type googleFake struct {
	mu      sync.Mutex
	queries []string
}

func (g *googleFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	user := func(id, mail string) string {
		return `{"id":"` + id + `","primaryEmail":"` + mail + `","name":{"fullName":"X"}}`
	}
	switch {
	case r.URL.Path == "/token":
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
	case strings.HasSuffix(r.URL.Path, "/users"):
		q := r.URL.Query().Get("query")
		g.mu.Lock()
		g.queries = append(g.queries, q)
		g.mu.Unlock()
		switch q {
		case "orgUnitPath='/Eng'":
			_, _ = w.Write([]byte(`{"users":[` + user("1", "ada@example.com") + `]}`))
		case "orgUnitPath='/Fin'":
			_, _ = w.Write([]byte(`{"users":[` + user("2", "ben@example.com") + `]}`))
		default: // the whole customer
			_, _ = w.Write([]byte(`{"users":[` + user("1", "ada@example.com") + `,` + user("2", "ben@example.com") + `,` + user("3", "cy@example.com") + `]}`))
		}
	default: // groups, members, roles and assignments: none
		_, _ = w.Write([]byte(`{}`))
	}
}

func googleCredential(t *testing.T, admin string) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{"type": "service_account", "client_email": "reader@fixture.iam.example.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	if admin != "" {
		m["admin_email"] = admin
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// A connection created with org units syncs only those: wire.Connector builds the
// Google connector from the connection's stored scope, and the connector is marked
// as built from a connection (it replaces an env-configured one).
func TestGoogleConnectorIsBuiltFromTheStoredConfig(t *testing.T) {
	fake := &googleFake{}
	srv, n := serve(t, fake)
	n.Endpoints = map[string]string{"TESSERA_GOOGLE_API_URL": srv.URL, "TESSERA_GOOGLE_TOKEN_URL": srv.URL + "/token"}
	p := governed.Params{Type: governed.GoogleWorkspace, Customer: "my_customer", OrgUnits: []string{"/Eng", "/Fin"},
		Secret: googleCredential(t, "admin@example.com")}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "google" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	res, err := cn.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range res.Accounts {
		if a.System == "google" {
			ids = append(ids, a.ExternalID)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"1", "2"}) {
		t.Errorf("accounts = %v, want only the users of /Eng and /Fin", ids)
	}
	slices.Sort(fake.queries)
	if want := []string{"orgUnitPath='/Eng'", "orgUnitPath='/Fin'"}; !slices.Equal(fake.queries, want) {
		t.Errorf("user queries = %q, want %q", fake.queries, want)
	}

	// no org units: the whole customer, as an env-configured connector reads it
	fake.queries = nil
	p.OrgUnits = nil
	cn, err = wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if res, err = cn.Discover(context.Background()); err != nil || len(res.Accounts) != 3 {
		t.Errorf("no org units: %d accounts, %v; want all 3 users", len(res.Accounts), err)
	}

	// a connection never carries an endpoint: an override is refused outside dev, and the
	// credential is never echoed by a refusal
	n.RT = connsync.Runtime{Env: config.Prod}
	if _, err := wire.Connector(p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
		t.Errorf("prod with an override: %v", err)
	}
	n.Endpoints = nil
	p.Secret = googleCredential(t, "")
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("no admin e-mail: %v", err)
	}
	if s := p.String(); strings.Contains(s, "PRIVATE KEY") {
		t.Errorf("params print the credential: %s", s)
	}
}
