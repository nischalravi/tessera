package wire_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

// recorder is a fake that answers every path with body and records what it is asked for.
type recorder struct {
	mu    sync.Mutex
	paths []string
	auth  []string
	forms []string
	body  func(path string) string
}

func (f *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	_ = r.ParseForm()
	f.forms = append(f.forms, r.PostForm.Encode())
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(f.body(r.URL.Path)))
}

// An Okta connection's stored org URL and sealed credential build the connector: the API token
// reaches the org, the connector replaces an env-configured one, an override is refused outside
// dev and a refusal never echoes the credential.
func TestOktaConnectorIsBuiltFromTheStoredConfig(t *testing.T) {
	fake := &recorder{body: func(path string) string {
		if strings.Contains(path, "/iam/assignees") {
			return `{"value":[]}`
		}
		return `[]`
	}}
	srv, n := serve(t, fake)
	n.Endpoints = map[string]string{"TESSERA_OKTA_ORG_URL": srv.URL}
	const cred = `{"api_token":"SECRET-VALUE"}`
	p := governed.Params{Type: governed.Okta, OrgURL: "https://acme.okta.com", Secret: cred}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "okta" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sawUsers bool
	for i, path := range fake.paths {
		sawUsers = sawUsers || path == "/api/v1/users"
		if fake.auth[i] != "SSWS SECRET-VALUE" {
			t.Errorf("%s: authorization %q", path, fake.auth[i])
		}
	}
	if !sawUsers {
		t.Errorf("paths = %v, want the users read", fake.paths)
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
	if s := (governed.Params{Type: governed.Okta, Secret: cred}).String(); strings.Contains(s, "SECRET-VALUE") {
		t.Errorf("params print the credential: %s", s)
	}
}

// An Entra connection's stored tenant and sealed client build the connector: the token is asked
// for the stored tenant, the connector replaces an env-configured one, an override is refused
// outside dev and a refusal never echoes the credential.
func TestEntraConnectorIsBuiltFromTheStoredConfig(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	fake := &recorder{}
	srv, n := serve(t, fake)
	fake.body = func(path string) string {
		switch {
		case strings.HasSuffix(path, "/oauth2/v2.0/token"):
			return `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`
		case strings.Contains(path, "delta"):
			return `{"value":[],"@odata.deltaLink":"` + srv.URL + path + `?$deltatoken=d1"}`
		}
		return `{"value":[]}`
	}
	n.Endpoints = map[string]string{"TESSERA_ENTRA_GRAPH_URL": srv.URL, "TESSERA_ENTRA_AUTHORITY_URL": srv.URL}
	const cred = `{"client_id":"app-1","client_secret":"SECRET-VALUE"}`
	p := governed.Params{Type: governed.Entra, TenantID: tenant, Cloud: "global", Secret: cred}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "entra" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if _, err := cn.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sawToken bool
	for i, path := range fake.paths {
		if path == "/"+tenant+"/oauth2/v2.0/token" {
			sawToken = true
			if !strings.Contains(fake.forms[i], "client_id=app-1") {
				t.Errorf("token form %q lacks the stored client", fake.forms[i])
			}
		}
	}
	if !sawToken {
		t.Errorf("paths = %v, want a token request for the stored tenant", fake.paths)
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
}
