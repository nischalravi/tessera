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

// workdayFake is a Workday tenant with one worker; it records the paths it is asked for.
type workdayFake struct {
	mu    sync.Mutex
	paths []string
}

func (f *workdayFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/token"):
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
	case strings.HasSuffix(r.URL.Path, "/workers"):
		_, _ = w.Write([]byte(`{"total":1,"data":[{"id":"w1","descriptor":"Ada Lovelace","employeeId":"E1","primaryWorkEmail":"ada@example.com","active":true}]}`))
	default:
		_, _ = w.Write([]byte(`{"total":0,"data":[]}`))
	}
}

// A Workday connection's stored tenant_host and api_version are the ones the connector reads:
// the api_version of the config is in the request paths, the connector replaces an
// env-configured one (connectors.ConnectionBacked), and a refusal never echoes the credential.
func TestWorkdayConnectorIsBuiltFromTheStoredConfig(t *testing.T) {
	fake := &workdayFake{}
	srv, n := serve(t, fake)
	n.Endpoints = map[string]string{"TESSERA_WORKDAY_BASE_URL": srv.URL}
	const cred = `{"tenant":"acme_dpt1","client_id":"cid","client_secret":"SECRET-VALUE"}`
	p := governed.Params{Type: governed.Workday, TenantHost: "wd2-impl-services1.workday.com", APIVersion: "v44.0", Secret: cred}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "workday" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	res, err := cn.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var accounts int
	for _, a := range res.Accounts {
		if a.System == "workday" {
			accounts++
		}
	}
	if accounts != 1 {
		t.Errorf("accounts = %d, want the one worker", accounts)
	}
	var sawWorkers bool
	for _, path := range fake.paths {
		if path == "/ccx/api/v44.0/acme_dpt1/workers" {
			sawWorkers = true
		}
		if strings.Contains(path, "/api/v1/") {
			t.Errorf("a request used the default version: %s", path)
		}
	}
	if !sawWorkers {
		t.Errorf("paths = %v, want the workers of api version v44.0", fake.paths)
	}

	// a connection never carries an endpoint: an override is refused outside dev
	n.RT = connsync.Runtime{Env: config.Prod}
	if _, err := wire.Connector(p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
		t.Errorf("prod with an override: %v", err)
	}
	// a credential that is not usable is refused without echoing it
	n.Endpoints = nil
	p.Secret = "SECRET-VALUE"
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("plain credential: %v", err)
	}
	if s := (governed.Params{Type: governed.Workday, Secret: cred}).String(); strings.Contains(s, "SECRET-VALUE") {
		t.Errorf("params print the credential: %s", s)
	}
}
