package wire_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen/fakerest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// A REST connection's stored spec and sealed credential build the connector, which replaces an
// env-configured one; a spec the environment refuses fails closed and never echoes the credential.
func TestRestConnectorIsBuiltFromTheStoredSpec(t *testing.T) {
	f := fakerest.New(3)
	t.Cleanup(f.Close)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, MaxBodyBytes: 8 << 20, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	n := governed.Net{RT: connsync.Runtime{Env: config.Dev, AllowLoopback: true}, HC: hc, Now: func() time.Time { return t0 }}
	spec := &restgen.Spec{BaseURL: f.URL, Auth: restgen.Auth{Type: restgen.AuthBearer}, Limits: restgen.Limits{RequestsPerSecond: 100, Burst: 100},
		Users: &restgen.Resource{Path: "/offset/users", Pagination: restgen.Pagination{Style: restgen.PageOffset, OffsetParam: "offset", SizeParam: "limit", PageSize: 10},
			Fields: map[string]string{"id": "$.id", "username": "$.login", "email": "$.email", "display_name": "$.name"}}}
	p := governed.Params{Type: governed.RestGeneric, Rest: spec, Secret: fakerest.Bearer}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "rest" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	if res, err := cn.Discover(context.Background()); err != nil || len(res.Accounts) != 3 {
		t.Fatalf("discover: %v", err)
	}

	p.Secret = ""
	if _, err := wire.Connector(p, n); err == nil {
		t.Error("opened without a credential")
	}
	p.Secret, p.Rest = "SECRET-VALUE", nil
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("no spec: %v", err)
	}
	bad := *spec
	bad.BaseURL = "http://169.254.169.254"
	p.Rest = &bad
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("metadata host: %v", err)
	}
	n.RT = connsync.Runtime{Env: config.Prod}
	p.Rest = spec // an http URL: refused under the production rules
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("http in prod: %v", err)
	}
}

// A SQL connection's stored settings and sealed password build the connector under the production
// rules unless the runtime is dev: an unknown environment name never gets the dev ones.
func TestSQLConnectorIsBuiltFromTheStoredSettings(t *testing.T) {
	cfg := &sqldb.Config{Engine: "postgres", Host: "db.example.com", Database: "app", Username: "ro", Mode: sqldb.ModeNative}
	p := governed.Params{Type: governed.SQL, SQL: cfg, Secret: "pw"}
	n := governed.Net{RT: connsync.Runtime{Env: config.Prod}, Now: func() time.Time { return t0 }}
	cn, err := wire.Connector(p, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cn.(connectors.ConnectionBacked); !ok || cn.System() != "sql" {
		t.Errorf("connector %T (system %q) is not marked as connection-backed", cn, cn.System())
	}
	off := *cfg
	off.TLS = "disable"
	p.SQL = &off
	if _, err := wire.Connector(p, governed.Net{RT: connsync.Runtime{Env: "staging"}}); err == nil {
		t.Error("tls disable accepted in an unknown environment")
	}
	if _, err := wire.Connector(p, governed.Net{RT: connsync.Runtime{Env: config.Dev, AllowLoopback: true}}); err != nil {
		t.Errorf("tls disable in dev: %v", err)
	}
	p.Secret, p.SQL = "SECRET-VALUE", &sqldb.Config{Engine: "postgres", Host: "169.254.169.254", Username: "ro", Mode: sqldb.ModeNative}
	if _, err := wire.Connector(p, n); err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Errorf("metadata host: %v", err)
	}
}
