// Package devidptest runs the dev IdP in-process on a loopback httptest
// server, for relying-party tests (docs/design/phase-0-platform-security.md
// §18.5). Import it from _test.go files only.
package devidptest

import (
	"net"
	"net/http/httptest"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
)

// Test client registered by Start when the config has no clients. The secret
// is a fixed test value, not a credential.
const (
	ClientID     = "tessera-test"
	ClientSecret = "devidp-test-secret" // #nosec G101 -- fixed test-only value for an in-process mock IdP
)

// IdP is a running in-process dev IdP.
type IdP struct {
	*devidp.Server
	HTTP *httptest.Server
	URL  string // the issuer
}

// Start starts a dev IdP on 127.0.0.1 with fault injection enabled. When
// cfg.Clients is empty it registers ClientID/ClientSecret with redirect URIs
// on any loopback port. The server stops when the test ends.
func Start(tb testing.TB, cfg devidp.Config) *IdP {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	cfg.Issuer = "http://" + ln.Addr().String()
	cfg.Faults = true
	if len(cfg.Clients) == 0 {
		cfg.Clients = []devidp.Client{{
			ID:           ClientID,
			Secret:       ClientSecret,
			RedirectURIs: []string{"http://127.0.0.1:*/callback", "http://127.0.0.1:*/api/auth/oidc/*/callback"},
		}}
	}
	srv, err := devidp.New(cfg)
	if err != nil {
		_ = ln.Close()
		tb.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(srv.Handler())
	_ = hs.Listener.Close()
	hs.Listener = ln
	hs.Start()
	tb.Cleanup(hs.Close)
	return &IdP{Server: srv, HTTP: hs, URL: cfg.Issuer}
}
