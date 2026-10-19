package readiness

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// readySCIM creates a real (non-demo) scim_app connection in ready_to_validate.
func readySCIM(t *testing.T, s *Service, st Scope) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Payroll SCIM", ConnectorType: "scim_app", System: "payroll",
			Config: json.RawMessage(`{"base_url":"https://example.com/scim/v2","technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/scim"}, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Attest(c, id, "base.owner", "both owners agreed in CHG-1042", "admin", t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	return id
}

// scimStub answers the discovery and list reads of a one-group application.
func scimStub(t *testing.T) (*http.Client, string) {
	t.Helper()
	const lr = `"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer scim-test-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/scim/v2/") {
		case "ServiceProviderConfig":
			_, _ = w.Write([]byte(`{"patch":{"supported":true},"filter":{"supported":true,"maxResults":100}}`))
		case "ResourceTypes":
			_, _ = w.Write([]byte(`{` + lr + `,"totalResults":2,"Resources":[{"name":"User"},{"name":"Group"}]}`))
		case "Schemas":
			_, _ = w.Write([]byte(`{` + lr + `,"totalResults":1,"Resources":[{"id":"u"}]}`))
		case "Users":
			if r.URL.Query().Get("startIndex") == "1" {
				_, _ = w.Write([]byte(`{` + lr + `,"totalResults":1,"startIndex":1,"Resources":[{"id":"u1","groups":[{"value":"g1"}]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{` + lr + `,"totalResults":1,"startIndex":2,"Resources":[]}`))
		case "Groups":
			if r.URL.Query().Get("startIndex") == "1" {
				_, _ = w.Write([]byte(`{` + lr + `,"totalResults":1,"startIndex":1,"Resources":[{"id":"g1","members":[{"value":"u1","type":"User"}]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{` + lr + `,"totalResults":1,"startIndex":2,"Resources":[]}`))
		case "Groups/g1":
			_, _ = w.Write([]byte(`{"id":"g1","members":[{"value":"u1","type":"User"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := srv.Client()
	hc.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return hc, "scim-test-token"
}

// A real scim_app connection has no simulated results: without a credential
// every live check errors (and the run is not labelled simulated); with one,
// the checks run against the application and can satisfy gates.
func TestValidate_SCIMLive(t *testing.T) {
	s, st := newSvc(t), newStore(t)
	id := readySCIM(t, s, st)

	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("a real connection's run is labelled simulated")
	}
	r := resultFor(v, "scim.endpoint", "endpoint_reachable")
	if r == nil || r.Status != "error" || r.Simulated {
		t.Fatalf("without a credential: %+v", r)
	}

	hc, tok := scimStub(t)
	s.Runner.SCIM = SCIMLiveOptions{Client: hc, Token: func(*Bundle) (scim.Secret, error) { return scim.Secret(tok), nil }}
	clock := clockAt(t0.Add(2 * time.Hour))
	v, err = s.Validate(context.Background(), st, id, "admin", clock)
	if err != nil {
		t.Fatal(err)
	}
	if v.Simulated {
		t.Error("live run labelled simulated")
	}
	for _, c := range [][2]string{{"scim.endpoint", "endpoint_reachable"}, {"scim.auth", "auth_ok"}, {"scim.discovery", "scim_discovery"},
		{"scim.paging", "paging"}, {"scim.groups.members", "members_complete"}} {
		r := resultFor(v, c[0], c[1])
		if r == nil || r.Status != "pass" || r.Simulated {
			t.Errorf("%s: %+v", c[1], r)
		}
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), tok) {
		t.Error("the token is in the run view")
	}

	// Demo connectors keep their simulated prober.
	if _, ok, _ := s.Runner.SCIM.prober(&Bundle{Conn: &store.Connection{ConnectorType: "demo-ad"}}, t0); ok {
		t.Error("a demo connection got the real SCIM prober")
	}
}
