package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func transportServers(t *testing.T, env string) (f *storetest.Fixture, a, b http.Handler) {
	t.Helper()
	f = storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *Server {
		s := newIsolationServer(f)
		s.cfg.Sealer = sealer
		s.cfg.Env = env
		return s
	}
	return f, asAdmin(t, mk(), f.DB, f.A.ID, storetest.Now).Handler(), asAdmin(t, mk(), f.DB, f.B.ID, storetest.Now).Handler()
}

func decodeJSON(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("%v: %.300s", err, body)
	}
}

// export signs tenant A's configuration and returns the bundle file and A's key.
func exportA(t *testing.T, a http.Handler) (bundle string, key map[string]any) {
	t.Helper()
	rec := serveOnce(a, http.MethodPost, "/api/config/export", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("export %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Hash   string          `json:"hash"`
		Bundle json.RawMessage `json:"bundle"`
	}
	decodeJSON(t, rec.Body.String(), &out)
	var k struct {
		Key map[string]any `json:"key"`
	}
	decodeJSON(t, serveOnce(a, http.MethodGet, "/api/config/signing-key", "").Body.String(), &k)
	if k.Key == nil {
		t.Fatal("no signing key after export")
	}
	return string(out.Bundle), k.Key
}

func trustA(t *testing.T, b http.Handler, key map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"kid": key["kid"], "public_key": key["public_key"], "label": "larkspur dev"})
	if rec := serveOnce(b, http.MethodPost, "/api/config/trusted-signers", string(body)); rec.Code != http.StatusCreated {
		t.Fatalf("trust %d: %s", rec.Code, rec.Body)
	}
}

func TestConfigTransport_ExportPlanApply(t *testing.T) {
	_, a, b := transportServers(t, "test")
	var k struct {
		Key any `json:"key"`
	}
	decodeJSON(t, serveOnce(a, http.MethodGet, "/api/config/signing-key", "").Body.String(), &k)
	if k.Key != nil {
		t.Fatalf("key before the first export: %v", k.Key)
	}
	bundle, key := exportA(t, a)

	rec := serveOnce(b, http.MethodPost, "/api/config/import/plan", bundle)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "untrusted_signer") {
		t.Fatalf("untrusted plan %d: %s", rec.Code, rec.Body)
	}
	trustA(t, b, key)
	if rec := serveOnce(b, http.MethodPost, "/api/config/trusted-signers", `{"kid":"x","public_key":"short","label":"x"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad key %d", rec.Code)
	}

	rec = serveOnce(b, http.MethodPost, "/api/config/import/plan", bundle)
	if rec.Code != http.StatusOK {
		t.Fatalf("plan %d: %s", rec.Code, rec.Body)
	}
	var plan struct {
		Hash     string   `json:"hash"`
		Refusals []string `json:"refusals"`
		Items    []any    `json:"items"`
	}
	decodeJSON(t, rec.Body.String(), &plan)
	if plan.Hash == "" || len(plan.Refusals) != 0 {
		t.Fatalf("plan %s", rec.Body)
	}

	if rec := serveOnce(b, http.MethodPost, "/api/config/import/apply", bundle); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("apply without hash %d", rec.Code)
	}
	if rec := serveOnce(b, http.MethodPost, "/api/config/import/apply?hash=00", bundle); !strings.Contains(rec.Body.String(), "hash_mismatch") {
		t.Errorf("apply with another hash %d: %s", rec.Code, rec.Body)
	}
	rec = serveOnce(b, http.MethodPost, "/api/config/import/apply?hash="+url.QueryEscape(plan.Hash), bundle)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply %d: %s", rec.Code, rec.Body)
	}
	var imps []map[string]any
	decodeJSON(t, serveOnce(b, http.MethodGet, "/api/config/imports", "").Body.String(), &imps)
	if len(imps) != 1 || imps[0]["bundle_hash"] != plan.Hash {
		t.Errorf("imports %v", imps)
	}
	// Tenant A sees none of B's imports or signers.
	if body := serveOnce(a, http.MethodGet, "/api/config/imports", "").Body.String(); strings.TrimSpace(body) != "[]" {
		t.Errorf("A sees imports: %s", body)
	}
	if body := serveOnce(a, http.MethodGet, "/api/config/trusted-signers", "").Body.String(); strings.TrimSpace(body) != "[]" {
		t.Errorf("A sees signers: %s", body)
	}
}

// TestIsolation_TrustedSignerScoped: tenant A cannot remove a signer that
// tenant B trusts; it answers as for a kid that exists nowhere.
func TestIsolation_TrustedSignerScoped(t *testing.T) {
	_, a, b := transportServers(t, "test")
	_, key := exportA(t, a)
	trustA(t, b, key)
	kid := key["kid"].(string)
	cross := serveOnce(a, http.MethodDelete, "/api/config/trusted-signers/"+kid, "")
	missing := serveOnce(a, http.MethodDelete, "/api/config/trusted-signers/cfg-nowhere", "")
	if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() {
		t.Errorf("cross %d %s, missing %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
	if body := serveOnce(b, http.MethodGet, "/api/config/trusted-signers", "").Body.String(); !strings.Contains(body, kid) {
		t.Errorf("B lost its signer: %s", body)
	}
	if rec := serveOnce(b, http.MethodDelete, "/api/config/trusted-signers/"+kid, ""); rec.Code != http.StatusOK {
		t.Errorf("B removes its own signer: %d %s", rec.Code, rec.Body)
	}
}

func TestConfigTransport_NoSealer(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := asAdmin(t, newIsolationServer(f), f.DB, f.A.ID, storetest.Now).Handler()
	if rec := serveOnce(h, http.MethodPost, "/api/config/export", "{}"); !strings.Contains(rec.Body.String(), "export_unavailable") {
		t.Errorf("export without a KEK %d: %s", rec.Code, rec.Body)
	}
}

// TestConfigTransport_ProdRefusesDevOnly: on a prod server, a bundle
// naming a localhost target is planned with a refusal and cannot be applied.
func TestConfigTransport_ProdRefusesDevOnly(t *testing.T) {
	_, a, b := transportServers(t, "prod")
	if rec := serveOnce(a, http.MethodPost, "/api/connections",
		`{"name":"Lab","connector_type":"demo-ad","system":"lab","config":{"host":"localhost"}}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d: %s", rec.Code, rec.Body)
	}
	bundle, key := exportA(t, a)
	trustA(t, b, key)
	rec := serveOnce(b, http.MethodPost, "/api/config/import/plan", bundle)
	var plan struct {
		Hash     string   `json:"hash"`
		Refusals []string `json:"refusals"`
	}
	decodeJSON(t, rec.Body.String(), &plan)
	if len(plan.Refusals) == 0 || !strings.Contains(plan.Refusals[0], "localhost") {
		t.Fatalf("prod plan %d: %s", rec.Code, rec.Body)
	}
	rec = serveOnce(b, http.MethodPost, "/api/config/import/apply?hash="+plan.Hash, bundle)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "bundle_refused") {
		t.Errorf("prod apply %d: %s", rec.Code, rec.Body)
	}
}
