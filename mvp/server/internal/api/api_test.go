package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// testServer is a server over st, signed in as testAdmin in st's tenant.
func testServer(t testing.TB, st *testkit.DB, mutate ...func(*Config)) http.Handler {
	t.Helper()
	cfg := Config{
		Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Connectors:     func(time.Time) ([]connectors.Connector, error) { return connectors.Load("demo", testkit.Now) },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return asAdmin(t, New(cfg), st.DB, st.Tenant, testkit.Now).Handler()
}

type client struct {
	t *testing.T
	h http.Handler
}

func (c client) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func (c client) json(method, path, body string, want int) any {
	c.t.Helper()
	rec := c.do(method, path, body)
	if rec.Code != want {
		c.t.Fatalf("%s %s: status %d, want %d: %.300s", method, path, rec.Code, want, rec.Body.String())
	}
	var v any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	return v
}

// at walks a decoded JSON value: at(v, "summary", "permissions_removed"), at(v, 0, "id").
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func TestRevokeDryRunAndApplyViaAPI(t *testing.T) {
	t.Parallel()
	st, ids := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	e := testkit.Get(t, st, func(c *store.TenantTx) (*store.GrantEdge, error) {
		return c.EdgeBetween(graph.Key("account", ids["acct:okta:carol"]), graph.Key("group", ids["group:okta:platform"]))
	})
	dry := c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id": %d, "dry_run": true}`, e.ID), 200)
	if at(dry, "summary", "permissions_removed") != 1.0 || at(dry, "summary", "violations_resolved") != 1.0 {
		t.Errorf("summary = %v", at(dry, "summary"))
	}
	if d := at(dry, "identities", 0, "removed", 0, "usage", "days_since_used"); d != 75.0 {
		t.Errorf("days_since_used = %v", d)
	}
	if _, ok := dry.(map[string]any)["applied"]; ok {
		t.Error("a dry run must not report applied")
	}
	carol := fmt.Sprintf("/api/identities/%d", ids["carol"])
	if p := at(c.json("GET", carol, "", 200), "risk", "privileged"); p != 1.0 {
		t.Errorf("privileged before = %v", p)
	}
	applied := c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id": %d, "dry_run": false}`, e.ID), 200)
	if at(applied, "applied") != true {
		t.Errorf("applied = %v", at(applied, "applied"))
	}
	if p := at(c.json("GET", carol, "", 200), "risk", "privileged"); p != 0.0 {
		t.Errorf("privileged after = %v", p)
	}
	if a := at(c.json("GET", "/api/audit", "", 200), 0, "action"); a != "grant.revoke" {
		t.Errorf("latest audit action = %v", a)
	}
	c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id": %d}`, e.ID), 404)
}

func TestAPISmoke(t *testing.T) {
	t.Parallel() // its own database
	c := client{t, testServer(t, testkit.Demo(t))}
	summary := c.json("GET", "/api/summary", "", 200)
	if at(summary, "identities", "ai_agent") != 6.0 || at(summary, "violations", "total").(float64) <= 0 {
		t.Errorf("summary = %v", summary)
	}
	idents := c.json("GET", "/api/identities", "", 200).([]any)
	if len(idents) < 90 {
		t.Errorf("identities = %d", len(idents))
	}
	var aliceID float64
	for _, i := range idents {
		if at(i, "name") == "Alice Okafor" {
			aliceID = at(i, "id").(float64)
		}
	}
	detail := c.json("GET", fmt.Sprintf("/api/identities/%d", int(aliceID)), "", 200)
	found := false
	for _, p := range at(detail, "effective_permissions").([]any) {
		found = found || at(p, "resource") == "s3://customer-pii"
	}
	if !found {
		t.Error("alice should reach s3://customer-pii")
	}
	g := c.json("GET", fmt.Sprintf("/api/graph?identity_id=%d", int(aliceID)), "", 200)
	kinds := map[any]bool{}
	for _, n := range at(g, "nodes").([]any) {
		kinds[at(n, "kind")] = true
	}
	for _, k := range []string{"identity", "account", "group", "perm", "resource"} {
		if !kinds[k] {
			t.Errorf("graph lacks %s nodes", k)
		}
	}
	// An unknown identity or resource is a 404, not a 500 (UAT #306).
	c.json("GET", "/api/graph?identity_id=99999999", "", 404)
	c.json("GET", "/api/graph?resource_id=99999999", "", 404)
	orphan := false
	for _, n := range c.json("GET", "/api/nhi", "", 200).([]any) {
		for _, f := range at(n, "flags").([]any) {
			orphan = orphan || f == "orphaned"
		}
		if at(n, "type") == "ai_agent" && len(at(n, "delegations").([]any)) == 0 {
			t.Errorf("agent %v has no delegations", at(n, "name"))
		}
	}
	if !orphan {
		t.Error("expected an orphaned NHI")
	}
	for _, path := range []string{"/api/policies", "/api/violations", "/api/jit/requests", "/api/reviews/campaigns",
		"/api/hris/events", "/api/resources", "/api/connectors", "/api/least-privilege/recommendations"} {
		t.Run(path, func(t *testing.T) {
			if v := c.json("GET", path, "", 200).([]any); len(v) == 0 {
				t.Error("empty response")
			}
		})
	}
	camp := at(c.json("GET", "/api/reviews/campaigns", "", 200), 0)
	if items, total := at(camp, "items").(float64), at(camp, "total_grants").(float64); !(items > 0 && items < total) {
		t.Errorf("campaign is not exception-only: %v of %v", items, total)
	}
}

func TestAccountsList(t *testing.T) {
	t.Parallel()
	c := client{t, testServer(t, testkit.Demo(t))}
	rows := c.json("GET", "/api/accounts", "", 200).([]any)
	if float64(len(rows)) != at(c.json("GET", "/api/summary", "", 200), "accounts") {
		t.Errorf("accounts list length %d does not match summary", len(rows))
	}
	for _, k := range []string{"id", "system", "username", "kind", "status", "last_login_at", "identity"} {
		if _, ok := rows[0].(map[string]any)[k]; !ok {
			t.Errorf("row lacks %s", k)
		}
	}
	found := false
	for _, r := range rows {
		if id, ok := at(r, "identity").(map[string]any); ok && id["name"] == "Alice Okafor" && at(r, "system") == "okta" {
			found = at(r, "status") == "active"
		}
	}
	if !found {
		t.Error("alice's active okta account missing")
	}
	aws := c.json("GET", "/api/accounts?system=aws", "", 200).([]any)
	if len(aws) == 0 {
		t.Fatal("no aws accounts")
	}
	for _, r := range aws {
		if at(r, "system") != "aws" {
			t.Errorf("system filter leaked %v", at(r, "system"))
		}
	}
}

func TestRoutingAndErrors(t *testing.T) {
	t.Parallel()
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	tests := []struct {
		method, path, body string
		status             int
		detail             string
	}{
		{"GET", "/api/nope", "", 404, `"Not Found"`},
		{"POST", "/api/summary", "", 405, `"Method Not Allowed"`},
		{"GET", "/api/jit/requests/1/approve", "", 405, `"Method Not Allowed"`},
		{"GET", "/api/identities/9999", "", 404, `"identity not found"`},
		{"GET", "/api/graph", "", 400, `"identity_id or resource_id is required"`},
		{"POST", "/api/simulate", `{"remove_edge_ids": [], "dryrun": true}`, 422, `"extra_forbidden"`},
		{"POST", "/api/simulate", `{"a": 1} trailing`, 422, `"json_invalid"`},
		// the decision routes are /approve, /deny and /revoke (§16.2); there is no {action}
		{"POST", "/api/jit/requests/1/escalate", "", 404, `"Not Found"`},
		{"POST", "/api/jit/requests/1/approve", `{"approver": "mallory@larkspur.example"}`, 422, `"extra_forbidden"`},
		{"POST", "/api/least-privilege/revoke", `{"edge_id": 1, "actor": "mallory"}`, 422, `"extra_forbidden"`},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := c.do(tc.method, tc.path, tc.body)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.detail) {
				t.Errorf("got %d %s, want %d containing %s", rec.Code, rec.Body.String(), tc.status, tc.detail)
			}
		})
	}
	if rec := c.do("POST", "/api/summary", ""); rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("Allow = %q", rec.Header().Get("Allow"))
	}
	if rec := c.do("HEAD", "/api/health", ""); rec.Code != 200 {
		t.Errorf("HEAD = %d", rec.Code)
	}
	if rec := c.do("GET", "/api/health/", ""); rec.Code != 307 || rec.Header().Get("Location") != "/api/health" {
		t.Errorf("trailing slash: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestBodySizeLimit(t *testing.T) {
	t.Parallel()
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st, func(cfg *Config) { cfg.MaxBodyBytes = 64 })}
	big := `{"remove_edge_ids": [` + strings.Repeat("1,", 100) + `1]}`
	if rec := c.do("POST", "/api/simulate", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	// unknown length (chunked) bodies are cut off by MaxBytesReader
	req := httptest.NewRequest("POST", "/api/simulate", io.MultiReader(strings.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked status = %d, want 413", rec.Code)
	}
	if rec := c.do("POST", "/api/simulate", `{}`); rec.Code != 200 {
		t.Errorf("small body = %d", rec.Code)
	}
}

func TestCORS(t *testing.T) {
	t.Parallel()
	st, _ := testkit.Tiny(t)
	c := client{t, testServer(t, st)}
	tests := []struct {
		name, method, origin string
		wantAllow            string
		wantStatus           int
	}{
		{"allowed origin", "GET", "http://localhost:5173", "http://localhost:5173", 200},
		{"other origin gets no header", "GET", "https://evil.example", "", 200},
		{"allowed preflight", "OPTIONS", "http://localhost:5173", "http://localhost:5173", 200},
		{"rejected preflight", "OPTIONS", "https://evil.example", "", 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := c.do(tc.method, "/api/health", "", "Origin", tc.origin, "Access-Control-Request-Method", "POST")
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantAllow {
				t.Errorf("allow-origin = %q, want %q", got, tc.wantAllow)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestHandlerTimeout(t *testing.T) {
	st, _ := testkit.Tiny(t)
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HandlerTimeout: 20 * time.Millisecond})
	srv.handle("GET", "/api/slow", read, need(auth.PermGraphRead), func(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
		return nil, r.Context().Err()
	})
	rec := httptest.NewRecorder()
	asAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/slow", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestInternalErrorsAreNotLeaked(t *testing.T) {
	t.Parallel()
	st, _ := testkit.Tiny(t)
	var logs strings.Builder
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	srv.handle("GET", "/api/boom", read, need(auth.PermGraphRead), func(http.ResponseWriter, *http.Request, *params) (any, error) {
		return nil, fmt.Errorf("SELECT secret FROM vault failed")
	})
	srv.handle("GET", "/api/panic", read, need(auth.PermGraphRead), func(http.ResponseWriter, *http.Request, *params) (any, error) { panic("kaboom") })
	h := asAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler()
	for _, path := range []string{"/api/boom", "/api/panic"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path+"?token=abc123", nil))
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "vault") || strings.Contains(rec.Body.String(), "kaboom") {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
	}
	if strings.Contains(logs.String(), "abc123") {
		t.Error("query strings must not be logged")
	}
}
