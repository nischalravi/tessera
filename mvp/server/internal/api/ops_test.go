package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func platformHead(t *testing.T, e *adminEnv) int64 {
	t.Helper()
	var seq int64
	if err := e.f.DB.ReadTenant(context.Background(), tenancy.Platform, func(tx *store.TenantTx) error {
		h, err := tx.AuditHead()
		seq = h.LastSeq
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return seq
}

// The probes are answered ahead of the audit middleware: polling them never
// writes to the ledger, while every /api/* request (and an unknown route, and
// /metrics on this listener) still does.
func TestProbes_NotAudited_APIStillAudited(t *testing.T) {
	e := newAdminEnv(t)
	before := platformHead(t, e)
	for i := 0; i < 20; i++ {
		for _, p := range []string{"/livez", "/readyz"} {
			rec := serve(e.h, httptest.NewRequest(http.MethodGet, p, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
			}
		}
	}
	if platformHead(t, e) != before {
		t.Fatal("probes wrote to the audit ledger")
	}
	// /api/* is audited, anonymous requests land on the _platform chain
	serve(e.h, httptest.NewRequest(http.MethodGet, "/api/summary", nil))
	if platformHead(t, e) != before+1 {
		t.Error("GET /api/summary was not audited")
	}
	// /metrics is not on the API listener: an ordinary, audited, unknown route
	rec := serve(e.h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "tessera_http_requests_total") {
		t.Errorf("/metrics served on the public listener: %d", rec.Code)
	}
	if platformHead(t, e) != before+2 {
		t.Error("GET /metrics on the API listener was not audited")
	}
	// only GET/HEAD are probes: a POST to /livez is an audited unknown route
	serve(e.h, httptest.NewRequest(http.MethodPost, "/livez", nil))
	if platformHead(t, e) != before+3 {
		t.Error("POST /livez was not audited")
	}
}

func TestProbes_Shape(t *testing.T) {
	e := newAdminEnv(t)
	rec := serve(e.h, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if rec.Body.String() != `{"status":"ok"}` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("livez: %q %v", rec.Body, rec.Header())
	}
	rec = serve(e.h, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Body.String() != `{"status":"ok","checks":{"audit_chain":"ok","database":"ok","draining":"ok","kek":"ok","loops":"ok","schema":"ok"}}` {
		t.Errorf("readyz: %q", rec.Body)
	}
	if rec = serve(e.h, httptest.NewRequest(http.MethodHead, "/readyz", nil)); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD readyz: %d %q", rec.Code, rec.Body)
	}
	// a failing dependency: 503, same keys
	e2 := newAdminEnv(t)
	e2.srv.cfg.Health.Sealer = nil
	rec = serve(e2.h, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var v struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusServiceUnavailable ||
		v.Status != "unavailable" || v.Checks["kek"] != "fail" || len(v.Checks) != 6 {
		t.Errorf("readyz without KEK: %d %s", rec.Code, rec.Body)
	}
}

// Requests are recorded under the route pattern, never the raw path.
func TestMetrics_HTTPRouteLabelsAreBounded(t *testing.T) {
	e := newAdminEnv(t)
	admin := e.login(t, e.f.B, "ada@b.example", 0, auth.RoleTenantAdmin)
	for i := 0; i < 5; i++ {
		e.call(admin, "GET", "/api/admin/change-requests/00000000-0000-4000-8000-00000000000"+string(rune('0'+i)), "")
		serve(e.h, httptest.NewRequest(http.MethodGet, "/nope/"+strings.Repeat("x", i+1), nil))
	}
	seen := false
	obs.HTTPRequests.Each(func(l []string, _ float64) {
		if strings.Contains(l[0], "00000000-0000") || strings.Contains(l[0], "/nope/") {
			t.Errorf("raw path in route label: %q", l[0])
		}
		if l[0] == "GET /api/admin/change-requests/{change_id}" {
			seen = true
		}
	})
	if !seen {
		t.Error("no series under the route pattern")
	}
}

// GET /api/admin/platform-health: admin.read only, no secrets.
func TestPlatformHealth_RBAC(t *testing.T) {
	e := newAdminEnv(t)
	b := e.f.B
	admin := e.login(t, b, "ada@b.example", 0, auth.RoleTenantAdmin)
	auditor := e.login(t, b, "aud@b.example", 0, auth.RoleAuditor)
	viewer := e.login(t, b, "vic@b.example", 0, auth.RoleViewer)
	e.mustCall(t, viewer, "GET", "/api/admin/platform-health", "", http.StatusForbidden)
	if rec := serve(e.h, httptest.NewRequest(http.MethodGet, "/api/admin/platform-health", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
	for _, l := range []auth.Role{auth.RoleTenantAdmin, auth.RoleAuditor} {
		who := admin
		if l == auth.RoleAuditor {
			who = auditor
		}
		v := e.mustCall(t, who, "GET", "/api/admin/platform-health", "", http.StatusOK)
		for _, k := range []string{"status", "checks", "loops", "http", "audit", "database", "logins", "connectors", "max_loop_lag_seconds"} {
			if _, ok := v[k]; !ok {
				t.Errorf("%s: missing %q in %v", l, k, v)
			}
		}
	}
	_, _, raw := e.call(admin, "GET", "/api/admin/platform-health", "")
	for _, bad := range []string{"password", "secret", "kek\":", "hunter"} {
		if strings.Contains(strings.ToLower(raw), bad) {
			t.Errorf("response mentions %q", bad)
		}
	}
	// a write method is not routed
	e.mustCall(t, admin, "POST", "/api/admin/platform-health", `{}`, http.StatusMethodNotAllowed)
}

func TestLoginMethodLabels(t *testing.T) {
	for route, want := range map[string]string{
		"GET /api/auth/oidc/{connection_id}/callback":   "oidc",
		"POST /api/auth/saml/{connection_id}/acs":       "saml",
		"GET /api/auth/oauth2/{connection_id}/callback": "oauth2",
		"GET /api/auth/login":                           "other",
		"GET /t/{slug}/bootstrap":                       "other",
		obs.Unmatched:                                   "other",
	} {
		if got := loginMethodOfRoute(route); got != want {
			t.Errorf("loginMethodOfRoute(%q) = %s, want %s", route, got, want)
		}
	}
	if loginMethodOfProtocol("saml") != "saml" || loginMethodOfProtocol("dev_mock'; drop") != "other" {
		t.Error("protocol label not a closed set")
	}
}

func TestRunQueue_ReportsEverySweepAsALoop(t *testing.T) {
	e := newAdminEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.RunQueue(ctx); close(done) }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ran := 0
		for _, l := range obs.DefaultLoops.Snapshot() {
			if l.Runs > 0 && slices.Contains(SweeperLoops, l.Name) {
				ran++
			}
		}
		if ran == len(SweeperLoops) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d sweeper loops reported a run", ran, len(SweeperLoops))
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}
