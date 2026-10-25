package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func limitedEnv(t *testing.T, def ClientRate) (*oauthEnv, machineClient, cliTokens) {
	t.Helper()
	e := newOAuthEnv(t)
	e.srv.clientLimits = newClientLimiter(def)
	m := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, true)
	return e, m, e.machineToken(m, "tenant-a", "tessera:read")
}

// TestClientRateLimit: a machine client spends one token per request from its
// bucket; the answers carry the RateLimit-* fields, the refused request is 429
// with Retry-After, is audited with the client as actor and is counted; the
// bucket refills with time.
func TestClientRateLimit(t *testing.T) {
	e, m, tok := limitedEnv(t, ClientRate{Burst: 3, PerMinute: 60})
	for i, remaining := range []string{"2", "1", "0"} {
		rec := e.call(tok, "GET", "/api/summary", "")
		if rec.Code != 200 {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body)
		}
		h := rec.Header()
		if h.Get("RateLimit-Limit") != "3" || h.Get("RateLimit-Remaining") != remaining || h.Get("RateLimit-Policy") != "60;w=60" {
			t.Errorf("request %d headers: %v", i+1, h)
		}
		if reset, err := strconv.Atoi(h.Get("RateLimit-Reset")); err != nil || reset < 1 || reset > 3 {
			t.Errorf("request %d RateLimit-Reset = %q", i+1, h.Get("RateLimit-Reset"))
		}
	}
	before := len(httpEvents(ledger(t, e.f.DB, e.f.A.ID)))
	counted := rateLimitedTotal.Value()
	rec := e.call(tok, "GET", "/api/summary", "")
	if rec.Code != 429 || body(rec)["error"] != "rate_limited" {
		t.Fatalf("over the limit: %d %s", rec.Code, rec.Body)
	}
	h := rec.Header()
	if h.Get("Retry-After") != "1" || h.Get("RateLimit-Remaining") != "0" || h.Get("RateLimit-Limit") != "3" || h.Get("RateLimit-Reset") != "3" {
		t.Errorf("429 headers: %v", h)
	}
	if strings.Contains(rec.Body.String(), m.id) {
		t.Errorf("the client id is echoed: %s", rec.Body)
	}
	if rateLimitedTotal.Value() != counted+1 {
		t.Errorf("tessera_api_client_rate_limited_total = %v, want %v", rateLimitedTotal.Value(), counted+1)
	}
	evs := httpEvents(ledger(t, e.f.DB, e.f.A.ID))
	if len(evs) != before+1 {
		t.Fatalf("%d http.request events for the refused request, want 1", len(evs)-before)
	}
	var hf httpField
	if err := json.Unmarshal(evs[0].HTTP, &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Status != 429 || evs[0].Outcome != "failure" || evs[0].ActorType != store.ActorAPIClient ||
		evs[0].ClientID == nil || *evs[0].ClientID != m.id {
		t.Errorf("event: status %d outcome %s actor %s client %v", hf.Status, evs[0].Outcome, evs[0].ActorType, evs[0].ClientID)
	}
	// another client has its own bucket
	other := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, true)
	if rec := e.call(e.machineToken(other, "tenant-a", "tessera:read"), "GET", "/api/summary", ""); rec.Code != 200 {
		t.Errorf("another client: %d", rec.Code)
	}
	// one token a second: after a second there is one request again, and no more
	e.clock.Advance(time.Second)
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 200 {
		t.Errorf("after a refill: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 429 {
		t.Errorf("a second request in the same second: %d", rec.Code)
	}
}

// TestClientRateLimit_Override: a client's own row replaces the default, and a
// cleared row brings the default back (after the 30 second cache).
func TestClientRateLimit_Override(t *testing.T) {
	e, m, tok := limitedEnv(t, ClientRate{Burst: 5, PerMinute: 60})
	set := func(burst, per int) {
		t.Helper()
		err := e.f.DB.InTenant(context.Background(), e.f.A.ID, func(tx *store.TenantTx) error {
			return tx.SetAPIClientLimit(m.id, burst, per, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
		e.srv.clientLimits.forget(bucketKey{e.f.A.ID, m.id})
	}
	set(1, 60)
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "1" {
		t.Fatalf("first: %d %v", rec.Code, rec.Header())
	}
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 429 {
		t.Errorf("second with burst 1: %d", rec.Code)
	}
	// a raised limit applies to the existing bucket
	set(4, 60)
	e.clock.Advance(time.Second)
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "4" {
		t.Errorf("after raising: %d %v", rec.Code, rec.Header())
	}
	// cleared: the default (burst 5) after the cache expires
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, func(tx *store.TenantTx) error { return tx.ClearAPIClientLimit(m.id) }); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(clientLimitCacheTTL + time.Second)
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "5" {
		t.Errorf("after clearing: %d %v", rec.Code, rec.Header())
	}
}

// TestClientRateLimit_OffAndUsers: PerMinute 0 turns the limit off, and a
// signed-in user (cookie session) is never limited by it.
func TestClientRateLimit_OffAndUsers(t *testing.T) {
	e, _, tok := limitedEnv(t, ClientRate{Burst: 2, PerMinute: 0})
	for i := 0; i < 5; i++ {
		rec := e.call(tok, "GET", "/api/summary", "")
		if rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "" {
			t.Fatalf("limit off, request %d: %d %v", i+1, rec.Code, rec.Header())
		}
	}
	f := storetest.TwoTenants(t)
	srv := newIsolationServerWith(f, func(c *Config) { c.ClientRate = ClientRate{Burst: 1, PerMinute: 1} })
	h := asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()
	for i := 0; i < 5; i++ {
		if rec := serveOnce(h, "GET", "/api/summary", ""); rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "" {
			t.Fatalf("a user's request %d: %d %v", i+1, rec.Code, rec.Header())
		}
	}
}

func TestClientRate_Defaults(t *testing.T) {
	for _, tc := range []struct{ in, want ClientRate }{
		{ClientRate{}, ClientRate{120, 600}},
		{ClientRate{Burst: 7, PerMinute: 0}, ClientRate{7, 0}},
		{ClientRate{Burst: 7, PerMinute: 9}, ClientRate{7, 9}},
	} {
		if got := tc.in.orDefault(); got != tc.want {
			t.Errorf("%+v.orDefault() = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// TestAdminClientLimitRoutes: the admin routes read, set and clear a client's
// limit, with step-up, tenant scoping, validation and audit events.
func TestAdminClientLimitRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedClient(t, f.DB, f.A.ID, "tsc_client_a", "ETL A")
	seedClient(t, f.DB, f.B.ID, "tsc_client_b", "ETL B")
	srv := newIsolationServerWith(f, func(c *Config) { c.ClientRate = ClientRate{Burst: 50, PerMinute: 300} })
	h := srv.Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	path := "/api/admin/api-clients/tsc_client_b/rate-limit"
	do := func(l authtest.Login, method, p, b string) (*httptest.ResponseRecorder, map[string]any) {
		rec := reqDo(h, l, method, p, b)
		return rec, body(rec)
	}

	if rec, b := do(admin, "GET", path, ""); rec.Code != 200 || b["source"] != "default" || b["burst"] != 50.0 || b["per_minute"] != 300.0 {
		t.Fatalf("default: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(viewer, "GET", path, ""); rec.Code != 403 {
		t.Errorf("viewer reads: %d", rec.Code)
	}
	if rec, _ := do(viewer, "PUT", path, `{"burst":5,"per_minute":5}`); rec.Code != 403 {
		t.Errorf("viewer sets: %d", rec.Code)
	}
	if rec, _ := do(stale, "PUT", path, `{"burst":5,"per_minute":5}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	for name, b := range map[string]string{"burst 0": `{"burst":0,"per_minute":5}`, "per_minute 0": `{"burst":5,"per_minute":0}`,
		"burst too big": `{"burst":100001,"per_minute":5}`, "per_minute too big": `{"burst":5,"per_minute":600001}`,
		"unknown field": `{"burst":5,"per_minute":5,"x":1}`, "not json": `nope`, "strings": `{"burst":"5","per_minute":5}`, "empty": ``} {
		if rec, _ := do(admin, "PUT", path, b); rec.Code != 422 || strings.Contains(rec.Body.String(), "nope") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec, b := do(admin, "PUT", path, `{"burst":5,"per_minute":30}`); rec.Code != 200 || b["source"] != "client" || b["burst"] != 5.0 || b["per_minute"] != 30.0 {
		t.Fatalf("set: %d %s", rec.Code, rec.Body)
	}
	if rec, b := do(admin, "GET", path, ""); rec.Code != 200 || b["source"] != "client" || b["per_minute"] != 30.0 {
		t.Errorf("read back: %d %s", rec.Code, rec.Body)
	}
	// tenant A's client is not found from B, and B's limit never shows in A
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if rec, _ := do(admin, m, "/api/admin/api-clients/tsc_client_a/rate-limit", `{"burst":5,"per_minute":5}`); rec.Code != 404 {
			t.Errorf("%s A's client from B: %d", m, rec.Code)
		}
	}
	if rec, b := do(admin, "DELETE", path, ""); rec.Code != 200 || b["source"] != "default" {
		t.Errorf("clear: %d %s", rec.Code, rec.Body)
	}
	var kinds []string
	for _, ev := range ledger(t, f.DB, f.B.ID) {
		if strings.HasPrefix(ev.Action, "oauth.client.rate_limit.") {
			kinds = append(kinds, ev.Action)
		}
	}
	if fmt.Sprint(kinds) != "[oauth.client.rate_limit.cleared oauth.client.rate_limit.set]" {
		t.Errorf("audit events (newest first) = %v", kinds)
	}
}

// TestClientRateLimit_NotChargedAsAnonymous: an authenticated machine client is
// limited by its own bucket only. Its requests carry no session cookie but do
// not spend the IP's anonymous bucket, so a client allowed more than that
// bucket gets its full limit and the people signed in from the same address
// are not refused because of it; made-up tokens still drain the bucket
// (issue #608).
func TestClientRateLimit_NotChargedAsAnonymous(t *testing.T) {
	e, _, tok := limitedEnv(t, ClientRate{Burst: 10, PerMinute: 60})
	big := RateLimit{Every: time.Nanosecond, Burst: 1 << 20}
	e.srv.limits = newLimiters(RateLimits{Anonymous: RateLimit{Every: time.Hour, Burst: 3}, Auth: big, OAuth: big})
	const ip = "198.51.100.20:1000"
	from := func(r *http.Request) { r.RemoteAddr = ip }
	for i := 0; i < 10; i++ {
		rec := e.call(tok, "GET", "/api/summary", "", from)
		if rec.Code != 200 || rec.Header().Get("RateLimit-Limit") != "10" {
			t.Fatalf("client request %d: %d %v %s", i+1, rec.Code, rec.Header(), rec.Body)
		}
	}
	// the 11th is the client's own refusal, with its RateLimit-* fields
	rec := e.call(tok, "GET", "/api/summary", "", from)
	if rec.Code != 429 || rec.Header().Get("RateLimit-Policy") != "60;w=60" {
		t.Fatalf("over the client's limit: %d %v", rec.Code, rec.Header())
	}
	// the address's anonymous budget is untouched: three made-up tokens are
	// answered 401 and spend it, the fourth is refused before authentication
	for i := 0; i < 4; i++ {
		r := httptest.NewRequest("GET", "/api/summary", nil)
		r.RemoteAddr = ip
		r.Header.Set("Authorization", "Bearer made-up-"+strconv.Itoa(i))
		if code := serve(e.h, r).Code; (i < 3 && code != 401) || (i == 3 && code != 429) {
			t.Errorf("made-up token %d: %d", i, code)
		}
	}
}
