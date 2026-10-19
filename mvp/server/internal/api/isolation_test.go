package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// API tenant isolation tests (design §14.4). The server is bound to tenant B
// of storetest.TwoTenants; tenant A carries storetest.Sentinel in every name,
// email, tag and payload. Until authentication lands (PR5) "signed in as B"
// means Config.Tenant = B.

// missingID is an id no fixture row has.
const missingID = 987654321

// isolationServer is a server over the two-tenant fixture, signed in as
// testAdmin in tenant.
func isolationServer(t testing.TB, f *storetest.Fixture, tenant tenancy.ID) testSrv {
	t.Helper()
	return asAdmin(t, newIsolationServer(f), f.DB, tenant, storetest.Now)
}

func newIsolationServer(f *storetest.Fixture) *Server {
	kek, err := seal.New(storetest.IdentityKEK)
	if err != nil {
		panic(err)
	}
	return New(Config{
		Identifiers: identifiers.NewKeyer(kek),
		Store:       f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
		Env:            "test",
		RateLimits:     noRateLimits, // the coverage tests send hundreds of anonymous requests
	})
}

func serveOnce(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func leaks(body string) bool {
	return strings.Contains(strings.ToLower(body), strings.ToLower(storetest.Sentinel))
}

// crossTenantCase is one call that names one of tenant A's rows by id. The
// same call with an id that exists nowhere is the baseline: from tenant B,
// A's id must be indistinguishable from a missing one.
type crossTenantCase struct {
	method string
	path   func(id int64) string
	body   func(id int64) string
	key    string // fixture key of tenant A's row
}

func fixed(path string) func(int64) string { return func(int64) string { return path } }

func pathf(format string) func(int64) string {
	return func(id int64) string { return fmt.Sprintf(format, id) }
}

// crossTenantCases cover every route with a path parameter (enforced by
// TestIsolation_RouteCrossTenant) and every request body field holding an id.
var crossTenantCases = map[string]crossTenantCase{
	"GET identity":         {method: "GET", path: pathf("/api/identities/%d"), key: "alice"},
	"GET identity (nhi)":   {method: "GET", path: pathf("/api/identities/%d"), key: "svc-etl"},
	"GET leaver plan":      {method: "GET", path: pathf("/api/jml/leaver-plan/%d"), key: "alice"},
	"GET campaign":         {method: "GET", path: pathf("/api/reviews/campaigns/%d"), key: "campaign"},
	"GET hris plan":        {method: "GET", path: pathf("/api/hris/events/%d/plan"), key: "hris:leaver"},
	"POST hris execute":    {method: "POST", path: pathf("/api/hris/events/%d/execute"), key: "hris:leaver"},
	"POST review decision": {method: "POST", path: pathf("/api/reviews/items/%d/decision"), key: "item", body: func(int64) string { return `{"decision":"revoke"}` }},
	"POST jit approve":     {method: "POST", path: pathf("/api/jit/requests/%d/approve"), key: "request:pending", body: func(int64) string { return `{}` }},
	"POST jit deny":        {method: "POST", path: pathf("/api/jit/requests/%d/deny"), key: "request:pending", body: func(int64) string { return `{}` }},
	"POST jit revoke":      {method: "POST", path: pathf("/api/jit/requests/%d/revoke"), key: "request:approved", body: func(int64) string { return `{}` }},
	"POST revoke edge (dry run)": {method: "POST", path: fixed("/api/least-privilege/revoke"), key: "edge:0",
		body: func(id int64) string { return fmt.Sprintf(`{"edge_id":%d}`, id) }},
	"POST revoke edge": {method: "POST", path: fixed("/api/least-privilege/revoke"), key: "edge:0",
		body: func(id int64) string { return fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, id) }},
	"POST jit request identity": {method: "POST", path: fixed("/api/jit/requests"), key: "alice",
		body: func(id int64) string {
			return fmt.Sprintf(`{"identity_id":%d,"group_id":%d,"justification":"x"}`, id, id)
		}},
	"POST simulate remove edge": {method: "POST", path: fixed("/api/simulate"), key: "edge:0",
		body: func(id int64) string { return fmt.Sprintf(`{"remove_edge_ids":[%d]}`, id) }},
	"GET graph by identity": {method: "GET", path: pathf("/api/graph?identity_id=%d"), key: "alice"},
	"GET graph by resource": {method: "GET", path: pathf("/api/graph?resource_id=%d"), key: "resource:aws:prod"},
	"POST simulate disable account": {method: "POST", path: fixed("/api/simulate"), key: "acct:aws:svc-etl",
		body: func(id int64) string { return fmt.Sprintf(`{"disable_account_ids":[%d]}`, id) }},
	"PUT group ownership": {method: "PUT", path: pathf("/api/ownership/group/%d"), key: "group:okta:payments-approvers",
		body: func(int64) string { return `{}` }},
	"PUT identity ownership": {method: "PUT", path: pathf("/api/ownership/identity/%d"), key: "svc-etl",
		body: func(int64) string { return `{}` }},
	"POST bulk ownership": {method: "POST", path: fixed("/api/ownership/bulk"), key: "svc-etl",
		body: func(id int64) string { return fmt.Sprintf(`{"objects":[{"kind":"identity","key":"%d"}]}`, id) }},
	"PUT catalog item": {method: "PUT", path: pathf("/api/catalog/items/%d"), key: "group:okta:platform",
		body: func(int64) string { return `{"requestable":true,"risk":"low"}` }},
	"GET lifecycle": {method: "GET", path: pathf("/api/identities/%d/lifecycle"), key: "alice"},
	"PUT lifecycle": {method: "PUT", path: pathf("/api/identities/%d/lifecycle"), key: "alice",
		body: func(int64) string { return `{"worker_type":"employee","reason":"x"}` }},
	"POST lifecycle extend": {method: "POST", path: pathf("/api/identities/%d/lifecycle/extend"), key: "alice",
		body: func(int64) string { return `{"ends_at":"2030-01-01T00:00:00Z","reason":"x"}` }},
	"POST link account": {method: "POST", path: pathf("/api/accounts/%d/link"), key: "acct:okta:alice",
		body: func(id int64) string { return fmt.Sprintf(`{"identity_id":%d,"reason":"x"}`, id) }},
	"POST account not person": {method: "POST", path: pathf("/api/accounts/%d/not-person"), key: "acct:okta:alice",
		body: func(int64) string { return `{"reason":"x"}` }},
	"DELETE account link": {method: "DELETE", path: pathf("/api/accounts/%d/link"), key: "acct:okta:alice"},
	"POST merge identity": {method: "POST", path: pathf("/api/identities/%d/merge"), key: "alice",
		body: func(id int64) string { return fmt.Sprintf(`{"into":%d,"reason":"x"}`, id) }},
	"GET identity affiliations": {method: "GET", path: pathf("/api/identities/%d/affiliations"), key: "alice"},
	"GET identity identifiers":  {method: "GET", path: pathf("/api/identities/%d/identifiers"), key: "alice"},
	// a bundle names catalog groups by id: tenant A's group is not in B's catalog, like a missing one
	"POST invite bundle": {method: "POST", path: fixed("/api/guests/invitations"), key: "group:aws:ProdAdmin",
		body: func(id int64) string {
			return fmt.Sprintf(`{"given_name":"G","email":"g@x.example","population":"visitor","purpose":"x","ends_at":"2026-10-12T00:00:00Z","bundle":[%d]}`, id)
		}},
	"POST add affiliation": {method: "POST", path: pathf("/api/identities/%d/affiliations"), key: "alice",
		body: func(int64) string { return `{"type":"alum","reason":"x"}` }},
	"GET identity containment": {method: "GET", path: pathf("/api/identities/%d/containment"), key: "alice"},
	"POST contain identity": {method: "POST", path: pathf("/api/identities/%d/contain"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
	"GET identity disables": {method: "GET", path: pathf("/api/identities/%d/disables"), key: "alice"},
	"POST disable identity": {method: "POST", path: pathf("/api/identities/%d/disable"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
	"POST enable identity": {method: "POST", path: pathf("/api/identities/%d/enable"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
}

// routeParamKey maps each route with path parameters to the cases above.
var routeParamCases = map[string][]string{
	"GET /api/identities/{identity_id}":                   {"GET identity", "GET identity (nhi)"},
	"GET /api/jml/leaver-plan/{identity_id}":              {"GET leaver plan"},
	"GET /api/reviews/campaigns/{campaign_id}":            {"GET campaign"},
	"GET /api/hris/events/{event_id}/plan":                {"GET hris plan"},
	"POST /api/hris/events/{event_id}/execute":            {"POST hris execute"},
	"POST /api/reviews/items/{item_id}/decision":          {"POST review decision"},
	"POST /api/jit/requests/{request_id}/approve":         {"POST jit approve"},
	"POST /api/jit/requests/{request_id}/deny":            {"POST jit deny"},
	"POST /api/jit/requests/{request_id}/revoke":          {"POST jit revoke"},
	"PUT /api/catalog/items/{group_id}":                   {"PUT catalog item"},
	"GET /api/identities/{identity_id}/lifecycle":         {"GET lifecycle"},
	"PUT /api/identities/{identity_id}/lifecycle":         {"PUT lifecycle"},
	"POST /api/identities/{identity_id}/lifecycle/extend": {"POST lifecycle extend"},
	"POST /api/accounts/{account_id}/link":                {"POST link account"},
	"POST /api/accounts/{account_id}/not-person":          {"POST account not person"},
	"DELETE /api/accounts/{account_id}/link":              {"DELETE account link"},
	"POST /api/identities/{identity_id}/merge":            {"POST merge identity"},
	"GET /api/identities/{identity_id}/affiliations":      {"GET identity affiliations"},
	"GET /api/identities/{identity_id}/identifiers":       {"GET identity identifiers"},
	"POST /api/identities/{identity_id}/affiliations":     {"POST add affiliation"},
	"PUT /api/ownership/{kind}/{object_key}":              {"PUT group ownership", "PUT identity ownership"},
	"POST /api/identities/{identity_id}/contain":          {"POST contain identity"},
	"GET /api/identities/{identity_id}/containment":       {"GET identity containment"},
	"GET /api/identities/{identity_id}/disables":          {"GET identity disables"},
	"POST /api/identities/{identity_id}/disable":          {"POST disable identity"},
	"POST /api/identities/{identity_id}/enable":           {"POST enable identity"},
}

// TestIsolation_RouteCrossTenant: as tenant B, every route with a path
// parameter (and every body field holding an id) given tenant A's id answers
// exactly as for an id that does not exist: the same status and body, never
// 200 or 403, never A's data, and tenant A is left untouched.
//
// The original API contract, which the parity fixtures pin, answers a missing
// id with 404 on GET routes and with 400 on some POST routes (for example
// "request is not pending"); the design's "404" is therefore checked as
// "indistinguishable from missing".
func TestIsolation_RouteCrossTenant(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := isolationServer(t, f, f.B.ID)
	h := srv.Handler()

	for _, rt := range srv.Routes() {
		if !strings.Contains(rt.Pattern, "{") {
			continue
		}
		if _, ok := readinessRouteCases[rt.Method+" "+rt.Pattern]; ok {
			continue // TestIsolation_ReadinessRouteCrossTenant
		}
		if rt.Pattern == "/api/audit/events/{event_id}/proof" {
			continue // TestIsolation_AuditRoutes
		}
		if strings.HasPrefix(rt.Pattern, "/api/reviews/schedules/{schedule_id}") {
			continue // TestReviewSchedulesAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/jobs/{job_id}") {
			continue // TestIsolation_JobRoutes (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/provisioning/") {
			continue // TestIsolation_ProvisioningRoutes (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/config/trusted-signers/{kid}" {
			continue // TestIsolation_TrustedSignerScoped (a key id, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/approvals/delegations/{delegation_id}") {
			continue // TestApprovalsAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/removal-requests/{request_id}") {
			continue // TestRemovalAPI_StepUpAndCrossTenant (a UUID, not a fixture id)
		}
		if rt.Pattern == "/api/orgs/{org_id}" {
			continue // TestOrgsAPI (ids are derived from department names, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/request-drafts/{draft_id}") {
			continue // TestRequestDraftsAPI (a UUID, private to its user)
		}
		if strings.HasPrefix(rt.Pattern, "/api/requests/{request_id}") {
			continue // TestRequestsAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/roles/{role_id}") || strings.HasPrefix(rt.Pattern, "/api/role-requests/{request_id}") {
			continue // TestRolesAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/abac/policies/{policy_id}") || rt.Pattern == "/api/catalog/items/{group_id}/policy" {
			continue // TestAbacAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/auth/oidc/{connection_id}/callback" || rt.Pattern == "/api/auth/oauth2/{connection_id}/callback" ||
			rt.Pattern == "/api/auth/cas/{connection_id}/callback" || rt.Pattern == "/api/auth/wsfed/{connection_id}/callback" ||
			rt.Pattern == "/t/{slug}/bootstrap" {
			continue // TestIsolation_LoginCrossTenant (public; the tenant comes from the cookie or the slug)
		}
		if strings.HasPrefix(rt.Pattern, "/api/auth/saml/{connection_id}/") {
			continue // TestIsolation_SAMLCrossTenant (public; the tenant comes from the cookie or the connection)
		}
		if rt.Pattern == "/api/identity-merges/{merge_id}/unmerge" {
			continue // TestCorrelationAPI_CrossTenant (a UUID, not a fixture id)
		}
		if rt.Pattern == "/api/affiliations/{affiliation_id}/end" {
			continue // TestAffiliationsAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/sponsorships/{sponsorship_id}") {
			continue // TestSponsorshipsAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/email/messages/{message_id}") {
			continue // TestEmailAPI_CrossTenant (a UUID, not a fixture id)
		}
		if rt.Pattern == "/api/containment-retries/{retry_id}/retry-now" {
			continue // TestContainmentRetriesAPI (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/groups/") {
			continue // TestGroupsTenantIsolation (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/auth/sessions/{session_id}" {
			continue // TestIsolation_SessionCookieScoped (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/siem/sinks/") {
			continue // TestSiemAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/alerts/") {
			continue // TestAlertsAPI_CrossTenant (UUIDs and rule names, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/admin/") {
			continue // TestAdminAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if _, ok := routeParamCases[rt.Method+" "+rt.Pattern]; !ok {
			t.Errorf("route %s %s has path parameters but no cross-tenant case", rt.Method, rt.Pattern)
		}
	}

	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	for name, tc := range crossTenantCases {
		t.Run(name, func(t *testing.T) {
			aID, ok := f.A.IDs[tc.key]
			if !ok || aID == 0 {
				t.Fatalf("fixture has no tenant A row %q", tc.key)
			}
			body := func(id int64) string {
				if tc.body == nil {
					return ""
				}
				return tc.body(id)
			}
			cross := serveOnce(h, tc.method, tc.path(aID), body(aID))
			missing := serveOnce(h, tc.method, tc.path(missingID), body(missingID))
			if cross.Code == http.StatusOK && tc.path(0) != "/api/simulate" {
				t.Errorf("tenant A's id answered 200: %.300s", cross.Body.String())
			}
			if cross.Code == http.StatusForbidden {
				t.Error("tenant A's id answered 403, which reveals it exists")
			}
			if leaks(cross.Body.String()) {
				t.Errorf("response leaks tenant A data: %.300s", cross.Body.String())
			}
			// Simulate echoes the requested ids; otherwise the two responses
			// must be byte-identical.
			norm := func(s string, id int64) string { return strings.ReplaceAll(s, fmt.Sprint(id), "<id>") }
			if cross.Code != missing.Code || norm(cross.Body.String(), aID) != norm(missing.Body.String(), missingID) {
				t.Errorf("tenant A's id is distinguishable from a missing one:\n A: %d %.300s\n missing: %d %.300s",
					cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
			}
		})
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("calls made as tenant B changed tenant A")
	}
}

// TestIsolation_ListRoutesNeverLeak: as tenant B, every GET route (with B's
// own ids for path parameters) answers without any of tenant A's data. POST
// routes that return tenant data are exercised too.
func TestIsolation_ListRoutesNeverLeak(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	// Positive control: served as tenant A, the sentinel is visible.
	if rec := serveOnce(isolationServer(t, f, f.A.ID).Handler(), http.MethodGet, "/api/identities", ""); !leaks(rec.Body.String()) {
		t.Fatal("tenant A's own identities do not carry the sentinel; the leak check would never fire")
	}
	srv := isolationServer(t, f, f.B.ID)
	h := srv.Handler()
	b := f.B.IDs
	param := regexp.MustCompile(`\{[a-z_]+\}`)
	lines := seedRequestLines(t, f)        // A's justification carries the sentinel
	roleIDs, _ := seedRoles(t, f)          // and A's role description
	sponsorships := seedSponsorships(t, f) // and A's sponsorship purpose
	policyIDs := seedAbac(t, f)            // and A's policy name
	values := map[string]string{
		"/api/jobs/{job_id}":                         insertJobRun(t, f.DB, f.B.ID),
		"/api/provisioning/ops/{op_id}":              insertProvOp(t, f.DB, f.B.ID, f.B.Refs["connection:ad"], "b-key"),
		"/api/abac/policies/{policy_id}":             policyIDs[f.B.ID],
		"/api/roles/{role_id}":                       roleIDs[f.B.ID],
		"/api/roles/{role_id}/versions":              roleIDs[f.B.ID],
		"/api/roles/{role_id}/drift":                 roleIDs[f.B.ID],
		"/api/requests/{request_id}":                 lines[f.B.ID],
		"/api/sponsorships/{sponsorship_id}":         sponsorships[f.B.ID],
		"/api/identities/{identity_id}":              fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/lifecycle":    fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/affiliations": fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/identifiers":  fmt.Sprint(b["alice"]),
		"/api/jml/leaver-plan/{identity_id}":         fmt.Sprint(b["alice"]),
		"/api/reviews/campaigns/{campaign_id}":       fmt.Sprint(b["campaign"]),
		"/api/hris/events/{event_id}/plan":           fmt.Sprint(b["hris:leaver"]),
		"/api/audit/events/{event_id}/proof":         latestEventID(t, f.DB, f.B.ID),
		"/api/email/messages/{message_id}":           seedEmailMessage(t, f, f.B, store.EmailDeferred),
		"/api/identities/{identity_id}/containment":  fmt.Sprint(b["alice"]),
		"/api/siem/sinks/{sink_id}/dead-letters":     seedSiemSink(t, f.DB, f.B.ID, "b"),
		"/api/alerts/{alert_id}":                     seedAlert(t, f.DB, f.B.ID, "b"),
		"/api/identities/{identity_id}/disables":     fmt.Sprint(b["alice"]),
		"/api/orgs/{org_id}":                         orgs.RootID,
	}
	checked := 0
	for _, rt := range srv.Routes() {
		if rt.Method != http.MethodGet || !rt.Tenant {
			continue
		}
		if strings.HasPrefix(rt.Pattern, "/api/admin/") && strings.Contains(rt.Pattern, "{") {
			continue // TestAdminAPI_CrossTenant (UUIDs, not fixture ids)
		}
		path := rt.Pattern
		if rp, ok := readinessGetPaths(f.B.Refs)[path]; ok && strings.Contains(path, "{") {
			path = rp // tenant B's own readiness ids
		}
		if strings.HasPrefix(path, "/api/groups/") && strings.Contains(path, "{") {
			continue // TestGroupsTenantIsolation (UUIDs, not fixture ids)
		}
		if path == "/api/request-drafts/{draft_id}" {
			continue // TestRequestDraftsAPI (a UUID, private to its user)
		}
		if strings.Contains(path, "{") {
			v, ok := values[path]
			if !ok {
				t.Errorf("GET %s has path parameters but no tenant B value", rt.Pattern)
				continue
			}
			path = param.ReplaceAllString(path, v)
		}
		queries := []string{"", "?q=a", "?limit=1000", "?unused_days=1", "?type=service", "?type=ai_agent", "?requestable=true"}
		if path == "/api/graph" {
			queries = []string{fmt.Sprintf("?identity_id=%d", b["alice"]), fmt.Sprintf("?resource_id=%d", b["resource:aws:prod"]),
				fmt.Sprintf("?identity_id=%d&perm_key=perm:%d", b["alice"], b["perm:aws:get-pii"])}
		}
		for i, q := range queries {
			rec := serveOnce(h, http.MethodGet, path+q, "")
			if rec.Code != http.StatusOK {
				if i == 0 || path == "/api/graph" {
					t.Errorf("GET %s: status %d: %.300s", path, rec.Code, rec.Body.String())
				}
				continue
			}
			checked++
			if leaks(rec.Body.String()) {
				t.Errorf("GET %s%s leaks tenant A data", path, q)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no GET route was checked")
	}
	// Writes that return tenant data, then the reads again.
	for _, c := range []struct{ path, body string }{
		{"/api/connectors/sync", `{}`},
		{"/api/reviews/campaigns", `{}`},
		{"/api/simulate", `{}`},
		{"/api/jit/sweep", `{}`},
		{"/api/hris/events", `{"type":"leaver","identity_id":` + fmt.Sprint(b["bob"]) + `}`},
		{fmt.Sprintf("/api/jit/requests/%d/approve", b["request:pending"]), `{}`},
		{fmt.Sprintf("/api/reviews/items/%d/decision", b["item"]), `{"decision":"keep"}`},
		{fmt.Sprintf("/api/hris/events/%d/execute", b["hris:leaver"]), ``},
	} {
		rec := serveOnce(h, http.MethodPost, c.path, c.body)
		if rec.Code != http.StatusOK {
			t.Errorf("POST %s: status %d: %.300s", c.path, rec.Code, rec.Body.String())
		}
		if leaks(rec.Body.String()) {
			t.Errorf("POST %s leaks tenant A data", c.path)
		}
	}
	for _, rt := range srv.Routes() {
		if rt.Method == http.MethodGet && rt.Tenant && !strings.Contains(rt.Pattern, "{") {
			if rec := serveOnce(h, http.MethodGet, rt.Pattern, ""); leaks(rec.Body.String()) {
				t.Errorf("after writes, GET %s leaks tenant A data", rt.Pattern)
			}
		}
	}
}

// TestIsolation_GraphSnapshotScoped: tenant B's graph shares no node with
// tenant A's, and /api/simulate with one of A's node keys is a 400.
func TestIsolation_GraphSnapshotScoped(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	snap := func(id tenancy.ID) *graph.Snapshot {
		var g *graph.Snapshot
		if err := f.DB.ReadTenant(context.Background(), id, func(c *store.TenantTx) error {
			var err error
			g, err = graph.Build(c, storetest.Now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return g
	}
	ga, gb := snap(f.A.ID), snap(f.B.ID)
	if len(ga.Nodes()) == 0 || len(gb.Nodes()) == 0 {
		t.Fatal("empty graph; the fixture is not exercising the test")
	}
	for _, n := range ga.Nodes() {
		if gb.HasNode(n.Key) {
			t.Errorf("tenant B's graph has tenant A's node %s", n.Key)
		}
	}
	h := isolationServer(t, f, f.B.ID).Handler()
	for _, body := range []string{
		fmt.Sprintf(`{"add_edges":[{"src":"account:%d","dst":"group:%d"}]}`, f.A.IDs["acct:okta:alice"], f.B.IDs["group:aws:ProdAdmin"]),
		fmt.Sprintf(`{"add_edges":[{"src":"account:%d","dst":"group:%d"}]}`, f.B.IDs["acct:okta:alice"], f.A.IDs["group:aws:ProdAdmin"]),
	} {
		rec := serveOnce(h, http.MethodPost, "/api/simulate", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown node") {
			t.Errorf("simulate with tenant A's node key: %d %.300s, want 400 unknown node", rec.Code, rec.Body.String())
		}
	}
}

// TestIsolation_NoSessionFailsClosed: without a session every non-public
// route answers 401 login_required with no data, whatever tenant a client
// names in a header or query parameter; the request is recorded on the
// platform chain, anonymous, with the reason.
func TestIsolation_NoSessionFailsClosed(t *testing.T) {
	t.Parallel()
	f := storetest.TwoTenants(t)
	srv := isolationServer(t, f, f.B.ID)
	h := srv.Anonymous()
	for _, rt := range srv.Routes() {
		if rt.Public {
			continue
		}
		path := regexp.MustCompile(`\{[a-z_]+\}`).ReplaceAllString(rt.Pattern, "1") + "?tenant=" + f.A.Slug
		body := ""
		if rt.Method != http.MethodGet {
			body = `{}`
		}
		req := httptest.NewRequest(rt.Method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tessera-Tenant", f.A.ID.String())
		req.Header.Set("X-Tessera-User", "alice")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "login_required") {
			t.Errorf("%s %s without a session: %d %.200s, want 401 login_required", rt.Method, path, rec.Code, rec.Body.String())
		}
		if leaks(rec.Body.String()) {
			t.Errorf("%s %s without a session leaks data", rt.Method, path)
		}
	}
	var events int
	if err := f.DB.ReadTenant(context.Background(), tenancy.Platform, func(c *store.TenantTx) error {
		log, err := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
		for _, e := range log {
			if e.Action == store.ActionHTTPRequest && e.ActorType == store.ActorAnonymous &&
				strings.Contains(string(e.Detail), `"anonymous_reason":"no_session"`) {
				events++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if events == 0 {
		t.Error("no anonymous http.request event recorded on the platform chain")
	}
}

// TestIsolation_TenantContextMissing: a handler that reaches tenant data
// without the tenant wrapper (a programming error) gets 500, not data, and
// tenancy.context_missing is recorded on the platform tenant.
func TestIsolation_TenantContextMissing(t *testing.T) {
	f := storetest.TwoTenants(t)
	raw := newIsolationServer(f)
	raw.handle(http.MethodGet, "/api/oops", noTenant, need(auth.PermGraphRead), func(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
		return store.TxFrom(r.Context()).Identities()
	})
	h := asAdmin(t, raw, f.DB, f.B.ID, storetest.Now).Handler()
	rec := serveOnce(h, http.MethodGet, "/api/oops", "")
	if rec.Code != http.StatusInternalServerError || leaks(rec.Body.String()) {
		t.Errorf("handler without a tenant transaction: %d %.200s", rec.Code, rec.Body.String())
	}
	var events int
	if err := f.DB.ReadTenant(context.Background(), tenancy.Platform, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		for _, e := range log {
			if e.Action == "tenancy.context_missing" {
				events++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if events == 0 {
		t.Error("no tenancy.context_missing event recorded on the platform tenant")
	}
}
