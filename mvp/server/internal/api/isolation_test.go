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

func newIsolationServer(f *storetest.Fixture) *Server { return newIsolationServerWith(f, nil) }

// newRotationIsolationServer is newIsolationServer with a KEK for adapter
// credentials and the simulated rotation adapter admitted.
func newRotationIsolationServer(f *storetest.Fixture) *Server {
	return newIsolationServerWith(f, func(c *Config) { c.Sealer, c.RotationFake = testSealer(), true })
}

func newIsolationServerWith(f *storetest.Fixture, mutate func(*Config)) *Server {
	kek, err := seal.New(storetest.IdentityKEK)
	if err != nil {
		panic(err)
	}
	cfg := Config{
		Identifiers: identifiers.NewKeyer(kek),
		Store:       f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
		Env:            "test",
		RateLimits:     noRateLimits, // the coverage tests send hundreds of anonymous requests
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

// testSealer is a throwaway KEK for adapter credentials.
func testSealer() *seal.Sealer {
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		panic(err)
	}
	return s
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
	"GET identity":            {method: "GET", path: pathf("/api/identities/%d"), key: "alice"},
	"GET identity (nhi)":      {method: "GET", path: pathf("/api/identities/%d"), key: "svc-etl"},
	"GET leaver plan":         {method: "GET", path: pathf("/api/jml/leaver-plan/%d"), key: "alice"},
	"GET campaign":            {method: "GET", path: pathf("/api/reviews/campaigns/%d"), key: "campaign"},
	"GET hris plan":           {method: "GET", path: pathf("/api/hris/events/%d/plan"), key: "hris:leaver"},
	"POST hris execute":       {method: "POST", path: pathf("/api/hris/events/%d/execute"), key: "hris:leaver"},
	"POST review consult":     {method: "POST", path: pathf("/api/reviews/items/%d/consult"), key: "item", body: func(int64) string { return `{"identity_id":1,"question":"x"}` }},
	"POST review reassign":    {method: "POST", path: pathf("/api/reviews/items/%d/reassign"), key: "item", body: func(int64) string { return `{"identity_id":1,"reason":"x"}` }},
	"GET review item events":  {method: "GET", path: pathf("/api/reviews/items/%d/events"), key: "item"},
	"POST campaign lock":      {method: "POST", path: pathf("/api/reviews/campaigns/%d/lock"), key: "campaign", body: func(int64) string { return `{"reason":"x"}` }},
	"POST campaign unlock":    {method: "POST", path: pathf("/api/reviews/campaigns/%d/unlock"), key: "campaign", body: func(int64) string { return `{}` }},
	"POST campaign close":     {method: "POST", path: pathf("/api/reviews/campaigns/%d/close"), key: "campaign", body: func(int64) string { return `{"reason":"x"}` }},
	"POST review decision":    {method: "POST", path: pathf("/api/reviews/items/%d/decision"), key: "item", body: func(int64) string { return `{"decision":"revoke"}` }},
	"GET campaign population": {method: "GET", path: pathf("/api/reviews/campaigns/%d/population"), key: "campaign"},
	"GET campaign export":     {method: "GET", path: pathf("/api/reviews/campaigns/%d/export"), key: "campaign"},
	"POST qa decision": {method: "POST", path: pathf("/api/reviews/qa/%d/decision"), key: "qa",
		body: func(int64) string { return `{"decision":"revoke"}` }},
	"POST jit approve": {method: "POST", path: pathf("/api/jit/requests/%d/approve"), key: "request:pending", body: func(int64) string { return `{}` }},
	"POST jit deny":    {method: "POST", path: pathf("/api/jit/requests/%d/deny"), key: "request:pending", body: func(int64) string { return `{}` }},
	"POST jit revoke":  {method: "POST", path: pathf("/api/jit/requests/%d/revoke"), key: "request:approved", body: func(int64) string { return `{}` }},
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
	"DELETE account link":         {method: "DELETE", path: pathf("/api/accounts/%d/link"), key: "acct:okta:alice"},
	"DELETE account link request": {method: "DELETE", path: pathf("/api/correlation/link-requests/%d"), key: "acct:okta:alice"},
	"POST merge identity": {method: "POST", path: pathf("/api/identities/%d/merge"), key: "alice",
		body: func(id int64) string { return fmt.Sprintf(`{"into":%d,"reason":"x"}`, id) }},
	"GET identity affiliations":  {method: "GET", path: pathf("/api/identities/%d/affiliations"), key: "alice"},
	"GET identity identifiers":   {method: "GET", path: pathf("/api/identities/%d/identifiers"), key: "alice"},
	"GET identity access bundle": {method: "GET", path: pathf("/api/identities/%d/access-bundle"), key: "alice"},
	"GET identity guest profile": {method: "GET", path: pathf("/api/identities/%d/guest-profile"), key: "alice"},
	// a bundle names catalog groups by id: tenant A's group is not in B's catalog, like a missing one
	"POST invite bundle": {method: "POST", path: fixed("/api/guests/invitations"), key: "group:aws:ProdAdmin",
		body: func(id int64) string {
			return fmt.Sprintf(`{"given_name":"G","email":"g@x.example","population":"visitor","purpose":"x","ends_at":"2026-10-12T00:00:00Z","bundle":[%d]}`, id)
		}},
	"POST add affiliation": {method: "POST", path: pathf("/api/identities/%d/affiliations"), key: "alice",
		body: func(int64) string { return `{"type":"alum","reason":"x"}` }},
	"POST resend invitation": {method: "POST", path: pathf("/api/guests/%d/resend-invitation"), key: "alice",
		body: func(int64) string { return `{}` }},
	"POST revoke invitation": {method: "POST", path: pathf("/api/guests/%d/revoke-invitation"), key: "alice",
		body: func(int64) string { return `{}` }},
	"POST guest recovery": {method: "POST", path: pathf("/api/guests/%d/recovery"), key: "alice",
		body: func(int64) string { return `{}` }},
	"GET identity containment": {method: "GET", path: pathf("/api/identities/%d/containment"), key: "alice"},
	"POST contain identity": {method: "POST", path: pathf("/api/identities/%d/contain"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
	"GET identity disables": {method: "GET", path: pathf("/api/identities/%d/disables"), key: "alice"},
	"POST disable identity": {method: "POST", path: pathf("/api/identities/%d/disable"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
	"POST enable identity": {method: "POST", path: pathf("/api/identities/%d/enable"), key: "alice",
		body: func(int64) string { return `{"reason":"suspected credential compromise"}` }},
	// the groups REST API (GR-5): groups are UUIDs and are in TestGroupsAPI_Isolation; identities are here
	"GET identity groups": {method: "GET", path: pathf("/api/identities/%d/groups"), key: "alice"},
	"GET scim user":       {method: "GET", path: pathf("/scim/v2/Users/%d"), key: "alice"},
}

// routeParamKey maps each route with path parameters to the cases above.
var routeParamCases = map[string][]string{
	"GET /api/identities/{identity_id}":                   {"GET identity", "GET identity (nhi)"},
	"GET /api/jml/leaver-plan/{identity_id}":              {"GET leaver plan"},
	"GET /api/reviews/campaigns/{campaign_id}":            {"GET campaign"},
	"GET /api/reviews/campaigns/{campaign_id}/population": {"GET campaign population"},
	"GET /api/reviews/campaigns/{campaign_id}/export":     {"GET campaign export"},
	"POST /api/reviews/qa/{qa_id}/decision":               {"POST qa decision"},
	"GET /api/hris/events/{event_id}/plan":                {"GET hris plan"},
	"POST /api/hris/events/{event_id}/execute":            {"POST hris execute"},
	"POST /api/reviews/items/{item_id}/decision":          {"POST review decision"},
	"POST /api/reviews/items/{item_id}/consult":           {"POST review consult"},
	"POST /api/reviews/items/{item_id}/reassign":          {"POST review reassign"},
	"GET /api/reviews/items/{item_id}/events":             {"GET review item events"},
	"POST /api/reviews/campaigns/{campaign_id}/lock":      {"POST campaign lock"},
	"POST /api/reviews/campaigns/{campaign_id}/unlock":    {"POST campaign unlock"},
	"POST /api/reviews/campaigns/{campaign_id}/close":     {"POST campaign close"},
	"POST /api/jit/requests/{request_id}/approve":         {"POST jit approve"},
	"POST /api/jit/requests/{request_id}/deny":            {"POST jit deny"},
	"POST /api/jit/requests/{request_id}/revoke":          {"POST jit revoke"},
	"PUT /api/catalog/items/{group_id}":                   {"PUT catalog item"},
	"GET /api/identities/{identity_id}/lifecycle":         {"GET lifecycle"},
	"POST /api/guests/{identity_id}/resend-invitation":    {"POST resend invitation"},
	"POST /api/guests/{identity_id}/revoke-invitation":    {"POST revoke invitation"},
	"POST /api/guests/{identity_id}/recovery":             {"POST guest recovery"},
	"PUT /api/identities/{identity_id}/lifecycle":         {"PUT lifecycle"},
	"POST /api/identities/{identity_id}/lifecycle/extend": {"POST lifecycle extend"},
	"POST /api/accounts/{account_id}/link":                {"POST link account"},
	"POST /api/accounts/{account_id}/not-person":          {"POST account not person"},
	"DELETE /api/accounts/{account_id}/link":              {"DELETE account link"},
	"DELETE /api/correlation/link-requests/{account_id}":  {"DELETE account link request"},
	"POST /api/identities/{identity_id}/merge":            {"POST merge identity"},
	"GET /api/identities/{identity_id}/affiliations":      {"GET identity affiliations"},
	"GET /api/identities/{identity_id}/identifiers":       {"GET identity identifiers"},
	"GET /api/identities/{identity_id}/access-bundle":     {"GET identity access bundle"},
	"GET /api/identities/{identity_id}/guest-profile":     {"GET identity guest profile"},
	"POST /api/identities/{identity_id}/affiliations":     {"POST add affiliation"},
	"PUT /api/ownership/{kind}/{object_key}":              {"PUT group ownership", "PUT identity ownership"},
	"POST /api/identities/{identity_id}/contain":          {"POST contain identity"},
	"GET /api/identities/{identity_id}/containment":       {"GET identity containment"},
	"GET /api/identities/{identity_id}/groups":            {"GET identity groups"},
	"GET /scim/v2/Users/{id}":                             {"GET scim user"},
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
		if rt.Pattern == "/api/reviews/consultations/{consultation_id}/answer" {
			continue // TestReviewActionsAPI (the consultation is private to the person asked)
		}
		if strings.HasPrefix(rt.Pattern, "/api/reviews/schedules/{schedule_id}") {
			continue // TestReviewSchedulesAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/jobs/{job_id}") {
			continue // TestIsolation_JobRoutes (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/queue/jobs/{job_id}") {
			continue // TestQueueAPI (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/queue/schedules/{name}") {
			continue // TestQueueSchedulePauseResume (a schedule name, per tenant)
		}
		if strings.HasPrefix(rt.Pattern, "/api/access-drift/{drift_id}") || strings.HasPrefix(rt.Pattern, "/api/remediation-policies/{policy_id}") {
			continue // TestDriftAPI (UUIDs, not fixture ids)
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
		if strings.HasPrefix(rt.Pattern, "/api/questionnaires/{id}") {
			continue // TestQuestionnairesAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/workflows/{id}") || strings.HasPrefix(rt.Pattern, "/api/service-account-requests/{id}") {
			continue // TestWorkflowsAPI_CrossTenant, TestServiceAccountsAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/datasets/{id}") {
			continue // TestDatasetsAPI (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/roles/{role_id}") || strings.HasPrefix(rt.Pattern, "/api/role-requests/{request_id}") {
			continue // TestRolesAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/role-mining/") {
			continue // TestRoleMiningAPI_Flow (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/sod/") {
			continue // TestSodAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/abac/policies/{policy_id}") || rt.Pattern == "/api/catalog/items/{group_id}/policy" {
			continue // TestAbacAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if _, ok := rotationRouteCases[rt.Method+" "+rt.Pattern]; ok {
			continue // TestIsolation_RotationRouteCrossTenant
		}
		if rt.Pattern == "/api/auth/oidc/{connection_id}/callback" || rt.Pattern == "/api/auth/oauth2/{connection_id}/callback" ||
			rt.Pattern == "/api/auth/cas/{connection_id}/callback" || rt.Pattern == "/api/auth/wsfed/{connection_id}/callback" ||
			rt.Pattern == "/t/{slug}/bootstrap" {
			continue // TestIsolation_LoginCrossTenant (public; the tenant comes from the cookie or the slug)
		}
		if strings.HasPrefix(rt.Pattern, "/api/auth/saml/{connection_id}/") {
			continue // TestIsolation_SAMLCrossTenant (public; the tenant comes from the cookie or the connection)
		}
		if strings.HasPrefix(rt.Pattern, "/api/access/") {
			continue // TestAccessCrossTenant (UUID ids, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/t/{slug}/.well-known/") || strings.HasPrefix(rt.Pattern, "/t/{slug}/oauth/") {
			continue // TestOAuth_CrossTenant (public; the tenant is the slug, and its codes and tokens are its own)
		}
		if strings.HasPrefix(rt.Pattern, "/t/{slug}/mcp/") || strings.HasPrefix(rt.Pattern, "/api/mcp/") {
			continue // TestMCP_CrossTenant (UUID and token ids, a tenant slug in the path)
		}
		if strings.HasPrefix(rt.Pattern, "/t/{slug}/aws/.well-known/") {
			continue // TestAWSFederation_PublicDocuments (public; the tenant is the slug, and its keys are its own)
		}
		if rt.Pattern == "/api/identity-merges/{merge_id}/unmerge" {
			continue // TestCorrelationAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/identity-matches/{match_id}") || strings.HasPrefix(rt.Pattern, "/api/identity-merge-requests/{merge_request_id}") {
			continue // TestMatchingAPI_CrossTenant (UUIDs, not fixture ids)
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
		if rt.Pattern == "/api/email/suppressions/{address}" {
			continue // TestSuppressionsAndDSNAPI (an email address, not a fixture id: tenant A gets 404 on B's)
		}
		if rt.Pattern == "/api/auth/oidc/{connection_id}/callback" || rt.Pattern == "/t/{slug}/bootstrap" {
			continue // TestIsolation_LoginCrossTenant (public; the tenant comes from the cookie or the slug)
		}
		if rt.Pattern == "/api/guest-lifecycle/tasks/{task_id}/resolve" {
			continue // TestGuestLifecycleAPI_CrossTenant (a UUID, not a fixture id)
		}
		if rt.Pattern == "/public/t/{slug}/guest/renewal-request" {
			continue // TestGuestLifecycleAPI_RenewalRequest (public; the tenant comes from the slug)
		}
		if strings.HasPrefix(rt.Pattern, "/public/t/{slug}/register") {
			continue // TestRegister_* (public; the tenant comes from the slug)
		}
		if strings.HasPrefix(rt.Pattern, "/api/guest-registrations/{registration_id}/") {
			continue // TestRegisterAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/public/t/{slug}/claim/") {
			continue // TestClaim_SessionIsPerTenant (public; the tenant comes from the slug)
		}
		if rt.Pattern == "/api/guest-recoveries/{case_id}/cancel" || rt.Pattern == "/api/admin/terms/{key}/assignments" {
			continue // TestTermsAPI_CrossTenant (a UUID and a document key, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/jobs/{job_id}") {
			continue // TestIsolation_JobRoutes (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/provisioning/") {
			continue // TestIsolation_ProvisioningRoutes (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/containment-retries/{retry_id}/retry-now" {
			continue // TestContainmentRetriesAPI (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/ssf/transmitters/{id}") || strings.HasPrefix(rt.Pattern, "/public/t/{slug}/ssf/") || rt.Pattern == "/public/t/{slug}/lp/denials" {
			continue // TestSSFAPI_CrossTenant, TestLPDenial_OtherTenantsSlug (a bearer secret per tenant, not a fixture id)
		}
		if rt.Pattern == "/api/agents/{id}/revoke" {
			continue // TestAgentsAPI (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/aws/principals/") || strings.HasPrefix(rt.Pattern, "/api/aws/resources/") ||
			rt.Pattern == "/api/aws/explanations/{id}" {
			continue // TestAWSEvalTenantIsolation (ARNs and content hashes, not fixture ids)
		}
		if rt.Pattern == "/api/aws/connectors/{id}" || rt.Pattern == "/api/aws/snapshots/{id}" {
			continue // TestAWSAPI_*, and store.TestIsolation_AWSTables (UUIDs and content hashes, not fixture ids)
		}
		if rt.Pattern == "/api/aws/connectors/{id}/collect" || rt.Pattern == "/api/aws/collection-runs/{id}" {
			continue // TestAWSCollectTenantIsolation, and store.TestIsolation_AWSCollectionRuns (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/aws/changes/{op_id}/restore" {
			continue // TestIsolation_ProvisioningRoutes (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/aws/shadow/checks/{id}") {
			continue // TestAWSShadowTenantIsolation (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/lp/revocations/{id}") {
			continue // TestLPAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/evidence/packs/{pack_id}") {
			continue // TestEvidenceAPI_CrossTenant (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/helpdesk/cases/{case_id}") {
			continue // TestHelpdeskTenantIsolation (a UUID, not a fixture id)
		}
		if rt.Pattern == "/api/helpdesk/risk-signals/{risk_id}/dismiss" {
			continue // TestHelpdeskRiskDismissCrossTenant (a UUID, not a fixture id), store.TestIsolation_HelpdeskRiskDismissal
		}
		if strings.HasPrefix(rt.Pattern, "/api/groups/") || rt.Pattern == "/scim/v2/Groups/{id}" {
			continue // TestGroupsTenantIsolation (UUIDs, not fixture ids)
		}
		if rt.Pattern == "/api/auth/sessions/{session_id}" {
			continue // TestIsolation_SessionCookieScoped (a UUID, not a fixture id)
		}
		if strings.HasPrefix(rt.Pattern, "/api/flatfile/") {
			continue // TestFlatfileAPI_CrossTenant (a system name or a UUID, not a fixture id)
		}
		if rt.Pattern == "/api/admin/api-clients/{client_id}" {
			continue // TestAdminAPIClients_CrossTenant (a client_id string, not a fixture id)
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
		if strings.HasPrefix(rt.Pattern, "/api/orgs/{org_id}/") || rt.Pattern == "/api/review-types/{review_type}" {
			continue // TestSettingsAPI_CrossTenant (derived ids and type names, not fixture ids)
		}
		if strings.HasPrefix(rt.Pattern, "/api/vms/") {
			continue // TestVmsAPI (UUIDs, not fixture ids: tenant A gets 404 on B's source)
		}
		if strings.HasPrefix(rt.Pattern, "/api/breach/plans/{id}") {
			continue // TestBreachAPI_CrossTenant (UUIDs, not fixture ids: tenant A gets 404 on B's plan)
		}
		if strings.HasPrefix(rt.Pattern, "/api/proposals/") {
			continue // TestProposalsAPI_* (UUIDs and ids of one tenant's rows; a client sees only its own proposals)
		}
		if strings.HasPrefix(rt.Pattern, "/api/oauth-apps/") {
			continue // TestOAuthAppsAPI (UUIDs, not fixture ids: tenant B gets 404 on A's app and grants)
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
	ssfIDs := seedSSFTransmitters(t, f) // each tenant's own, A's carrying the sentinel
	// Each tenant has a help-desk case; A's carries the sentinel through its identity's name.
	caseIDs := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			hc := &store.HelpdeskCase{IdentityID: tn.IDs["alice"], Kind: "mfa", System: "okta", Reason: "lost phone", RequestedBy: "agent"}
			if err := c.InsertHelpdeskCase(hc, storetest.Now); err != nil {
				return err
			}
			caseIDs[tn.Slug] = hc.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// each tenant has an OAuth client; tenant A's carries the sentinel
	seedClient(t, f.DB, f.A.ID, "tsc_client_a", "ETL "+storetest.Sentinel)
	seedClient(t, f.DB, f.B.ID, "tsc_client_b", "ETL B")
	srv := asLinkedAdmin(t, newIsolationServer(f), f.DB, f.B.ID, storetest.Now) // decides a review item
	h := srv.Handler()
	b := f.B.IDs
	param := regexp.MustCompile(`\{[a-z_]+\}`)
	lines := seedRequestLines(t, f)        // A's justification carries the sentinel
	roleIDs, _ := seedRoles(t, f)          // and A's role description
	sponsorships := seedSponsorships(t, f) // and A's sponsorship purpose
	policyIDs := seedAbac(t, f)            // and A's policy name
	values := map[string]string{
		"/api/jobs/{job_id}":                              insertJobRun(t, f.DB, f.B.ID),
		"/api/provisioning/ops/{op_id}":                   insertProvOp(t, f.DB, f.B.ID, f.B.Refs["connection:ad"], "b-key"),
		"/api/abac/policies/{policy_id}":                  policyIDs[f.B.ID],
		"/api/roles/{role_id}":                            roleIDs[f.B.ID],
		"/api/roles/{role_id}/versions":                   roleIDs[f.B.ID],
		"/api/roles/{role_id}/drift":                      roleIDs[f.B.ID],
		"/api/roles/{role_id}/exclusions":                 roleIDs[f.B.ID],
		"/api/roles/{role_id}/flags":                      roleIDs[f.B.ID],
		"/api/requests/{request_id}":                      lines[f.B.ID],
		"/api/requests/{request_id}/comments":             lines[f.B.ID],
		"/api/requests/{request_id}/attachments":          lines[f.B.ID],
		"/api/sponsorships/{sponsorship_id}":              sponsorships[f.B.ID],
		"/api/identities/{identity_id}":                   fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/lifecycle":         fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/affiliations":      fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/identifiers":       fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/access-bundle":     fmt.Sprint(b["alice"]),
		"/api/identities/{identity_id}/guest-profile":     fmt.Sprint(b["alice"]),
		"/api/jml/leaver-plan/{identity_id}":              fmt.Sprint(b["alice"]),
		"/api/reviews/campaigns/{campaign_id}":            fmt.Sprint(b["campaign"]),
		"/api/hris/events/{event_id}/plan":                fmt.Sprint(b["hris:leaver"]),
		"/api/audit/events/{event_id}/proof":              latestEventID(t, f.DB, f.B.ID),
		"/api/email/messages/{message_id}":                seedEmailMessage(t, f, f.B, store.EmailDeferred),
		"/api/identities/{identity_id}/containment":       fmt.Sprint(b["alice"]),
		"/api/siem/sinks/{sink_id}/dead-letters":          seedSiemSink(t, f.DB, f.B.ID, "b"),
		"/api/alerts/{alert_id}":                          seedAlert(t, f.DB, f.B.ID, "b"),
		"/api/identities/{identity_id}/disables":          fmt.Sprint(b["alice"]),
		"/api/ssf/transmitters/{id}":                      ssfIDs[f.B.Slug],
		"/api/evidence/packs/{pack_id}":                   seedEvidencePack(t, f, f.B.ID),
		"/api/evidence/packs/{pack_id}/download":          seedEvidencePack(t, f, f.B.ID),
		"/api/orgs/{org_id}":                              orgs.RootID,
		"/api/reviews/campaigns/{campaign_id}/population": fmt.Sprint(b["campaign"]),
		"/api/reviews/items/{item_id}/events":             fmt.Sprint(b["item"]),
		"/api/reviews/campaigns/{campaign_id}/export":     fmt.Sprint(b["campaign"]),
		"/api/helpdesk/cases/{case_id}":                   caseIDs[f.B.Slug],
		"/api/admin/api-clients/{client_id}":              "tsc_client_b",
		"/api/identities/{identity_id}/groups":            fmt.Sprint(b["alice"]),
		"/scim/v2/Users/{id}":                             fmt.Sprint(b["alice"]),
	}
	checked := 0
	for _, rt := range srv.Routes() {
		if rt.Method != http.MethodGet || !rt.Tenant {
			continue
		}
		if rt.Pattern == "/api/flatfile/uploads/{upload_id}" {
			continue // TestFlatfileAPI_CrossTenant (a UUID; the list route below is checked here)
		}
		if strings.HasPrefix(rt.Pattern, "/api/admin/") && strings.Contains(rt.Pattern, "{") {
			continue // TestAdminAPI_CrossTenant (UUIDs, not fixture ids)
		}
		path := rt.Pattern
		if path == "/api/aws/snapshots/{id}" {
			continue // a content hash, not a fixture id: TestAWSAPI_Snapshots and store.TestIsolation_AWSTables
		}
		if path == "/api/aws/collection-runs/{id}" {
			continue // a UUID, not a fixture id: TestAWSCollectTenantIsolation
		}
		if path == "/api/aws/shadow/checks/{id}" {
			continue // a UUID, not a fixture id: TestAWSShadowTenantIsolation
		}
		if strings.HasPrefix(path, "/api/aws/principals/") || strings.HasPrefix(path, "/api/aws/resources/") ||
			path == "/api/aws/explanations/{id}" || path == "/api/aws/can" {
			continue // they need a snapshot and a query: TestAWSEvalTenantIsolation
		}
		if rp, ok := readinessGetPaths(f.B.Refs)[path]; ok && strings.Contains(path, "{") {
			path = rp // tenant B's own readiness ids
		}
		if path == "/api/mcp/authorizations/{id}" {
			continue // TestMCP_CrossTenant (a UUID, not a fixture id)
		}
		if (strings.HasPrefix(path, "/api/groups/") || path == "/scim/v2/Groups/{id}") && strings.Contains(path, "{") {
			continue // TestGroupsTenantIsolation (UUIDs, not fixture ids)
		}
		if path == "/api/orgs/{org_id}/settings" {
			continue // TestSettingsAPI_CrossTenant (derived ids, not fixture ids)
		}
		if strings.HasPrefix(path, "/api/lp/revocations/{id}") {
			continue // TestLPAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(path, "/api/sod/") && strings.Contains(path, "{") {
			continue // TestSodAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if strings.HasPrefix(path, "/api/role-mining/") && strings.Contains(path, "{") {
			continue // TestRoleMiningAPI_Flow (UUIDs, not fixture ids)
		}
		if path == "/api/proposals/{change_id}" {
			continue // TestProposalsAPI_* (a UUID, readable only by the client that proposed it)
		}
		if path == "/api/request-drafts/{draft_id}" {
			continue // TestRequestDraftsAPI (a UUID, private to its user)
		}
		if path == "/api/oauth-apps/{app_id}" {
			continue // TestOAuthAppsAPI (a UUID, not a fixture id)
		}
		if strings.HasPrefix(path, "/api/breach/plans/{id}") {
			continue // TestBreachAPI_CrossTenant (a UUID, not a fixture id)
		}
		if path == "/api/questionnaires/{id}" {
			continue // TestQuestionnairesAPI_CrossTenant (a UUID, not a fixture id)
		}
		if path == "/api/datasets/{id}" || path == "/api/datasets/{id}/contains" {
			continue // TestDatasetsAPI (UUIDs, not fixture ids)
		}
		if path == "/api/workflows/{id}" || path == "/api/service-account-requests/{id}" {
			continue // TestWorkflowsAPI_CrossTenant, TestServiceAccountsAPI_CrossTenant (UUIDs, not fixture ids)
		}
		if rp, ok := rotationGetPaths(f.B.Refs)[path]; ok {
			path = rp // tenant B's own rotation ids
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
		if path == "/api/groups/permissions/check" {
			continue // needs a resource and an action: TestGroupsPermissionsAPI
		}
		if path == "/api/groups/permissions/effective" {
			queries = []string{fmt.Sprintf("?identity=%d", b["alice"])}
		}
		if path == "/api/access/as-of" {
			queries = []string{fmt.Sprintf("?resource=%d&date=2026-10-08", b["resource:aws:prod"]),
				fmt.Sprintf("?resource=%d&date=2026-10-08T09:00:00", b["resource:aws:customer-pii"])}
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
