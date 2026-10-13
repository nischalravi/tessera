package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// designRoutes is the route -> requirement table of the designs, transcribed:
// docs/design/phase-0-platform-security.md §16.2 (existing routes) and §16.1
// (session and audit routes), and docs/design/deployment-readiness.md §9
// (readiness routes). Columns: method, pattern, permission, step-up
// (STEP_UP_POLICY or -). "public" marks the allow-list. Routes that neither
// design names (GET /api/accounts, the API description) are marked with a
// trailing "#" and the requirement chosen for them in this PR.
const designRoutes = `
GET    /api/health                                   public
GET    /api/connectors                               graph.read      -
POST   /api/connectors/sync                          connectors.sync -
GET    /api/summary                                  graph.read      -
GET    /api/identities                               graph.read      -
GET    /api/identities/{identity_id}                 graph.read      -
GET    /api/accounts                                 graph.read      -  #
GET    /api/groups                                   graph.read      -
GET    /api/resources                                graph.read      -
GET    /api/graph                                    graph.read      -
GET    /api/nhi                                      graph.read      -
GET    /api/least-privilege/recommendations          graph.read      -
POST   /api/least-privilege/revoke                   graph.read      -  (dry_run=false: grants.revoke + STEP_UP_POLICY in the handler)
GET    /api/policies                                 graph.read      -
GET    /api/violations                               graph.read      -
POST   /api/simulate                                 graph.read      -
GET    /api/jit/requests                             graph.read      -
POST   /api/jit/requests                             jit.request     -
POST   /api/jit/requests/{request_id}/approve        jit.decide      STEP_UP_POLICY
POST   /api/jit/requests/{request_id}/deny           jit.deny_revoke -
POST   /api/jit/requests/{request_id}/revoke         jit.deny_revoke -
POST   /api/jit/sweep                                jit.sweep       -
GET    /api/reviews/campaigns                        graph.read      -
POST   /api/reviews/campaigns                        reviews.manage  -
GET    /api/reviews/campaigns/{campaign_id}          graph.read      -
POST   /api/reviews/items/{item_id}/decision         reviews.decide  STEP_UP_POLICY
GET    /api/hris/events                              graph.read      -
POST   /api/hris/events                              hris.simulate_event -
GET    /api/hris/events/{event_id}/plan              graph.read      -
POST   /api/hris/events/{event_id}/execute           hris.execute    STEP_UP_POLICY
GET    /api/jml/leaver-plan/{identity_id}            graph.read      -
GET    /openapi.json                                 auth.self       -  #
GET    /docs                                         auth.self       -  #
GET    /docs/oauth2-redirect                         auth.self       -  #
GET    /redoc                                        auth.self       -  #
GET    /api/audit                                    audit.read      -
GET    /api/audit/events/{event_id}/proof            audit.read      -
GET    /api/audit/checkpoints                        audit.read      -
GET    /api/audit/keys                               audit.read      -
POST   /api/audit/verify                             audit.verify    -
GET    /api/audit/export                             audit.read      -
GET    /api/readiness/templates                      connections.read   -
GET    /api/readiness/templates/{type}               connections.read   -
PUT    /api/readiness/overlays/{type}                connections.manage STEP_UP_POLICY
GET    /api/readiness/openapi.json                   auth.self          -  #
GET    /api/connections                              connections.read   -
POST   /api/connections                              connections.manage -
GET    /api/connections/{id}                         connections.read   -
PATCH  /api/connections/{id}/config                  connections.manage STEP_UP_POLICY
PUT    /api/connections/{id}/credential              connections.manage STEP_UP_POLICY
GET    /api/connections/{id}/checklist               connections.read   -
POST   /api/connections/{id}/checklist/{item}/attest connections.manage -
POST   /api/connections/{id}/checklist/{item}/skip   connections.manage -
DELETE /api/connections/{id}/checklist/{item}/skip   connections.manage -
POST   /api/connections/{id}/transition              connections.manage -
POST   /api/connections/{id}/activate                connections.activate STEP_UP_POLICY
POST   /api/connections/{id}/retire                  connections.manage STEP_UP_POLICY
GET    /api/correlation/queue                        graph.read      -  # issue #160
GET    /api/correlation/decisions                    graph.read      -  # issue #160
POST   /api/accounts/{account_id}/link               identities.correlate STEP_UP_POLICY  # issue #160
POST   /api/accounts/{account_id}/not-person         identities.correlate STEP_UP_POLICY  # issue #160
DELETE /api/accounts/{account_id}/link               identities.correlate STEP_UP_POLICY  # issue #160
POST   /api/identities/{identity_id}/merge           identities.merge STEP_UP_POLICY  # issue #160
GET    /api/identity-merges                          graph.read      -  # issue #160
GET    /api/identities/{identity_id}/affiliations    graph.read      -  # issue #64
GET    /api/identities/{identity_id}/identifiers     graph.read      -  # issue #64
POST   /api/identities/{identity_id}/affiliations    identities.affiliate STEP_UP_POLICY  # issue #64
POST   /api/affiliations/{affiliation_id}/end        identities.affiliate STEP_UP_POLICY  # issue #64
POST   /api/identity-merges/{merge_id}/unmerge       identities.merge STEP_UP_POLICY  # issue #160
GET    /api/catalog                                  requests.create -  # issue #164 (?all=1: catalog.manage in the handler)
PUT    /api/catalog/items/{group_id}                 catalog.manage  STEP_UP_POLICY  # issue #164
POST   /api/requests                                 requests.create -  # issue #164 (others: requests.create_for_others in the handler)
GET    /api/requests                                 requests.create -  # issue #164 (scope=pending|all: requests.decide or graph.read)
GET    /api/requests/{request_id}                    requests.create -  # issue #164
POST   /api/requests/{request_id}/approve            requests.create STEP_UP_POLICY  # issue #164 (#165: the line's routing decides who)
POST   /api/requests/{request_id}/deny               requests.create -  # issue #164 (#165: the line's routing decides who)
POST   /api/requests/{request_id}/cancel             requests.create -  # issue #164 (the requester)
POST   /api/requests/{request_id}/remove             requests.create -  # issue #164 (requests.decide, or the beneficiary)
GET    /api/roles                                    requests.create -  # issue #161
POST   /api/roles                                    roles.manage    STEP_UP_POLICY  # issue #161
GET    /api/roles/{role_id}                          graph.read      -  # issue #161
PUT    /api/roles/{role_id}                          roles.manage    STEP_UP_POLICY  # issue #161
GET    /api/roles/{role_id}/versions                 graph.read      -  # issue #161
GET    /api/roles/{role_id}/drift                    graph.read      -  # issue #161
POST   /api/roles/{role_id}/retire                   roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/reconcile                roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/members                  roles.manage    STEP_UP_POLICY  # issue #161
POST   /api/roles/{role_id}/members/{identity_id}/remove roles.manage STEP_UP_POLICY  # issue #161
POST   /api/role-requests                            requests.create -  # issue #161 (others: requests.create_for_others in the handler)
GET    /api/role-requests                            requests.create -  # issue #161 (scope=pending|all: requests.decide or graph.read)
POST   /api/role-requests/{request_id}/approve       requests.decide STEP_UP_POLICY  # issue #161
POST   /api/role-requests/{request_id}/deny          requests.decide -  # issue #161
POST   /api/role-requests/{request_id}/cancel        requests.create -  # issue #161 (the requester)
GET    /api/lifecycle                                graph.read      -  # issue #159
GET    /api/lifecycle/sponsored                      requests.create -  # issue #159
POST   /api/lifecycle/sweep                          lifecycle.manage -  # issue #159
GET    /api/identities/{identity_id}/lifecycle       graph.read      -  # issue #159
PUT    /api/identities/{identity_id}/lifecycle       lifecycle.manage STEP_UP_POLICY  # issue #159
POST   /api/identities/{identity_id}/lifecycle/extend requests.create -  # issue #159 (the sponsor, or lifecycle.manage)
GET    /api/approvals/inbox                          requests.create -  # issue #165
GET    /api/approvals/delegates                      requests.create -  # issue #165
GET    /api/approvals/delegations                    requests.create -  # issue #165 (?all=1: requests.decide)
POST   /api/approvals/delegations                    requests.create -  # issue #165
POST   /api/approvals/delegations/{delegation_id}/revoke requests.create -  # issue #165
GET    /api/notifications                            auth.self       -  # issue #189 (the caller's own inbox)
POST   /api/notifications/read                       auth.self       -  # issue #189
GET    /api/notifications/preferences                auth.self       -  # issue #189
PUT    /api/notifications/preferences                auth.self       -  # issue #189
GET    /api/email/messages                           email.read      -  # issue #189
GET    /api/email/messages/{message_id}              email.read      -  # issue #189
POST   /api/email/messages/{message_id}/retry        email.manage    -  # issue #189
POST   /api/connections/{id}/validate                connections.manage -
GET    /api/connections/{id}/validations/{run}       connections.read   -
POST   /api/connections/{id}/dry-run                 connections.manage -
GET    /api/connections/{id}/dry-runs/{run}          connections.read   -
GET    /api/connections/{id}/findings                connections.read   -
POST   /api/connections/{id}/findings/{fid}/accept   connections.manage -
GET    /api/connections/{id}/health                  connections.read   -
GET    /api/insights/deployment-health               connections.read   -
POST   /api/insights/deployment-health/rerun         connections.manage -
GET    /api/auth/session                             auth.self       -
POST   /api/auth/logout                              auth.self       -
GET    /api/auth/sessions                            auth.self       -
DELETE /api/auth/sessions/{session_id}               auth.self       -  (another user's: admin.sessions.revoke + STEP_UP_ADMIN in the handler)
GET    /api/auth/dev-login                           public
POST   /api/auth/dev-login                           public
`

type designRoute struct {
	method, pattern string
	public          bool
	perm            auth.Permission
	stepUp          bool
}

func parseDesignRoutes(t *testing.T) []designRoute {
	t.Helper()
	var out []designRoute
	for _, line := range strings.Split(designRoutes, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		r := designRoute{method: f[0], pattern: f[1]}
		if f[2] == "public" {
			r.public = true
		} else {
			if len(f) < 4 {
				t.Fatalf("bad table line %q", line)
			}
			r.perm, r.stepUp = auth.Permission(f[2]), f[3] == "STEP_UP_POLICY"
		}
		out = append(out, r)
	}
	return out
}

// TestRoutesMatchDesignTable: the registered routes are exactly the design
// table, with the same permission and step-up requirement.
func TestRoutesMatchDesignTable(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	table := map[string]designRoute{}
	for _, r := range parseDesignRoutes(t) {
		table[r.method+" "+r.pattern] = r
	}
	seen := map[string]bool{}
	for _, rt := range srv.Routes() {
		k := rt.Method + " " + rt.Pattern
		seen[k] = true
		d, ok := table[k]
		if !ok {
			t.Errorf("%s is registered but not in the design table", k)
			continue
		}
		if rt.Public != d.public || rt.Perm != d.perm {
			t.Errorf("%s: public=%t perm=%q, design public=%t perm=%q", k, rt.Public, rt.Perm, d.public, d.perm)
		}
		if (rt.Authn != nil) != d.stepUp || (rt.Authn != nil && *rt.Authn != auth.StepUpPolicy) {
			t.Errorf("%s: step-up %v, design %t", k, rt.Authn, d.stepUp)
		}
	}
	for k := range table {
		if !seen[k] {
			t.Errorf("%s is in the design table but not registered", k)
		}
	}
}

// rbacRoles are the principals of the matrix: one per role, each signed in
// with a fresh phishing-resistant context (so every role a principal holds
// is active and every step-up requirement is met: the matrix tests the
// permission column alone; role activation and step-up have their own tests).
var rbacRoles = []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin,
	auth.RoleTenantAdmin, auth.RoleBreakGlass}

// TestRBACRouteMatrix (design §19 PR5 api/rbac_routes_test): for every
// route of the design table and every role, the expected status: 401
// without a session, 403 when the role lacks the route's permission, and
// otherwise anything but 401/403 (the handler ran). break_glass is never
// active under an IdP sign-in, so it is refused everything but the
// session's own routes.
func TestRBACRouteMatrix(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	logins := map[auth.Role]authtest.Login{}
	for _, r := range rbacRoles {
		logins[r] = signIn(t, f.DB, f.B.ID, authtest.User{Email: string(r) + "@b.example", Roles: []auth.Role{r}},
			authtest.Phr, storetest.Now)
	}
	routes := map[string]RouteInfo{}
	for _, rt := range srv.Routes() {
		routes[rt.Method+" "+rt.Pattern] = rt
	}
	for _, d := range parseDesignRoutes(t) {
		rt, ok := routes[d.method+" "+d.pattern]
		if !ok || d.public || d.pattern == "/api/auth/logout" {
			continue // public routes: TestAllRoutesRequireAuth; logout ends the role's session
		}
		t.Run(d.method+" "+d.pattern, func(t *testing.T) {
			if rec := serve(h, withHeader(routeRequest(rt, f.B), "X-Test-Anonymous", "1")); rec.Code != http.StatusUnauthorized {
				t.Errorf("anonymous: %d, want 401", rec.Code)
			}
			for _, role := range rbacRoles {
				req := routeRequest(rt, f.B)
				logins[role].Apply(req)
				rec := serve(h, req)
				// auth.self: any principal, whatever its roles
				allowed := d.perm == auth.PermAuthenticated ||
					(role != auth.RoleBreakGlass && containsPerm(auth.RolePermissions(role), d.perm))
				switch {
				case allowed && (rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden):
					t.Errorf("%s: %d %.200s, want the handler to run", role, rec.Code, rec.Body.String())
				case !allowed && rec.Code != http.StatusForbidden:
					t.Errorf("%s: %d %.200s, want 403", role, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// TestRevokeApplyNeedsGrantsRevoke: a dry run needs graph.read; applying
// needs grants.revoke (policy admins only) and a fresh phishing-resistant
// sign-in (§16.2, checked in the handler because it depends on the body).
func TestRevokeApplyNeedsGrantsRevoke(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	edge := f.B.IDs["edge:0"]
	for _, tc := range []struct {
		role   auth.Role
		ctx    authtest.Ctx
		status int
		err    string
	}{
		{auth.RoleViewer, authtest.Phr, 403, "forbidden"},
		{auth.RoleOperator, authtest.Phr, 403, "forbidden"},
		{auth.RoleTenantAdmin, authtest.Phr, 403, "forbidden"},
		{auth.RolePolicyAdmin, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, 401, "step_up_required"},
		{auth.RolePolicyAdmin, authtest.Phr, 200, ""},
	} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: fmt.Sprintf("%s-%d@b.example", tc.role, tc.status),
			Roles: []auth.Role{tc.role}}, tc.ctx, storetest.Now)
		dry := httptest.NewRequest(http.MethodPost, "/api/least-privilege/revoke", strings.NewReader(fmt.Sprintf(`{"edge_id":%d}`, edge)))
		dry.Header.Set("Content-Type", "application/json")
		l.Apply(dry)
		if rec := serve(h, dry); rec.Code != http.StatusOK && tc.role != auth.RolePolicyAdmin {
			t.Errorf("%s dry run: %d", tc.role, rec.Code)
		}
		apply := httptest.NewRequest(http.MethodPost, "/api/least-privilege/revoke",
			strings.NewReader(fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge)))
		apply.Header.Set("Content-Type", "application/json")
		l.Apply(apply)
		rec := serve(h, apply)
		if rec.Code != tc.status || (tc.err != "" && !strings.Contains(rec.Body.String(), tc.err)) {
			t.Errorf("%s apply: %d %.200s, want %d %s", tc.role, rec.Code, rec.Body.String(), tc.status, tc.err)
		}
	}
}

func withHeader(r *http.Request, k, v string) *http.Request {
	r.Header.Set(k, v)
	return r
}

func containsPerm(ps []auth.Permission, p auth.Permission) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// TestConnectionConfigNeedsStepUp: editing a connection's config can point
// its credential at another host or widen its write scope, so it needs the
// same fresh phishing-resistant sign-in as setting the credential.
func TestConnectionConfigNeedsStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := authtest.User{Email: "conn-admin@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}
	stale := signIn(t, f.DB, f.B.ID, admin, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	body := `{"base_url":"https://attacker.example"}`
	for _, path := range []string{"/api/connections/x/config", "/api/connections/x/credential"} {
		method := map[bool]string{true: "PATCH", false: "PUT"}[strings.HasSuffix(path, "config")]
		if rec := serve(h, authed(stale, method, path, body)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s %s with a 20-minute-old sign-in: %d %s", method, path, rec.Code, rec.Body.String())
		}
	}
	fresh := signIn(t, f.DB, f.B.ID, authtest.User{Email: "conn-admin2@b.example", Roles: admin.Roles}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(fresh, "PATCH", "/api/connections/x/config", body)); rec.Code == 401 || rec.Code == 403 {
		t.Errorf("PATCH config with a fresh sign-in: %d %s", rec.Code, rec.Body.String())
	}
}
