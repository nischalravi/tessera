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
POST   /api/identity-merges/{merge_id}/unmerge       identities.merge STEP_UP_POLICY  # issue #160
POST   /api/identities/{identity_id}/contain         identities.contain STEP_UP_POLICY  # issue #106
GET    /api/identities/{identity_id}/containment     graph.read      -  # issue #106
POST   /api/containment-retries/{retry_id}/retry-now identities.contain STEP_UP_POLICY  # issue #106
PUT    /api/connections/{id}/containment-credential  connections.manage STEP_UP_POLICY  # issue #106
POST   /api/connections/{id}/validate                connections.manage -
GET    /api/connections/{id}/validations/{run}       connections.read   -
POST   /api/connections/{id}/dry-run                 connections.manage -
GET    /api/connections/{id}/dry-runs/{run}          connections.read   -
GET    /api/connections/{id}/findings                connections.read   -
POST   /api/connections/{id}/findings/{fid}/accept   connections.manage -
GET    /api/connections/{id}/health                  connections.read   -
GET    /api/insights/deployment-health               connections.read   -
POST   /api/insights/deployment-health/rerun         connections.manage -
GET    /api/groups/folders                           groups.read     -  # issue #44, #47: the folders the caller may view
POST   /api/groups/folders                           groups.write    -  # issue #44, #47: create on the parent
GET    /api/groups/folders/{id}                      groups.read     -  # issue #44, #47: stem_view
PATCH  /api/groups/folders/{id}                      groups.write    -  # issue #44, #47: stem_admin
DELETE /api/groups/folders/{id}                      groups.write    -  # issue #44, #47: stem_admin
POST   /api/groups/folders/{id}/move                 groups.write    -  # issue #44, #47: stem_admin, create on the destination
POST   /api/groups/folders/{id}/copy                 groups.write    -  # issue #44, #47: stem_admin, create on the destination
GET    /api/groups/native                            groups.read     -  # issue #44, #47: the groups the caller may view
POST   /api/groups                                   groups.write    -  # issue #44, #47: create on the folder
GET    /api/groups/{id}                              groups.read     -  # issue #44, #47: view
PATCH  /api/groups/{id}                              groups.write    -  # issue #44, #47: admin
DELETE /api/groups/{id}                              groups.write    -  # issue #44, #47: admin
POST   /api/groups/{id}/move                         groups.write    -  # issue #44, #47: admin, create on the destination
POST   /api/groups/{id}/copy                         groups.write    -  # issue #44, #47: read, create on the destination
POST   /api/groups/{id}/restore                      groups.write    -  # issue #44, #47: admin
GET    /api/groups/{id}/members                      groups.read     -  # issue #45, #47: read
POST   /api/groups/{id}/members                      groups.write    -  # issue #45, #47: update, or optin for oneself
GET    /api/groups/{id}/members/{member}             groups.read     -  # issue #45, #47: read
DELETE /api/groups/{id}/members/{member}             groups.write    -  # issue #45, #47: update, or optout for oneself
POST   /api/groups/{id}/convert-to-composite         groups.write    -  # issue #45, #47: admin, read on the factors
PUT    /api/groups/{id}/composite                    groups.write    -  # issue #45, #47: admin, read on the factors
POST   /api/groups/engine/verify                     groups.admin    -  # issue #45
GET    /api/groups/engine/ops/{seq}                  groups.admin    -  # issue #45
GET    /api/groups/folders/{id}/privileges           groups.read     -  # issue #47: stem_admin
POST   /api/groups/folders/{id}/privileges           groups.write    -  # issue #47: stem_admin
GET    /api/groups/folders/{id}/privileges/effective groups.read     -  # issue #47: stem_view (own), stem_admin (another identity)
DELETE /api/groups/folders/{id}/privileges/{privilege_id} groups.write -  # issue #47: stem_admin
GET    /api/groups/{id}/privileges                   groups.read     -  # issue #47: admin
POST   /api/groups/{id}/privileges                   groups.write    -  # issue #47: admin
GET    /api/groups/{id}/privileges/effective         groups.read     -  # issue #47: view (own), admin (another identity)
DELETE /api/groups/{id}/privileges/{privilege_id}    groups.write    -  # issue #47: admin
GET    /api/groups/privileges/settings               groups.admin    -  # issue #47
PUT    /api/groups/privileges/settings               groups.admin    -  # issue #47
PUT    /api/groups/users/{id}/identity               groups.admin    STEP_UP_POLICY  # issue #47
GET    /api/groups/pit/digests                       groups.admin    -  # issue #46
GET    /api/groups/pit/verify                        groups.admin    -  # issue #46
POST   /api/groups/pit/rebuild                       groups.admin    -  # issue #46
GET    /api/groups/object-types                      groups.read     -  # issue #50: the object type vocabulary
GET    /api/groups/services                          groups.read     -  # issue #50: the services the caller's groups grant (stem_view, view)
GET    /api/groups/attr-defs                         groups.read     -  # issue #50: the definitions the caller may view (attr_view)
POST   /api/groups/attr-defs                         groups.write    -  # issue #50: create on the folder
GET    /api/groups/attr-defs/{id}                    groups.read     -  # issue #50: attr_view
PATCH  /api/groups/attr-defs/{id}                    groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-defs/{id}                    groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/actions            groups.read     -  # issue #50: attr_view
POST   /api/groups/attr-defs/{id}/actions            groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-defs/{id}/actions/{action_id} groups.write   -  # issue #50: attr_admin
PUT    /api/groups/attr-defs/{id}/actions/{action_id}/implies groups.write -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/privileges         groups.read     -  # issue #50: attr_admin
POST   /api/groups/attr-defs/{id}/privileges         groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-defs/{id}/privileges/effective groups.read   -  # issue #50: attr_view (own), attr_admin (another identity)
DELETE /api/groups/attr-defs/{id}/privileges/{privilege_id} groups.write -  # issue #50: attr_admin
GET    /api/groups/attr-names                        groups.read     -  # issue #50: attr_view on the definition
POST   /api/groups/attr-names                        groups.write    -  # issue #50: attr_admin on the definition
GET    /api/groups/attr-names/{id}                   groups.read     -  # issue #50: attr_view
PATCH  /api/groups/attr-names/{id}                   groups.write    -  # issue #50: attr_admin
DELETE /api/groups/attr-names/{id}                   groups.write    -  # issue #50: attr_admin
PUT    /api/groups/attr-names/{id}/implies           groups.write    -  # issue #50: attr_admin
GET    /api/groups/attr-assignments                  groups.read     -  # issue #50: attr_read and the owner's read privilege (filtered)
POST   /api/groups/attr-assignments                  groups.write    -  # issue #50: attr_update and the owner's update privilege (attr_optin on oneself)
GET    /api/groups/attr-assignments/{id}             groups.read     -  # issue #50: attr_read and the owner's read privilege
PATCH  /api/groups/attr-assignments/{id}             groups.write    -  # issue #50: attr_update and the owner's update privilege
DELETE /api/groups/attr-assignments/{id}             groups.write    -  # issue #50: attr_update and the owner's update privilege (attr_optout on oneself)
PUT    /api/groups/attr-assignments/{id}/values      groups.write    -  # issue #50: attr_update and the owner's update privilege
GET    /api/groups/{id}/object-types                 groups.read     -  # issue #50: view (lint findings need read)
PUT    /api/groups/{id}/object-types                 groups.write    -  # issue #50: group_attr_update
GET    /api/groups/folders/{id}/object-types         groups.read     -  # issue #50: stem_view
PUT    /api/groups/folders/{id}/object-types         groups.write    -  # issue #50: stem_attr_update
POST   /api/groups/policy/validate                   groups.read     -  # issue #52: read on the groups the policy refers to
POST   /api/groups/policy/diff                       groups.read     -  # issue #52: read on the policy groups compared and on the groups referred to
POST   /api/groups/policy/apply                      groups.write    -  # issue #52: create on the folder or admin on the policy group, read on the groups referred to
POST   /api/groups/policy/reindex                    groups.admin    -  # issue #52
GET    /api/groups/{id}/policy                       groups.read     -  # issue #52: read
GET    /api/auth/session                             auth.self       -
POST   /api/auth/logout                              auth.self       -
GET    /api/auth/sessions                            auth.self       -
GET    /api/auth/step-up                             auth.self       -
DELETE /api/auth/sessions/{session_id}               auth.self       -  (another user's: admin.sessions.revoke + STEP_UP_ADMIN in the handler)
GET    /api/auth/discover                            public
GET    /api/auth/login                               public
GET    /api/auth/oidc/{connection_id}/callback       public
GET    /api/auth/saml/{connection_id}/metadata       public
POST   /api/auth/saml/{connection_id}/acs            public
GET    /api/auth/oauth2/{connection_id}/callback     public
GET    /t/{slug}/bootstrap                           public
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
				// a group route's handler may still refuse for want of the folder's or
				// group's privilege (403 privilege_required, issue #47): the handler ran
				privDenied := rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), `"privilege_required"`)
				switch {
				case allowed && !privDenied && (rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden):
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
