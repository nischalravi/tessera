package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func ctxOf(c authtest.Ctx) *auth.AuthnContext {
	x := auth.ContextFromRecord(authtest.Record([16]byte{1}, c, t0))
	return &x
}

var webauthn = func() *auth.AuthnContext {
	c := ctxOf(authtest.Ctx{AAL: 3, Phrh: true})
	c.Protocol, c.PhrBasis = "webauthn", "webauthn_attested"
	return c
}()

// TestRoleActivation (§12.2): admin roles are active only under a
// phishing-resistant context; other roles need AAL2 (phr with
// require_phr_for_all); break_glass needs a WebAuthn-attested AAL3 context.
func TestRoleActivation(t *testing.T) {
	all := auth.RoleSet{}
	for _, r := range auth.AllRoles() {
		all[r] = true
	}
	cases := []struct {
		name     string
		ctx      *auth.AuthnContext
		settings auth.ActivationSettings
		active   []auth.Role
	}{
		{"password only", ctxOf(authtest.AAL1), auth.ActivationSettings{}, nil},
		{"MFA, not phishing-resistant", ctxOf(authtest.AAL2), auth.ActivationSettings{},
			[]auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor}},
		{"phishing-resistant", ctxOf(authtest.Phr), auth.ActivationSettings{},
			[]auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin, auth.RoleTenantAdmin}},
		{"device-bound key (phrh)", ctxOf(authtest.Ctx{AAL: 3, Phrh: true}), auth.ActivationSettings{},
			[]auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin, auth.RoleTenantAdmin}},
		{"break-glass key", webauthn, auth.ActivationSettings{}, auth.AllRoles()},
		{"MFA with require_phr_for_all", ctxOf(authtest.AAL2), auth.ActivationSettings{RequirePhrForAll: true}, nil},
		{"no context", nil, auth.ActivationSettings{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			active, inactive := auth.ActivateRoles(all, tc.ctx, tc.settings, t0)
			got := active.Sorted()
			if len(got) != len(tc.active) {
				t.Fatalf("active %v, want %v", got, tc.active)
			}
			for i := range got {
				if got[i] != tc.active[i] {
					t.Fatalf("active %v, want %v", got, tc.active)
				}
			}
			if len(active)+len(inactive) != len(all) {
				t.Errorf("active %v and inactive %v do not partition the assigned roles", active, inactive)
			}
			for r, why := range inactive {
				if why == "" {
					t.Errorf("inactive %s has no reason", r)
				}
				if r.IsAdmin() && r != auth.RoleBreakGlass && why != auth.InactiveNeedsPhr {
					t.Errorf("inactive admin role %s: reason %q", r, why)
				}
			}
		})
	}
}

// TestAdminRoleInactiveWithoutPhr (design §19 PR5 role_activation_test):
// a tenant admin signed in without phishing resistance has no admin
// permission (403 role_inactive), keeps the session, and gets admin
// permissions after a phishing-resistant sign-in.
func TestAdminRoleInactiveWithoutPhr(t *testing.T) {
	e := newEnv(t)
	weak := authtest.LoginAs(t, e.db, tenantA, admin, authtest.AAL2, t0)
	p, why := e.authenticate(t, weak.Cookie)
	if p == nil {
		t.Fatalf("an AAL2 admin has no session: %s", why)
	}
	if !p.AssignedRoles.Has(auth.RoleTenantAdmin) || p.ActiveRoles.Has(auth.RoleTenantAdmin) ||
		p.InactiveRoles[auth.RoleTenantAdmin] != auth.InactiveNeedsPhr {
		t.Errorf("assigned %v active %v inactive %v", p.AssignedRoles, p.ActiveRoles, p.InactiveRoles)
	}
	for _, perm := range []auth.Permission{auth.PermAuditRead, auth.PermAdminRead, auth.PermConnectionsManage, auth.PermGraphRead} {
		d := auth.Check(p, perm, nil, t0)
		if d == nil || d.Status != http.StatusForbidden || d.Error != "role_inactive" {
			t.Errorf("%s without phr: %+v, want 403 role_inactive", perm, d)
		}
	}
	if d := auth.Check(p, auth.PermAuthenticated, nil, t0); d != nil {
		t.Errorf("the session's own routes: %+v", d)
	}
	strong := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	p, _ = e.authenticate(t, strong.Cookie)
	if p == nil || !p.ActiveRoles.Has(auth.RoleTenantAdmin) || auth.Check(p, auth.PermAuditRead, nil, t0) != nil {
		t.Errorf("phr admin: %+v", p)
	}
}

// TestCheck covers the error contract of §16.2.
func TestCheck(t *testing.T) {
	phr := ctxOf(authtest.Phr)
	stale := ctxOf(authtest.Ctx{AAL: 2, Phr: true, AuthTime: t0.Add(-16 * time.Minute)})
	user := func(ctx *auth.AuthnContext, roles ...auth.Role) *auth.Principal {
		assigned := auth.RoleSet{}
		for _, r := range roles {
			assigned[r] = true
		}
		active, inactive := auth.ActivateRoles(assigned, ctx, auth.ActivationSettings{}, t0)
		return &auth.Principal{Kind: auth.KindUser, Authn: ctx, AssignedRoles: assigned, ActiveRoles: active,
			InactiveRoles: inactive, Via: auth.ViaCookie}
	}
	machine := &auth.Principal{Kind: auth.KindAPIClient, ActiveRoles: auth.RoleSet{auth.RoleOperator: true},
		Scopes: auth.ScopeSet{auth.ScopeRead: true, auth.ScopeWrite: true}}
	cases := []struct {
		name  string
		p     *auth.Principal
		perm  auth.Permission
		authn *auth.AuthnRequirement
		code  int
		err   string
	}{
		{"anonymous", nil, auth.PermGraphRead, nil, 401, "login_required"},
		{"viewer reads", user(phr, auth.RoleViewer), auth.PermGraphRead, nil, 0, ""},
		{"viewer cannot approve", user(phr, auth.RoleViewer), auth.PermJITDecide, &auth.StepUpPolicy, 403, "forbidden"},
		{"tenant admin cannot revoke grants (SoD)", user(phr, auth.RoleTenantAdmin), auth.PermGrantsRevoke, nil, 403, "forbidden"},
		{"policy admin approves", user(phr, auth.RolePolicyAdmin), auth.PermJITDecide, &auth.StepUpPolicy, 0, ""},
		{"policy admin, stale authentication", user(stale, auth.RolePolicyAdmin), auth.PermJITDecide, &auth.StepUpPolicy, 401, "step_up_required"},
		{"operator, not phishing-resistant", user(ctxOf(authtest.AAL2), auth.RoleOperator), auth.PermJITDecide, &auth.StepUpPolicy, 401, "step_up_required"},
		{"operator, fresh phr", user(phr, auth.RoleOperator), auth.PermJITDecide, &auth.StepUpPolicy, 0, ""},
		{"admin change within 5 minutes", user(ctxOf(authtest.Ctx{AAL: 2, Phr: true, AuthTime: t0.Add(-4 * time.Minute)}), auth.RoleTenantAdmin),
			auth.PermAdminChangeReq, &auth.StepUpAdmin, 0, ""},
		{"admin change after 5 minutes", user(ctxOf(authtest.Ctx{AAL: 2, Phr: true, AuthTime: t0.Add(-6 * time.Minute)}), auth.RoleTenantAdmin),
			auth.PermAdminChangeReq, &auth.StepUpAdmin, 401, "step_up_required"},
		// an auth_time from the future satisfies nothing, not even the admin role's floor
		{"auth_time in the future", user(ctxOf(authtest.Ctx{AAL: 2, Phr: true, AuthTime: t0.Add(5 * time.Minute)}), auth.RolePolicyAdmin),
			auth.PermJITDecide, &auth.StepUpPolicy, 403, "role_inactive"},
		{"machine client on a step-up route", machine, auth.PermJITDecide, &auth.StepUpPolicy, 403, "interactive_authentication_required"},
		{"machine client within its scope", machine, auth.PermGraphRead, nil, 0, ""},
		{"machine client outside its scope", &auth.Principal{Kind: auth.KindAPIClient, ActiveRoles: auth.RoleSet{auth.RoleAuditor: true},
			Scopes: auth.ScopeSet{auth.ScopeRead: true}}, auth.PermAuditRead, nil, 403, "forbidden"},
		{"no permission declared", user(phr, auth.RoleTenantAdmin), "", nil, 403, "forbidden"},
		{"any principal", user(ctxOf(authtest.AAL1)), auth.PermAuthenticated, nil, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := auth.Check(tc.p, tc.perm, tc.authn, t0)
			if tc.code == 0 {
				if d != nil {
					t.Errorf("denied: %+v", d)
				}
				return
			}
			if d == nil || d.Status != tc.code || d.Error != tc.err {
				t.Errorf("got %+v, want %d %s", d, tc.code, tc.err)
			}
		})
	}
}

// TestStepUpChallenge: the 401 carries the RFC 9470 challenge.
func TestStepUpChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	req := auth.StepUpPolicy
	auth.WriteDenial(rec, &auth.Denial{Status: 401, Error: "step_up_required", Permission: auth.PermJITDecide, Requirement: &req})
	h := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{`error="insufficient_user_authentication"`, `acr_values="urn:tessera:acr:phr"`, "max_age=900"} {
		if !strings.Contains(h, want) {
			t.Errorf("WWW-Authenticate %q lacks %s", h, want)
		}
	}
	if b := rec.Body.String(); rec.Code != 401 || !strings.Contains(b, `"error":"step_up_required"`) ||
		!strings.Contains(b, `"max_age":900`) || !strings.Contains(b, `"acr":"urn:tessera:acr:phr"`) {
		t.Errorf("%d %s", rec.Code, b)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("denials must not be cached")
	}
}

// TestRolePermissionsMatchDesign pins the §12.1 table.
func TestRolePermissionsMatchDesign(t *testing.T) {
	want := map[auth.Role]string{
		auth.RoleViewer:      "graph.read",
		auth.RoleOperator:    "graph.read jit.request jit.decide jit.deny_revoke reviews.manage reviews.decide hris.simulate_event jobs.read provisioning.read",
		auth.RoleAuditor:     "graph.read audit.read audit.verify admin.read connections.read jobs.read provisioning.read",
		auth.RolePolicyAdmin: "graph.read jit.request jit.decide jit.deny_revoke reviews.manage reviews.decide hris.simulate_event grants.revoke hris.execute jit.sweep connectors.sync jobs.read provisioning.read provisioning.manage identities.correlate identities.merge identities.contain",
		auth.RoleTenantAdmin: "graph.read audit.read audit.verify admin.read admin.change.request admin.change.approve admin.users.disable admin.sessions.revoke connections.read connections.manage connections.activate jobs.read provisioning.read provisioning.manage",
		auth.RoleBreakGlass:  "admin.read breakglass.recover",
	}
	for r, w := range want {
		var got []string
		for _, p := range auth.RolePermissions(r) {
			got = append(got, string(p))
		}
		if strings.Join(got, " ") != w {
			t.Errorf("%s: %v, want %s", r, got, w)
		}
	}
}

// TestExpiredRoleAssignmentIgnored: an expired assignment confers nothing.
func TestExpiredRoleAssignmentIgnored(t *testing.T) {
	past := t0.Add(-time.Minute)
	got := auth.AssignedRoles([]*store.RoleAssignment{
		{Role: "viewer"}, {Role: "operator", ExpiresAt: &past}, {Role: "not-a-role"},
	}, t0)
	if len(got) != 1 || !got.Has(auth.RoleViewer) {
		t.Errorf("assigned %v", got)
	}
}

// TestTenantSettings: require_phr_for_all is read from the tenant's settings
// JSON; unreadable settings fail closed to the strictest floors.
func TestTenantSettings(t *testing.T) {
	for raw, want := range map[string]bool{
		"":                                    false,
		"{}":                                  false,
		`{"require_phr_for_all":false}`:       false,
		`{"require_phr_for_all":true}`:        true,
		`{"login_acr":"urn:tessera:acr:phr"}`: false,
		`{"require_phr_for_all":"yes"}`:       true,
		`not json`:                            true,
		`[]`:                                  true,
		`null`:                                true,
	} {
		if got := auth.TenantSettings(raw).RequirePhrForAll; got != want {
			t.Errorf("%q: require_phr_for_all %v, want %v", raw, got, want)
		}
	}
}
