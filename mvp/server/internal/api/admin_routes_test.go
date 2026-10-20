package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Admin API tests (design §15.2, §16.1): the routes of admin_routes.go over
// the two-tenant fixture, with a clock the test moves.

type adminEnv struct {
	f   *storetest.Fixture
	now time.Time
	srv *Server
	h   http.Handler
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	e := &adminEnv{f: f, now: storetest.Now}
	e.srv = New(Config{Store: f.DB, Clock: func() time.Time { return e.now }, Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{authtest.Origin}, Env: "test",
		RateLimits: noRateLimits, Sealer: sealer})
	e.h = e.srv.Handler()
	return e
}

// login signs the user in to tenant, with a phishing-resistant sign-in age ago.
func (e *adminEnv) login(t *testing.T, tenant storetest.Tenant, email string, age time.Duration, roles ...auth.Role) authtest.Login {
	t.Helper()
	return signIn(t, e.f.DB, tenant.ID, authtest.User{Email: email, Display: strings.Split(email, "@")[0], Roles: roles},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: e.now.Add(-age)}, e.now)
}

func (e *adminEnv) call(l authtest.Login, method, path, body string) (int, map[string]any, string) {
	rec := serve(e.h, authed(l, method, path, body))
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v) // not JSON (a 500): v stays nil and the status says it
	return rec.Code, v, rec.Body.String()
}

func (e *adminEnv) mustCall(t *testing.T, l authtest.Login, method, path, body string, want int) map[string]any {
	t.Helper()
	code, v, raw := e.call(l, method, path, body)
	if code != want {
		t.Fatalf("%s %s: %d %s, want %d", method, path, code, raw, want)
	}
	return v
}

func asString(v any) string { s, _ := v.(string); return s }

// TestAdminAPI_ChangeFlow: submit, list, read, refuse the requester's own
// approval, a missing or wrong hash, and a stale step-up, approve, refuse an
// early apply (409), then apply after the cooling-off.
func TestAdminAPI_ChangeFlow(t *testing.T) {
	e := newAdminEnv(t)
	b := e.f.B
	a1 := e.login(t, b, "ada@b.example", 0, auth.RoleTenantAdmin)
	a2 := e.login(t, b, "ben@b.example", 0, auth.RoleTenantAdmin)
	target := e.login(t, b, "tess@b.example", 0, auth.RoleViewer)
	body := fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"policy_admin"}}`, target.UserID)

	// a viewer cannot submit; an unknown type and an unknown payload field are 422
	e.mustCall(t, target, "POST", "/api/admin/change-requests", body, http.StatusForbidden)
	e.mustCall(t, a1, "POST", "/api/admin/change-requests", `{"type":"role.promote","payload":{}}`, http.StatusUnprocessableEntity)
	e.mustCall(t, a1, "POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"viewer","x":1}}`, target.UserID), http.StatusUnprocessableEntity)
	e.mustCall(t, a1, "POST", "/api/admin/change-requests", `{"type":"role.grant"}`, http.StatusUnprocessableEntity)
	e.mustCall(t, a1, "POST", "/api/admin/change-requests", `{"type":"role.grant","payload":{},"extra":true}`, http.StatusUnprocessableEntity)

	created := e.mustCall(t, a1, "POST", "/api/admin/change-requests", body, http.StatusCreated)
	id, hash := asString(created["id"]), asString(created["payload_hash"])
	if created["status"] != "pending_approval" || created["two_person"] != true || len(hash) != 64 || id == "" ||
		!strings.Contains(asString(created["summary"]), "Grant policy_admin to tess") {
		t.Fatalf("created request: %v", created)
	}
	list := e.mustCall(t, a2, "GET", "/api/admin/change-requests?status=open", "", http.StatusOK)
	if rows, _ := list["change_requests"].([]any); len(rows) != 1 {
		t.Fatalf("open requests: %v", list)
	}
	e.mustCall(t, a2, "GET", "/api/admin/change-requests?status=bogus", "", http.StatusUnprocessableEntity)
	one := e.mustCall(t, a2, "GET", "/api/admin/change-requests/"+id, "", http.StatusOK)
	if ns, _ := one["notifications"].([]any); len(ns) != 2 { // the two admins
		t.Errorf("notifications of the new request: %v", one["notifications"])
	}

	// the requester cannot approve; a missing or wrong hash does not approve
	if code, v, _ := e.call(a1, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)); code != 403 || v["error"] != "self_approval_refused" {
		t.Errorf("self approval: %d %v", code, v)
	}
	e.mustCall(t, a2, "POST", "/api/admin/change-requests/"+id+"/approve", `{}`, http.StatusUnprocessableEntity)
	if code, v, _ := e.call(a2, "POST", "/api/admin/change-requests/"+id+"/approve", `{"payload_hash":"`+strings.Repeat("a", 64)+`"}`); code != 409 || v["error"] != "payload_hash_mismatch" {
		t.Errorf("wrong hash: %d %v", code, v)
	}
	// a sign-in older than five minutes needs a step-up, with the RFC 9470 challenge
	stale := e.login(t, b, "ben@b.example", 10*time.Minute)
	rec := serve(e.h, authed(stale, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash)))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "step_up_required") ||
		!strings.Contains(rec.Header().Get("WWW-Authenticate"), "insufficient_user_authentication") ||
		!strings.Contains(rec.Body.String(), `"max_age":300`) {
		t.Errorf("stale approval: %d %s %s", rec.Code, rec.Body.String(), rec.Header().Get("WWW-Authenticate"))
	}
	approved := e.mustCall(t, a2, "POST", "/api/admin/change-requests/"+id+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, hash), http.StatusOK)
	if approved["status"] != "cooling_off" || approved["effective_at"] == nil {
		t.Fatalf("approved request: %v", approved)
	}
	if code, v, _ := e.call(a2, "POST", "/api/admin/change-requests/"+id+"/apply", ""); code != 409 || v["error"] != "cooling_off_active" {
		t.Errorf("early apply: %d %v", code, v)
	}
	e.now = e.now.Add(24 * time.Hour)
	a2 = e.login(t, b, "ben@b.example", 0, auth.RoleTenantAdmin)
	applied := e.mustCall(t, a2, "POST", "/api/admin/change-requests/"+id+"/apply", "", http.StatusOK)
	if applied["status"] != "applied" {
		t.Fatalf("applied request: %v", applied)
	}
	users := e.mustCall(t, a2, "GET", "/api/admin/users", "", http.StatusOK)
	found := false
	for _, u := range users["users"].([]any) {
		um := u.(map[string]any)
		if um["email"] == "tess@b.example" {
			for _, r := range um["roles"].([]any) {
				found = found || r.(map[string]any)["role"] == "policy_admin"
			}
		}
	}
	if !found {
		t.Errorf("the target does not hold policy_admin after the change applied: %v", users)
	}

	// a cancel during the cooling-off (sessions idle out after 15 minutes: sign in again)
	a1 = e.login(t, b, "ada@b.example", 0, auth.RoleTenantAdmin)
	two := e.mustCall(t, a1, "POST", "/api/admin/change-requests", fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"tenant_admin"}}`, target.UserID), http.StatusCreated)
	e.mustCall(t, e.login(t, b, "ben@b.example", 0), "POST", "/api/admin/change-requests/"+asString(two["id"])+"/cancel", "", http.StatusOK)
	if code, v, _ := e.call(a1, "POST", "/api/admin/change-requests/"+asString(two["id"])+"/cancel", ""); code != 409 || v["error"] != "invalid_state" {
		t.Errorf("second cancel: %d %v", code, v)
	}
	// notifications of the workflow are listed
	ns := e.mustCall(t, a1, "GET", "/api/admin/notifications", "", http.StatusOK)
	if rows, _ := ns["notifications"].([]any); len(rows) < 6 {
		t.Errorf("%d admin notifications listed, want one per recipient per transition", len(rows))
	}
}

// TestAdminAPI_ClientSecretNeverReturned: the client secret of a requested
// connection is sealed; no response, payload or list ever shows it.
func TestAdminAPI_ClientSecretNeverReturned(t *testing.T) {
	e := newAdminEnv(t)
	b := e.f.B
	a1 := e.login(t, b, "ada@b.example", 0, auth.RoleTenantAdmin)
	e.login(t, b, "ben@b.example", 0, auth.RoleTenantAdmin)
	const secret = "very-secret-client-secret-value"
	payload := `{"type":"idp_connection.create","client_secret":"` + secret + `","payload":{"name":"Okta","protocol":"oidc","profile":"okta","issuer":"https://acme.okta.example","client_id":"cid"}}`
	code, _, raw := e.call(a1, "POST", "/api/admin/change-requests", payload)
	if code != http.StatusCreated || strings.Contains(raw, secret) {
		t.Fatalf("create: %d, leaks the secret: %t", code, strings.Contains(raw, secret))
	}
	for _, p := range []string{"/api/admin/change-requests", "/api/admin/change-requests?status=open", "/api/admin/notifications", "/api/admin/idp-connections"} {
		if _, _, raw := e.call(a1, "GET", p, ""); strings.Contains(raw, secret) || strings.Contains(raw, "secret_enc") {
			t.Errorf("GET %s leaks the secret: %.200s", p, raw)
		}
	}
	// a secret inside the payload is an unknown field
	e.mustCall(t, a1, "POST", "/api/admin/change-requests", `{"type":"idp_connection.create","payload":{"name":"Okta","protocol":"oidc","profile":"okta","issuer":"https://acme.okta.example","client_id":"cid","client_secret":"x"}}`, http.StatusUnprocessableEntity)
}

// TestAdminAPI_CrossTenant: as tenant B, every admin route given tenant A's
// ids answers exactly as for ids that exist nowhere (404, same body), never
// 200 or 403, never A's data, and A is left untouched.
func TestAdminAPI_CrossTenant(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.f.A, e.f.B
	aliceA := e.login(t, a, "zz-larkspur-sentinel-admin@a.example", 0, auth.RoleTenantAdmin)
	e.login(t, a, "zz-larkspur-sentinel-second@a.example", 0, auth.RoleTenantAdmin)
	targetA := e.login(t, a, "zz-larkspur-sentinel-target@a.example", 0, auth.RoleViewer)
	adminB := e.login(t, b, "ben@b.example", 0, auth.RoleTenantAdmin)
	e.login(t, b, "bea@b.example", 0, auth.RoleTenantAdmin)

	created := e.mustCall(t, aliceA, "POST", "/api/admin/change-requests",
		fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"policy_admin"}}`, targetA.UserID), http.StatusCreated)
	changeA := asString(created["id"])
	var connA, recA, invA uuid.UUID
	err := e.f.DB.InTenant(context.Background(), a.ID, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		if err != nil || len(cs) == 0 {
			iss, cid := "https://a.okta.example", "c"
			c := &store.IdPConnection{Name: "zz-larkspur-sentinel-conn", Protocol: "oidc", Profile: store.ProfileOkta,
				Status: "active", Issuer: &iss, ClientID: &cid, CreatedAt: e.now, UpdatedAt: e.now}
			if err := tx.InsertIdPConnection(c); err != nil {
				return err
			}
			connA = c.ID
		} else {
			connA = cs[0].ID
		}
		inv := &store.BootstrapInvitation{CodeHash: strings.Repeat("c", 64), IdPConnectionID: connA, Email: "x@a.example",
			CreatedBy: "op", CreatedAt: e.now, ExpiresAt: e.now.Add(100 * time.Hour)}
		if err := tx.InsertBootstrapInvitation(inv); err != nil {
			return err
		}
		invA = inv.ID
		rec := &store.TenantRecovery{InvitationID: inv.ID, Operator: "op-1", CoOperator: "op-2", Ticket: "T",
			NotBefore: e.now.Add(72 * time.Hour), CreatedAt: e.now}
		if err := tx.InsertTenantRecovery(rec); err != nil {
			return err
		}
		recA = rec.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = invA
	// positive control: A sees its own (before the snapshot: a read is audited too)
	if _, _, raw := e.call(aliceA, "GET", "/api/admin/change-requests", ""); !strings.Contains(raw, changeA) {
		t.Error("tenant A does not see its own change request")
	}
	beforeA := storetest.Dump(t, e.f.DB, a.ID)
	missing := "00000000-0000-4000-8000-00000000dead"
	for name, tc := range map[string]struct {
		method, path, body string
		idA                string
	}{
		"read change":     {"GET", "/api/admin/change-requests/%s", "", changeA},
		"approve change":  {"POST", "/api/admin/change-requests/%s/approve", `{"payload_hash":"` + strings.Repeat("a", 64) + `"}`, changeA},
		"reject change":   {"POST", "/api/admin/change-requests/%s/reject", "", changeA},
		"cancel change":   {"POST", "/api/admin/change-requests/%s/cancel", "", changeA},
		"apply change":    {"POST", "/api/admin/change-requests/%s/apply", "", changeA},
		"disable user":    {"POST", "/api/admin/users/%s/disable", `{"reason":"cross tenant"}`, targetA.UserID.String()},
		"activate conn":   {"POST", "/api/admin/idp-connections/%s/activate", "", connA.String()},
		"cancel recovery": {"POST", "/api/admin/recovery/%s/cancel", "", recA.String()},
	} {
		t.Run(name, func(t *testing.T) {
			cross := serve(e.h, authed(adminB, tc.method, fmt.Sprintf(tc.path, tc.idA), tc.body))
			miss := serve(e.h, authed(adminB, tc.method, fmt.Sprintf(tc.path, missing), tc.body))
			if cross.Code == 200 || cross.Code == 403 || leaks(cross.Body.String()) {
				t.Errorf("tenant A's id: %d %.200s", cross.Code, cross.Body.String())
			}
			if cross.Code != miss.Code || cross.Body.String() != miss.Body.String() {
				t.Errorf("tenant A's id is distinguishable from a missing one:\n A: %d %s\n missing: %d %s",
					cross.Code, cross.Body.String(), miss.Code, miss.Body.String())
			}
		})
	}
	// a request in B that names A's user, or A's connection, is "no such user/connection"
	for name, body := range map[string]string{
		"grant to A's user":  fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"policy_admin"}}`, targetA.UserID),
		"revoke from A's":    fmt.Sprintf(`{"type":"role.revoke","payload":{"user_id":%q,"role":"viewer"}}`, targetA.UserID),
		"A's connection":     fmt.Sprintf(`{"type":"idp_connection.disable","payload":{"connection_id":%q}}`, connA),
		"A's trust change":   fmt.Sprintf(`{"type":"idp_connection.update_trust","payload":{"connection_id":%q,"client_id":"x"}}`, connA),
		"A's cosmetic":       fmt.Sprintf(`{"type":"idp_connection.update_cosmetic","payload":{"connection_id":%q,"name":"x"}}`, connA),
		"missing user":       fmt.Sprintf(`{"type":"role.grant","payload":{"user_id":%q,"role":"policy_admin"}}`, missing),
		"missing connection": fmt.Sprintf(`{"type":"idp_connection.disable","payload":{"connection_id":%q}}`, missing),
	} {
		code, _, raw := e.call(adminB, "POST", "/api/admin/change-requests", body)
		if code != http.StatusNotFound || leaks(raw) || strings.Contains(raw, connA.String()) {
			t.Errorf("%s: %d %s, want 404", name, code, raw)
		}
	}
	// lists in B never show A's rows
	for _, p := range []string{"/api/admin/users", "/api/admin/idp-connections", "/api/admin/change-requests", "/api/admin/change-requests?status=open",
		"/api/admin/notifications", "/api/admin/recovery", "/api/admin/api-clients"} {
		code, _, raw := e.call(adminB, "GET", p, "")
		if code != http.StatusOK || leaks(raw) || strings.Contains(raw, changeA) || strings.Contains(raw, recA.String()) {
			t.Errorf("GET %s as B: %d, leaks A's data: %.300s", p, code, raw)
		}
	}
	if storetest.Dump(t, e.f.DB, a.ID) != beforeA {
		t.Error("calls made as tenant B changed tenant A")
	}
}

// TestAdminAPI_RecoveryRoutes: a tenant in operator recovery keeps signing
// its admins in; they see the recovery and cancel it; the recovery invitation
// is refused before not_before and after the cancel, with the reason audited.
func TestAdminAPI_RecoveryRoutes(t *testing.T) {
	e := newAdminEnv(t)
	b := e.f.B
	adminB := e.login(t, b, "ben@b.example", 0, auth.RoleTenantAdmin)
	viewer := e.login(t, b, "vic@b.example", 0, auth.RoleViewer)
	var conn uuid.UUID
	if err := e.f.DB.InTenant(context.Background(), b.ID, func(tx *store.TenantTx) error {
		iss, cid := "https://b.okta.example", "c"
		c := &store.IdPConnection{Name: "okta", Protocol: "oidc", Profile: store.ProfileOkta, Status: "active", Issuer: &iss,
			ClientID: &cid, CreatedAt: e.now, UpdatedAt: e.now}
		if err := tx.InsertIdPConnection(c); err != nil {
			return err
		}
		conn = c.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc := &admin.Service{DB: e.f.DB, Clock: func() time.Time { return e.now }}
	res, err := svc.RequestRecovery(context.Background(), admin.RecoveryRequest{Tenant: b.ID,
		Operator: admin.Operator{ID: "op-1", PhishingResistant: true}, CoOperator: admin.Operator{ID: "op-2", PhishingResistant: true},
		Ticket: "SUP-1", ConnectionID: conn, Email: "new@b.example"})
	if err != nil {
		t.Fatal(err)
	}
	// the invitation before not_before: refused, with the reason in the audit event
	redeem := func() string {
		rec := serve(e.srv.Handler(), httptest.NewRequest("GET", "/t/"+b.Slug+"/bootstrap?code="+res.Code, nil))
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?error=login_failed") {
			t.Fatalf("redeem: %d %s", rec.Code, rec.Header().Get("Location"))
		}
		evs := ledger(t, e.f.DB, b.ID)
		for _, ev := range evs {
			if ev.Action == "auth.login.failure" {
				return string(ev.Detail)
			}
		}
		return ""
	}
	if got := redeem(); !strings.Contains(got, admin.ReasonRecoveryNotYet) {
		t.Errorf("redeeming before not_before: audit detail %q, want %s", got, admin.ReasonRecoveryNotYet)
	}
	// the tenant is in recovery, yet its admins still work and see the recovery
	list := e.mustCall(t, adminB, "GET", "/api/admin/recovery", "", http.StatusOK)
	rows, _ := list["recoveries"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["status"] != "pending" {
		t.Fatalf("recoveries: %v", list)
	}
	id := asString(rows[0].(map[string]any)["id"])
	e.mustCall(t, viewer, "POST", "/api/admin/recovery/"+id+"/cancel", "", http.StatusForbidden)
	cancelled := e.mustCall(t, adminB, "POST", "/api/admin/recovery/"+id+"/cancel", "", http.StatusOK)
	if cancelled["status"] != "cancelled" {
		t.Fatalf("cancelled recovery: %v", cancelled)
	}
	e.mustCall(t, adminB, "POST", "/api/admin/recovery/"+id+"/cancel", "", http.StatusConflict)
	// after not_before the cancelled recovery's invitation is still refused
	e.now = e.now.Add(80 * time.Hour)
	rec := serve(e.srv.Handler(), httptest.NewRequest("GET", "/t/"+b.Slug+"/bootstrap?code="+res.Code, nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?error=login_failed") {
		t.Fatalf("redeem after the cancel: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var reasons []string
	for _, ev := range ledger(t, e.f.DB, b.ID) {
		if ev.Action == "auth.login.failure" {
			reasons = append(reasons, string(ev.Detail))
		}
	}
	if len(reasons) != 2 || !(strings.Contains(reasons[0], "bootstrap_code_used") || strings.Contains(reasons[0], admin.ReasonRecoveryClosed)) {
		t.Errorf("failure reasons %v, want the first (newest) refusal to say the code is used or the recovery is not pending", reasons)
	}
}
