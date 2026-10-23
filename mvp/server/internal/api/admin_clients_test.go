package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Machine clients through the real router (design §9.5, §16.1, §19 PR11): the
// read-only client list, a machine principal's permissions, and the routes a
// machine can never use.

// seedClient registers a machine client of the tenant, owned by a fresh user,
// with a fresh ES256 key; it returns the client's private key.
func seedClient(tb testing.TB, db *store.DB, tenant tenancy.ID, clientID, name string, opts ...func(*store.APIClient)) *ecdsa.PrivateKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	if err != nil {
		tb.Fatal(err)
	}
	_, jwks, err := oauth.ParseClientJWKS(raw)
	if err != nil {
		tb.Fatal(err)
	}
	owner := signIn(tb, db, tenant, authtest.User{Email: "owner-" + clientID + "@example.test", Roles: []auth.Role{auth.RoleViewer}},
		authtest.Phr, storetest.Now)
	c := &store.APIClient{ClientID: clientID, Name: name, Kind: store.ClientMachine, GrantTypes: []string{oauth.GrantClientCredentials},
		TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks, DPoPRequired: true, AllowedScopes: []string{"tessera:read"},
		Roles: []string{"viewer"}, OwnerUserID: &owner.UserID, CreatedAt: storetest.Now}
	for _, o := range opts {
		o(c)
	}
	if err := db.InTenant(context.Background(), tenant, func(tx *store.TenantTx) error { return tx.InsertAPIClient(c) }); err != nil {
		tb.Fatal(err)
	}
	return key
}

// TestAdminAPIClients: GET /api/admin/api-clients lists the tenant's clients
// with their public keys, for admin.read only.
func TestAdminAPIClients(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedClient(t, f.DB, f.A.ID, "tsc_client_a", "ETL "+storetest.Sentinel)
	seedClient(t, f.DB, f.B.ID, "tsc_client_b", "Nightly ETL", func(c *store.APIClient) {
		c.AllowedScopes, c.Roles, c.DPoPRequired = []string{"tessera:read", "tessera:audit"}, []string{"auditor"}, false
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		return oauth.EnsureCLIClient(tx, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	srv := newIsolationServer(f)
	h := srv.Handler()
	as := func(role auth.Role, path string) *httptest.ResponseRecorder {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		l.Apply(req)
		return serve(h, req)
	}
	rec := as(auth.RoleTenantAdmin, "/api/admin/api-clients")
	if rec.Code != 200 || leaks(rec.Body.String()) {
		t.Fatalf("list: %d %.300s", rec.Code, rec.Body)
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("want tenant B's CLI client and its machine client: %v %s", err, rec.Body)
	}
	byID := map[string]map[string]any{}
	for _, c := range list {
		byID[c["client_id"].(string)] = c
	}
	m := byID["tsc_client_b"]
	if m == nil || m["kind"] != "machine" || m["status"] != "active" || m["dpop_required"] != false || m["name"] != "Nightly ETL" ||
		m["token_endpoint_auth_method"] != "private_key_jwt" || m["owner_user_id"] == nil || m["last_used_at"] != nil {
		t.Fatalf("machine client: %v", m)
	}
	if fmt.Sprint(m["roles"]) != "[auditor]" || fmt.Sprint(m["allowed_scopes"]) != "[tessera:read tessera:audit]" ||
		fmt.Sprint(m["grant_types"]) != "[client_credentials]" {
		t.Errorf("roles, scopes or grants: %v", m)
	}
	ks, _ := m["keys"].([]any)
	if len(ks) != 1 || ks[0].(map[string]any)["kid"] != "k1" || ks[0].(map[string]any)["alg"] != "ES256" || ks[0].(map[string]any)["jkt"] == "" {
		t.Errorf("keys: %v", m["keys"])
	}
	for _, secret := range []string{`"d"`, "jwks", "secret", `"x"`, `"y"`} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the list contains %q: %s", secret, rec.Body)
		}
	}
	if cli := byID[oauth.CLIClientID]; cli == nil || cli["kind"] != "first_party_cli" || fmt.Sprint(cli["keys"]) != "[]" || cli["owner_user_id"] != nil {
		t.Errorf("CLI client: %v", cli)
	}

	// one client, by client_id
	rec = as(auth.RoleAuditor, "/api/admin/api-clients/tsc_client_b")
	var one map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &one) != nil || one["client_id"] != "tsc_client_b" {
		t.Errorf("get: %d %s", rec.Code, rec.Body)
	}
	// admin.read only: tenant_admin and auditor have it; the rest do not
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RolePolicyAdmin} {
		if rec := as(role, "/api/admin/api-clients"); rec.Code != 403 {
			t.Errorf("%s: %d %s", role, rec.Code, rec.Body)
		}
	}
	// the list route takes no PUT, PATCH or DELETE (creating is a POST, tested in TestAdminAPIClients_Manage)
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		l := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
		req := httptest.NewRequest(m, "/api/admin/api-clients", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		l.Apply(req)
		if rec := serve(h, req); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", m, rec.Code)
		}
	}
	if rec := serve(h, httptest.NewRequest(http.MethodGet, "/api/admin/api-clients", nil)); rec.Code != 401 {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

// TestAdminAPIClients_CrossTenant: tenant A's client_id, asked of as tenant B,
// answers exactly like one that does not exist, and B's list never shows A's.
func TestAdminAPIClients_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedClient(t, f.DB, f.A.ID, "tsc_client_a", "ETL "+storetest.Sentinel)
	seedClient(t, f.DB, f.B.ID, "tsc_client_b", "ETL B")
	h := isolationServer(t, f, f.B.ID).Handler()
	cross := serveOnce(h, http.MethodGet, "/api/admin/api-clients/tsc_client_a", "")
	missing := serveOnce(h, http.MethodGet, "/api/admin/api-clients/tsc_client_zz", "")
	if cross.Code != 404 || cross.Code != missing.Code || cross.Body.String() != missing.Body.String() || leaks(cross.Body.String()) {
		t.Errorf("A's client as B: %d %s; missing: %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
	if rec := serveOnce(h, http.MethodGet, "/api/admin/api-clients", ""); rec.Code != 200 || leaks(rec.Body.String()) ||
		strings.Contains(rec.Body.String(), "tsc_client_a") || !strings.Contains(rec.Body.String(), "tsc_client_b") {
		t.Errorf("B's list: %d %s", rec.Code, rec.Body)
	}
	if rec := serveOnce(h, http.MethodGet, "/api/admin/api-clients/"+strings.Repeat("a", 65), ""); rec.Code != 404 {
		t.Errorf("a client_id of 65 characters: %d", rec.Code)
	}
	// and as A, A's own client is there
	ha := isolationServer(t, f, f.A.ID).Handler()
	if rec := serveOnce(ha, http.MethodGet, "/api/admin/api-clients/tsc_client_a", ""); rec.Code != 200 {
		t.Errorf("A's client as A: %d %s", rec.Code, rec.Body)
	}
}

// ---------------------------------------------------------------- a machine principal at the router

// machineClient is a seeded machine client with its key.
type machineClient struct {
	id  string
	key *ecdsa.PrivateKey
}

// addMachine registers a machine client of slug in the environment.
func (e *oauthEnv) addMachine(slug string, roles, scopes []string, dpopRequired bool) machineClient {
	e.t.Helper()
	id := "tsc_" + strings.ToLower(seal.RandomSecret(16))[:12]
	key := seedClient(e.t, e.f.DB, e.tenants[slug], id, "ETL "+id, func(c *store.APIClient) {
		c.Roles, c.AllowedScopes, c.DPoPRequired = roles, scopes, dpopRequired
	})
	return machineClient{id: id, key: key}
}

func (e *oauthEnv) assertion(m machineClient, slug, endpoint string) string {
	e.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: m.key, KeyID: "k1"}}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	now := e.clock.Now()
	s, err := jwt.Signed(signer).Claims(map[string]any{"iss": m.id, "sub": m.id, "aud": publicBase + "/t/" + slug + "/oauth/" + endpoint,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "j_" + seal.RandomSecret(16)}).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// token gets a DPoP-bound access token for m (the proof key is a fresh one).
func (e *oauthEnv) machineToken(m machineClient, slug, scope string) cliTokens {
	e.t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	form := url.Values{"grant_type": {oauth.GrantClientCredentials}, "client_id": {m.id}, "scope": {scope},
		"client_assertion_type": {oauth.ClientAssertionType}, "client_assertion": {e.assertion(m, slug, "token")}}
	rec := e.tokenRequest(slug, form, k)
	if rec.Code != 200 {
		e.t.Fatalf("client credentials: %d %s", rec.Code, rec.Body)
	}
	return cliTokens{access: body(rec)["access_token"].(string), key: k}
}

// callBearer makes an API request with an unbound machine token.
func (e *oauthEnv) callBearer(token, method, path, jsonBody string) *httptest.ResponseRecorder {
	var req *http.Request
	if jsonBody != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return serve(e.h, req)
}

// TestMachinePrincipalRoutes: a machine client reaches the API with the
// permissions of its roles intersected with its scopes, is audited as an
// api_client with no session, and meets 403 wherever a human is needed.
func TestMachinePrincipalRoutes(t *testing.T) {
	e := newOAuthEnv(t)
	auditor := e.addMachine("tenant-a", []string{"auditor"}, []string{"tessera:read", "tessera:admin"}, true)
	op := e.addMachine("tenant-a", []string{"operator"}, []string{"tessera:read", "tessera:write"}, true)
	viewer := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read", "tessera:admin"}, true)
	aTok := e.machineToken(auditor, "tenant-a", "tessera:admin")
	opTok := e.machineToken(op, "tenant-a", "tessera:read tessera:write")
	viewTok := e.machineToken(viewer, "tenant-a", "")

	t.Run("roles intersect scopes", func(t *testing.T) {
		// auditor's role holds admin.read and the admin scope covers it
		if rec := e.call(aTok, "GET", "/api/admin/api-clients", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), auditor.id) {
			t.Errorf("auditor + admin scope: %d %.200s", rec.Code, rec.Body)
		}
		// the same role without a scope that covers graph.read is refused
		if rec := e.call(aTok, "GET", "/api/summary", ""); rec.Code != 403 || body(rec)["error"] != "forbidden" || body(rec)["permission"] != "graph.read" {
			t.Errorf("auditor, no read scope: %d %s", rec.Code, rec.Body)
		}
		// the viewer has the admin scope but not the role
		if rec := e.call(viewTok, "GET", "/api/admin/api-clients", ""); rec.Code != 403 {
			t.Errorf("viewer + admin scope: %d %s", rec.Code, rec.Body)
		}
		if rec := e.call(viewTok, "GET", "/api/summary", ""); rec.Code != 200 {
			t.Errorf("viewer reading: %d %s", rec.Code, rec.Body)
		}
		// the operator writes with a write scope, reads with a read scope
		if rec := e.call(opTok, "POST", "/api/jit/requests", `{"identity_id":1,"group_id":1,"justification":"x"}`); rec.Code == 401 || rec.Code == 403 {
			t.Errorf("operator write: %d %s", rec.Code, rec.Body)
		}
		if rec := e.call(opTok, "GET", "/api/summary", ""); rec.Code != 200 {
			t.Errorf("operator read: %d %s", rec.Code, rec.Body)
		}
		// a role the operator lacks stays out of reach, whatever the scope
		if rec := e.call(opTok, "POST", "/api/jit/sweep", `{}`); rec.Code != 403 {
			t.Errorf("sweep by an operator: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("step-up routes are 403 interactive_authentication_required", func(t *testing.T) {
		for _, c := range []struct{ method, path, body string }{
			{"POST", "/api/jit/requests/1/approve", `{}`},
			{"POST", "/api/reviews/items/1/decision", `{"decision":"keep"}`},
			{"POST", "/api/auth/device/approve", `{"user_code":"AAAA-BBBB","decision":"approve"}`},
			{"GET", "/api/auth/step-up?acr=urn:tessera:acr:phr&max_age=300&return_to=/", ""},
		} {
			rec := e.call(opTok, c.method, c.path, c.body)
			if rec.Code != 403 || body(rec)["error"] != "interactive_authentication_required" ||
				rec.Header().Get("WWW-Authenticate") != "" || body(rec)["step_up_url"] != nil {
				t.Errorf("%s %s: %d %s %q", c.method, c.path, rec.Code, rec.Body, rec.Header().Get("WWW-Authenticate"))
			}
		}
		// applying a revoke is decided in the handler: grants.revoke with step-up
		rec := e.call(opTok, "POST", "/api/least-privilege/revoke", `{"edge_id":1,"dry_run":false}`)
		if rec.Code != 403 {
			t.Errorf("applying a revoke: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("the session routes are for a signed-in user", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{"GET", "/api/auth/session"}, {"POST", "/api/auth/logout"}, {"GET", "/api/auth/sessions"},
			{"DELETE", "/api/auth/sessions/00000000-0000-4000-8000-00000000dead"},
		} {
			rec := e.call(opTok, c.method, c.path, "")
			if rec.Code != 403 || body(rec)["error"] != "interactive_authentication_required" {
				t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
			}
		}
	})
	t.Run("audited as the api_client, with no session", func(t *testing.T) {
		var found *store.AuditEvent
		for _, ev := range httpEvents(ledger(t, e.f.DB, e.f.A.ID)) {
			if strings.Contains(string(ev.HTTP), `"/api/summary"`) && ev.ActorID != nil && *ev.ActorID == viewer.id && ev.Outcome == store.OutcomeSuccess {
				found = ev
				break
			}
		}
		if found == nil || found.ActorType != store.ActorAPIClient || found.ClientID == nil || *found.ClientID != viewer.id ||
			found.SessionID != nil || len(found.Authn) != 0 {
			t.Fatalf("event: %+v", found)
		}
		if strings.Contains(string(found.Detail), viewTok.access) || strings.Contains(string(found.HTTP), "DPoP") {
			t.Error("the event records a credential")
		}
		// the denied step-up call is recorded as the client too
		for _, ev := range httpEvents(ledger(t, e.f.DB, e.f.A.ID)) {
			if strings.Contains(string(ev.HTTP), "/approve") && ev.ActorType == store.ActorAPIClient && ev.Outcome == store.OutcomeDenied {
				return
			}
		}
		t.Error("the refused approval is not audited as denied, by the api_client")
	})
	t.Run("a token never crosses tenants", func(t *testing.T) {
		// the principal's tenant is its token's: A's token sees A's data (the
		// positive control), B's token never does
		if rec := e.call(viewTok, "GET", "/api/identities", ""); rec.Code != 200 || !leaks(rec.Body.String()) {
			t.Errorf("tenant A's token does not see tenant A's data: %d", rec.Code)
		}
		b := e.addMachine("tenant-b", []string{"auditor", "viewer"}, []string{"tessera:admin", "tessera:read"}, true)
		bTok := e.machineToken(b, "tenant-b", "")
		if rec := e.call(bTok, "GET", "/api/identities", ""); rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("tenant B's token and tenant A's data: %d", rec.Code)
		}
		rec := e.call(bTok, "GET", "/api/admin/api-clients", "")
		if rec.Code != 200 || strings.Contains(rec.Body.String(), auditor.id) || !strings.Contains(rec.Body.String(), b.id) {
			t.Errorf("tenant B's client list: %d %s", rec.Code, rec.Body)
		}
		// a token of A with the client_id of B's client is not B's: the client is looked up in the token's tenant
		if rec := e.call(bTok, "GET", "/api/admin/api-clients/"+auditor.id, ""); rec.Code != 404 {
			t.Errorf("A's client asked of as B: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("an unbound token is Bearer-only and for a client that is not DPoP-required", func(t *testing.T) {
		nb := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, false)
		form := url.Values{"grant_type": {oauth.GrantClientCredentials}, "client_id": {nb.id},
			"client_assertion_type": {oauth.ClientAssertionType}, "client_assertion": {e.assertion(nb, "tenant-a", "token")}}
		rec := e.form("tenant-a", "token", form, nil)
		b := body(rec)
		if rec.Code != 200 || b["token_type"] != "Bearer" || b["refresh_token"] != nil {
			t.Fatalf("token: %d %s", rec.Code, rec.Body)
		}
		tok := b["access_token"].(string)
		if rec := e.callBearer(tok, "GET", "/api/summary", ""); rec.Code != 200 {
			t.Errorf("Bearer: %d %s", rec.Code, rec.Body)
		}
		// a write needs no CSRF token and no JSON-less shortcut: a body still has to be JSON
		if rec := e.callBearer(tok, "POST", "/api/jit/requests", `{"identity_id":1}`); rec.Code != 403 {
			t.Errorf("Bearer write without the role: %d %s", rec.Code, rec.Body)
		}
		// a DPoP-required client's token is not usable as Bearer
		if rec := e.callBearer(opTok.access, "GET", "/api/summary", ""); rec.Code != 401 {
			t.Errorf("a DPoP-bound token as Bearer: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("introspection through the router is public and audited", func(t *testing.T) {
		gw := e.addMachine("tenant-a", nil, []string{oauth.ScopeIntrospect}, true)
		before := len(httpEvents(ledger(t, e.f.DB, e.f.A.ID)))
		rec := e.form("tenant-a", "introspect", url.Values{"client_id": {gw.id}, "token": {opTok.access},
			"client_assertion_type": {oauth.ClientAssertionType}, "client_assertion": {e.assertion(gw, "tenant-a", "introspect")}}, nil)
		b := body(rec)
		if rec.Code != 200 || b["active"] != true || b["client_id"] != op.id || b["scope"] != "tessera:read tessera:write" {
			t.Fatalf("introspect: %d %s", rec.Code, rec.Body)
		}
		evs := httpEvents(ledger(t, e.f.DB, e.f.A.ID))
		if len(evs) != before+1 || !strings.Contains(string(evs[0].HTTP), "/t/{slug}/oauth/introspect") {
			t.Errorf("want one more http.request event for the introspection, have %d (was %d)", len(evs), before)
		}
		// no client authentication: 401 invalid_client, still one event
		before = len(httpEvents(ledger(t, e.f.DB, e.f.A.ID)))
		rec = e.form("tenant-a", "introspect", url.Values{"token": {opTok.access}, "client_id": {gw.id},
			"client_assertion_type": {oauth.ClientAssertionType}, "client_assertion": {"x.y.z"}}, nil)
		if rec.Code != 401 || body(rec)["error"] != "invalid_client" || len(httpEvents(ledger(t, e.f.DB, e.f.A.ID))) != before+1 {
			t.Errorf("bad assertion: %d %s", rec.Code, rec.Body)
		}
	})
}

// pubJWKS is a one-key public key set with the given kid.
func pubJWKS(t *testing.T, kid string) json.RawMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestAdminAPIClients_Manage: creating a machine client, adding and replacing its keys, and revoking it need an admin
// with a fresh passkey sign-in; none of it can grant the admin scope or role, accept a private key, or touch the CLI
// client or another tenant's client; each change is audited without key material.
func TestAdminAPIClients_Manage(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedClient(t, f.DB, f.A.ID, "tsc_client_a", "ETL A")
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error { return oauth.EnsureCLIClient(tx, storetest.Now) }); err != nil {
		t.Fatal(err)
	}
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now)
	owner := signIn(t, f.DB, f.B.ID, authtest.User{Email: "owner@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	_ = owner
	do := func(l authtest.Login, method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		return reqDo(h, l, method, path, string(raw))
	}
	create := func(m map[string]any) map[string]any {
		base := map[string]any{"name": "Nightly ETL", "owner": "owner@b.example", "scopes": []string{"tessera:read"}, "roles": []string{"viewer"}, "jwks": pubJWKS(t, "k1")}
		for k, v := range m {
			base[k] = v
		}
		return base
	}

	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAuditor, auth.RolePolicyAdmin} {
		l := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, now)
		if rec := do(l, "POST", "/api/admin/api-clients", create(nil)); rec.Code != 403 {
			t.Errorf("%s creates a client: %d", role, rec.Code)
		}
	}
	if rec := do(stale, "POST", "/api/admin/api-clients", create(nil)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	for name, body := range map[string]map[string]any{
		"the admin scope":       create(map[string]any{"scopes": []string{"tessera:read", "tessera:admin"}}),
		"no scope":              create(map[string]any{"scopes": []string{}}),
		"an unknown scope":      create(map[string]any{"scopes": []string{"root"}}),
		"the tenant_admin role": create(map[string]any{"roles": []string{"tenant_admin"}}),
		"no role":               create(map[string]any{"roles": []string{}}),
		"no name":               create(map[string]any{"name": " "}),
		"no owner":              create(map[string]any{"owner": ""}),
		"an unknown owner":      create(map[string]any{"owner": "nobody@b.example"}),
		"another tenant's user": create(map[string]any{"owner": "owner-tsc_client_a@example.test"}),
		"no keys":               create(map[string]any{"jwks": json.RawMessage(`{"keys":[]}`)}),
		"an unknown field":      create(map[string]any{"password": "x"}),
	} {
		if rec := do(admin, "POST", "/api/admin/api-clients", body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// a private key is refused, and never echoed
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: priv, KeyID: "p1", Algorithm: "ES256"}}})
	if rec := do(admin, "POST", "/api/admin/api-clients", create(map[string]any{"jwks": json.RawMessage(privSet)})); rec.Code != 422 || strings.Contains(rec.Body.String(), `"d"`) {
		t.Errorf("a private key: %d %s", rec.Code, rec.Body)
	}

	rec := do(admin, "POST", "/api/admin/api-clients", create(map[string]any{"scopes": []string{"tessera:read", "tessera:audit", "tessera:read"}, "roles": []string{"auditor"}}))
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var c map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	id, _ := c["client_id"].(string)
	if !strings.HasPrefix(id, "tsc_") || c["kind"] != "machine" || c["status"] != "active" || c["dpop_required"] != true || c["last_used_at"] != nil ||
		fmt.Sprint(c["allowed_scopes"]) != "[tessera:read tessera:audit]" || fmt.Sprint(c["roles"]) != "[auditor]" || c["owner_user_id"] == nil {
		t.Fatalf("created client = %v", c)
	}
	if ks, _ := c["keys"].([]any); len(ks) != 1 || ks[0].(map[string]any)["kid"] != "k1" {
		t.Errorf("keys = %v", c["keys"])
	}
	keys := func() []any {
		rec := do(admin, "GET", "/api/admin/api-clients/"+id, nil)
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		ks, _ := v["keys"].([]any)
		return ks
	}
	// add a second key for the overlap, then replace the set
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/keys", map[string]any{"mode": "add", "jwks": pubJWKS(t, "k1")}); rec.Code != 422 || !strings.Contains(rec.Body.String(), "already registered") {
		t.Errorf("a kid that is already there: %d %s", rec.Code, rec.Body)
	}
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/keys", map[string]any{"mode": "swap", "jwks": pubJWKS(t, "k2")}); rec.Code != 422 {
		t.Errorf("a bad mode: %d", rec.Code)
	}
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/keys", map[string]any{"mode": "add", "jwks": pubJWKS(t, "k2")}); rec.Code != 200 {
		t.Fatalf("add key: %d %s", rec.Code, rec.Body)
	}
	if ks := keys(); len(ks) != 2 {
		t.Errorf("keys after add = %v", ks)
	}
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/keys", map[string]any{"mode": "replace", "jwks": pubJWKS(t, "k3")}); rec.Code != 200 {
		t.Fatalf("replace keys: %d %s", rec.Code, rec.Body)
	}
	if ks := keys(); len(ks) != 1 || ks[0].(map[string]any)["kid"] != "k3" {
		t.Errorf("keys after replace = %v", ks)
	}
	// revoke
	if rec := do(stale, "POST", "/api/admin/api-clients/"+id+"/revoke", map[string]any{}); rec.Code != 401 {
		t.Errorf("stale revoke: %d", rec.Code)
	}
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/revoke", map[string]any{}); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"disabled"`) {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := do(admin, "POST", "/api/admin/api-clients/"+id+"/revoke", map[string]any{}); rec.Code != 409 {
		t.Errorf("revoke twice: %d", rec.Code)
	}
	// the CLI client and another tenant's client are out of reach, exactly like one that does not exist
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, target := range []string{oauth.CLIClientID, "tsc_client_a", "tsc_nope"} {
		for _, path := range []string{"/keys", "/revoke"} {
			body := map[string]any{}
			if path == "/keys" {
				body = map[string]any{"mode": "replace", "jwks": pubJWKS(t, "x")}
			}
			rec := do(admin, "POST", "/api/admin/api-clients/"+target+path, body)
			if rec.Code != 404 {
				t.Errorf("%s%s: %d %s", target, path, rec.Code, rec.Body)
			}
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	// the audit log names each change and carries no key material
	got := map[string]int{}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			if strings.HasPrefix(e.Action, "oauth.client.") {
				got[e.Action]++
				if d := string(e.Detail); strings.Contains(d, `"x"`) || strings.Contains(d, `"y"`) || strings.Contains(d, "jwks") || !strings.Contains(d, id) {
					t.Errorf("%s detail = %s", e.Action, d)
				}
			}
		}
		return err
	})
	if got["oauth.client.created"] != 1 || got["oauth.client.keys_rotated"] != 2 || got["oauth.client.revoked"] != 1 {
		t.Errorf("audit = %v", got)
	}
}
