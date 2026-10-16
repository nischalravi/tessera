package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/mcpauth"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

const (
	mcpPublic   = "https://tessera.example"
	mcpClientID = "https://client.example/agent.json"
	mcpRedirect = "https://client.example/cb"
	mcpVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

type mcpRes struct{ id, uri, secret string }

// mcpFx is tenant B of the two-tenant fixture (main) with the MCP authorization
// server configured; tenant A (other) is the neighbour. Tenant A's resource
// names carry the fixture's sentinel, which has spaces and so no scope name,
// which is why the server runs on B: a client bound to helper-bot, two resource servers, alice
// signed in (linked to her identity) and a policy administrator.
type mcpFx struct {
	t       *testing.T
	f       *storetest.Fixture
	main    storetest.Tenant
	other   storetest.Tenant
	srv     *Server
	h       http.Handler
	base    string // /t/tenant-b
	issuer  string
	alice   authtest.Login
	admin   authtest.Login
	aliceID int64
	botID   int64
	key     *ecdsa.PrivateKey
	resA    mcpRes
	resB    mcpRes
	shared  string
	hc      *http.Client
}

func newMCPFx(t *testing.T, limits RateLimits) *mcpFx {
	t.Helper()
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	x := &mcpFx{t: t, f: f, main: f.B, other: f.A, base: "/t/" + f.B.Slug, issuer: mcpPublic + "/t/" + f.B.Slug, aliceID: f.B.IDs["alice"],
		botID: f.B.IDs["helper-bot"], shared: "snowflake:SELECT:snowflake/CUSTOMERS", hc: hc}
	if x.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &x.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := keys.EnsureKeys(c, f.B.Slug, sealer, storetest.Now); err != nil {
			return err
		}
		// alice joins PII_READER: she and the bot share SELECT on CUSTOMERS
		if _, err := c.InsertEdge(&store.GrantEdge{Src: graph.Key("account", f.B.IDs["acct:okta:alice"]),
			Dst: graph.Key("group", f.B.IDs["group:snowflake:PII_READER"]), Relation: "member_of", Source: "manual", CreatedAt: storetest.Now}); err != nil {
			return err
		}
		cl := &store.MCPClient{ClientID: mcpClientID, Name: "Agent Host", RedirectURIs: `["` + mcpRedirect + `"]`, JWKS: string(jwks),
			DocSHA256: strings.Repeat("0", 64), ExpiresAt: storetest.Now.Add(1000 * time.Hour)}
		if err := c.UpsertMCPClient(cl, storetest.Now); err != nil {
			return err
		}
		return c.SetMCPClient(mcpClientID, &x.botID, "active", storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	x.srv = New(Config{
		Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", RateLimits: limits,
		AllowedOrigins: []string{"http://localhost:5173"}, PublicURL: mcpPublic, Sealer: sealer, OutboundHTTP: hc,
	})
	x.h = x.srv.Handler()
	x.alice = signIn(t, f.DB, f.B.ID, authtest.User{Email: "alice@a.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &x.aliceID},
		authtest.Phr, storetest.Now)
	x.admin = signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	x.resA = x.createResource("https://mcp-a.example/mcp", "mcp a")
	x.resB = x.createResource("https://mcp-b.example/mcp", "mcp b")
	return x
}

func (x *mcpFx) createResource(uri, name string) mcpRes {
	x.t.Helper()
	rec := corrDo(x.h, x.admin, "POST", "/api/mcp/resources", fmt.Sprintf(`{"resource":%q,"name":%q}`, uri, name))
	var v resourceView
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &v) != nil || v.Secret == "" {
		x.t.Fatalf("create resource: %d %s", rec.Code, rec.Body)
	}
	return mcpRes{v.ID, uri, v.Secret}
}

func form(h http.Handler, path string, v url.Values, basic ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	return serve(h, req)
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %d %s", rec.Code, rec.Body)
	}
	return m
}

func (x *mcpFx) authorizeURL(mod func(q url.Values)) string {
	q := url.Values{"response_type": {"code"}, "client_id": {mcpClientID}, "redirect_uri": {mcpRedirect}, "state": {"st-1"},
		"code_challenge": {mcpauth.ChallengeS256(mcpVerifier)}, "code_challenge_method": {"S256"}, "resource": {x.resA.uri},
		"scope": {x.shared}}
	if mod != nil {
		mod(q)
	}
	return x.base + "/oauth/authorize?" + q.Encode()
}

// userToken walks the browser flow (authorize, consent, code exchange) and
// returns the token response.
func (x *mcpFx) userToken(res mcpRes) map[string]any {
	x.t.Helper()
	rec := serve(x.h, authed(x.alice, "GET", x.authorizeURL(func(q url.Values) { q.Set("resource", res.uri) }), ""))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "/agent-authorization?consent=") {
		x.t.Fatalf("authorize: %d %s %s", rec.Code, loc, rec.Body)
	}
	id := strings.TrimPrefix(loc, "/agent-authorization?consent=")
	rec = corrDo(x.h, x.alice, "POST", "/api/mcp/authorizations/"+id+"/decision", `{"approve":true}`)
	if rec.Code != 200 {
		x.t.Fatalf("decision: %d %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(jsonBody(x.t, rec)["redirect_to"].(string))
	if err != nil || queryOf(u).Get("code") == "" || queryOf(u).Get("state") != "st-1" || queryOf(u).Get("iss") != x.issuer ||
		u.Scheme+"://"+u.Host+u.Path != mcpRedirect {
		x.t.Fatalf("redirect_to = %v, %v", u, err)
	}
	rec = form(x.h, x.base+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {queryOf(u).Get("code")},
		"code_verifier": {mcpVerifier}, "client_id": {mcpClientID}, "redirect_uri": {mcpRedirect}, "resource": {res.uri}})
	if rec.Code != 200 {
		x.t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	return jsonBody(x.t, rec)
}

func (x *mcpFx) actorAssertion() string {
	x.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: x.key, KeyID: "k1"}}, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: mcpClientID, Subject: mcpClientID, Audience: jwt.Audience{x.issuer},
		Expiry: jwt.NewNumericDate(storetest.Now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(storetest.Now), ID: uuid.NewString()}).Serialize()
	if err != nil {
		x.t.Fatal(err)
	}
	return raw
}

func (x *mcpFx) introspect(token string, res mcpRes) *httptest.ResponseRecorder {
	return form(x.h, x.base+"/oauth/introspect", url.Values{"token": {token}}, res.id, res.secret)
}

// ---------------------------------------------------------------- discovery

func TestMCP_Discovery(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	rec := serve(x.h, httptest.NewRequest("GET", x.base+"/.well-known/oauth-authorization-server", nil))
	m := jsonBody(t, rec)
	if rec.Code != 200 || m["issuer"] != x.issuer || m["token_endpoint"] != x.issuer+"/oauth/token" ||
		m["authorization_endpoint"] != x.issuer+"/oauth/authorize" || m["client_id_metadata_document_supported"] != true ||
		m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("AS metadata: %d %v", rec.Code, m)
	}
	if got := fmt.Sprint(m["code_challenge_methods_supported"]); got != "[S256]" {
		t.Errorf("code_challenge_methods_supported = %s, want S256 only", got)
	}
	if got := fmt.Sprint(m["token_endpoint_auth_methods_supported"]); got != "[none]" {
		t.Errorf("token_endpoint_auth_methods_supported = %s", got)
	}
	if got := fmt.Sprint(m["grant_types_supported"]); strings.Contains(got, "refresh_token") || !strings.Contains(got, mcpauth.GrantTokenExchange) {
		t.Errorf("grant_types_supported = %s", got)
	}

	rec = serve(x.h, httptest.NewRequest("GET", x.base+"/.well-known/oauth-protected-resource/"+x.resA.id, nil))
	m = jsonBody(t, rec)
	if rec.Code != 200 || m["resource"] != x.resA.uri || fmt.Sprint(m["authorization_servers"]) != "["+x.issuer+"]" ||
		fmt.Sprint(m["bearer_methods_supported"]) != "[header]" {
		t.Errorf("PRM: %d %v", rec.Code, m)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource/" + uuid.NewString(), "/.well-known/oauth-protected-resource/x"} {
		if rec := serve(x.h, httptest.NewRequest("GET", x.base+p, nil)); rec.Code != 404 {
			t.Errorf("PRM of an unknown resource: %d", rec.Code)
		}
	}
	rec = serve(x.h, httptest.NewRequest("GET", x.base+"/.well-known/jwks.json", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"kid"`) || strings.Contains(rec.Body.String(), `"d"`) {
		t.Errorf("jwks: %d %s", rec.Code, rec.Body)
	}
	// another tenant's slug serves that tenant's issuer, an unknown one is a 404
	if rec := serve(x.h, httptest.NewRequest("GET", "/t/nobody/.well-known/oauth-authorization-server", nil)); rec.Code != 404 {
		t.Errorf("unknown tenant: %d", rec.Code)
	}
	// a resource of tenant A is unknown under tenant B's slug
	if rec := serve(x.h, httptest.NewRequest("GET", "/t/"+x.other.Slug+"/.well-known/oauth-protected-resource/"+x.resA.id, nil)); rec.Code != 404 {
		t.Errorf("cross-tenant PRM: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- the browser flow

func TestMCP_AuthorizationCodeFlowAndTokenUse(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	resp := x.userToken(x.resA)
	if _, has := resp["refresh_token"]; has || resp["token_type"] != "Bearer" || resp["scope"] != x.shared {
		t.Fatalf("token response = %v", resp)
	}
	if n := resp["expires_in"].(float64); n <= 0 || n > 300 {
		t.Errorf("expires_in = %v", n)
	}
	tok := resp["access_token"].(string)

	// the resource server introspects it with its own credentials
	rec := x.introspect(tok, x.resA)
	in := jsonBody(t, rec)
	if rec.Code != 200 || in["active"] != true || in["aud"] != x.resA.uri || in["scope"] != x.shared || in["iss"] != x.issuer ||
		in["policy_version"] == nil {
		t.Fatalf("introspect = %d %v", rec.Code, in)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("introspection must not be cached")
	}
	act := in["act"].(map[string]any)
	if act["sub"] != fmt.Sprintf("identity:%d", x.botID) || in["sub"] != fmt.Sprintf("identity:%d", x.aliceID) {
		t.Errorf("sub/act = %v / %v", in["sub"], act)
	}
	if got := jsonBody(t, x.introspect(tok, x.resB))["active"]; got != false {
		t.Errorf("active at the wrong resource server: %v", got)
	}
	// resource server authentication
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"no credentials": form(x.h, x.base+"/oauth/introspect", url.Values{"token": {tok}}),
		"wrong secret":   form(x.h, x.base+"/oauth/introspect", url.Values{"token": {tok}}, x.resA.id, "nope"),
		"wrong id":       form(x.h, x.base+"/oauth/introspect", url.Values{"token": {tok}}, uuid.NewString(), x.resA.secret),
	} {
		if rec.Code != 401 || strings.Contains(rec.Body.String(), tok) {
			t.Errorf("introspect with %s: %d %s", name, rec.Code, rec.Body)
		}
	}

	// tool-call decisions are logged with the policy version
	call := func(tool string, need ...string) map[string]any {
		b, _ := json.Marshal(map[string]any{"token": tok, "tool": tool, "required_scope": need})
		req := httptest.NewRequest("POST", x.base+"/oauth/decisions", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(x.resA.id, x.resA.secret)
		rec := serve(x.h, req)
		if rec.Code != 200 {
			t.Fatalf("decision: %d %s", rec.Code, rec.Body)
		}
		return jsonBody(t, rec)
	}
	if d := call("query", x.shared); d["allow"] != true || d["policy_version"] == "" || d["jti"] == "" {
		t.Errorf("allowed call = %v", d)
	}
	if d := call("export", "aws:s3:GetObject:s3://customer-pii"); d["allow"] != false || d["reason"] == "" {
		t.Errorf("denied call = %v", d)
	}
	rec = corrDo(x.h, x.admin, "GET", "/api/mcp/decisions", "")
	var ds []mcpDecisionView
	if err := json.Unmarshal(rec.Body.Bytes(), &ds); err != nil || rec.Code != 200 {
		t.Fatalf("decisions: %d %s", rec.Code, rec.Body)
	}
	tools := 0
	for _, d := range ds {
		if d.PolicyVersion == "" {
			t.Errorf("decision without a policy version: %+v", d)
		}
		if d.Kind == "tool_call" {
			tools++
		}
	}
	if tools != 2 || ds[0].Kind != "tool_call" || ds[len(ds)-1].Kind != "issue" {
		t.Errorf("decision log = %d tool calls, newest %s, oldest %s", tools, ds[0].Kind, ds[len(ds)-1].Kind)
	}

	// the holder revokes it (RFC 7009); a garbage token is a 200 too
	if rec := form(x.h, x.base+"/oauth/revoke", url.Values{"token": {"garbage"}}); rec.Code != 200 {
		t.Errorf("revoke garbage: %d", rec.Code)
	}
	if rec := form(x.h, x.base+"/oauth/revoke", url.Values{"token": {tok}}); rec.Code != 200 {
		t.Errorf("revoke: %d", rec.Code)
	}
	if got := jsonBody(t, x.introspect(tok, x.resA))["active"]; got != false {
		t.Errorf("active after revoke: %v", got)
	}
	if call("query", x.shared)["allow"] != false {
		t.Error("a revoked token was allowed a tool call")
	}
	acts := auditActions(t, x.f, x.main.ID)
	for _, a := range []string{"mcp.token.issue", "mcp.token.revoke", "mcp.tool_call.decision", "mcp.authorize.approve", "mcp.resource.register"} {
		if acts[a] == 0 {
			t.Errorf("no %s audit event: %v", a, acts)
		}
	}
}

func TestMCP_TokenExchangeOverHTTP(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	sub := x.userToken(x.resA)["access_token"].(string)
	ex := url.Values{"grant_type": {mcpauth.GrantTokenExchange}, "subject_token": {sub}, "subject_token_type": {mcpauth.TypeAccessToken},
		"actor_token": {x.actorAssertion()}, "actor_token_type": {mcpauth.TypeJWT}, "resource": {x.resB.uri},
		"scope": {x.shared + " aws:s3:GetObject:s3://customer-pii"}}
	rec := form(x.h, x.base+"/oauth/token", ex)
	m := jsonBody(t, rec)
	if rec.Code != 200 || m["scope"] != x.shared || m["issued_token_type"] != mcpauth.TypeAccessToken || m["refresh_token"] != nil {
		t.Fatalf("exchange: %d %v", rec.Code, m)
	}
	in := jsonBody(t, x.introspect(m["access_token"].(string), x.resB))
	if in["active"] != true || in["aud"] != x.resB.uri {
		t.Errorf("exchanged token = %v", in)
	}
	// the same actor assertion cannot be replayed
	if rec := form(x.h, x.base+"/oauth/token", ex); rec.Code != 401 || jsonBody(t, rec)["error"] != "invalid_client" {
		t.Errorf("replay: %d %s", rec.Code, rec.Body)
	}
	// asking only for what the user alone holds is an empty intersection
	ex.Set("actor_token", x.actorAssertion())
	ex.Set("scope", "aws:s3:GetObject:s3://customer-pii")
	if rec := form(x.h, x.base+"/oauth/token", ex); rec.Code != 403 || jsonBody(t, rec)["error"] != "access_denied" {
		t.Errorf("empty intersection: %d %s", rec.Code, rec.Body)
	}
	acts := auditActions(t, x.f, x.main.ID)
	if acts["mcp.token.exchange"] != 1 || acts["mcp.token.deny"] < 2 {
		t.Errorf("audit = %v", acts)
	}
}

func TestMCP_AuthorizeRequestChecks(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	get := func(l authtest.Login, mod func(q url.Values)) *httptest.ResponseRecorder {
		return serve(x.h, authed(l, "GET", x.authorizeURL(mod), ""))
	}
	// no session: the usual 401, nothing stored
	if rec := serve(x.h, httptest.NewRequest("GET", x.authorizeURL(nil), nil)); rec.Code != 401 {
		t.Errorf("anonymous authorize: %d", rec.Code)
	}
	// a session of another tenant does not see this tenant's authorization server
	other := signIn(t, x.f.DB, x.other.ID, authtest.User{Email: "b@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := get(other, nil); rec.Code != 404 {
		t.Errorf("tenant B's session at tenant A's authorize: %d", rec.Code)
	}
	// errors before the redirect URI is trusted are never redirects
	for name, mod := range map[string]func(q url.Values){
		"unregistered redirect_uri": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"no redirect_uri":           func(q url.Values) { q.Del("redirect_uri") },
		"prefix of a registered":    func(q url.Values) { q.Set("redirect_uri", mcpRedirect+"/x") },
		"client_id not a url":       func(q url.Values) { q.Set("client_id", "agent") },
		"client_id over http":       func(q url.Values) { q.Set("client_id", "http://client.example/agent.json") },
		"repeated parameter":        func(q url.Values) { q.Add("scope", "x:y:z") },
	} {
		rec := get(x.alice, mod)
		if rec.Code != 400 || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %d location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	// protocol errors after it is trusted go back to the client, with iss and state
	for name, c := range map[string]struct {
		mod  func(q url.Values)
		want string
	}{
		"no PKCE":                {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"plain PKCE":             {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no method":              {func(q url.Values) { q.Del("code_challenge_method") }, "invalid_request"},
		"short challenge":        {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"implicit":               {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"no resource":            {func(q url.Values) { q.Del("resource") }, "invalid_target"},
		"relative resource":      {func(q url.Values) { q.Set("resource", "/mcp") }, "invalid_target"},
		"unregistered resource":  {func(q url.Values) { q.Set("resource", "https://unknown.example/mcp") }, "invalid_target"},
		"no scope":               {func(q url.Values) { q.Del("scope") }, "invalid_scope"},
		"scope the agent lacks":  {func(q url.Values) { q.Set("scope", "aws:s3:GetObject:s3://customer-pii") }, "invalid_scope"},
		"scope that is not real": {func(q url.Values) { q.Set("scope", "x:y:z") }, "invalid_scope"},
		"state too long":         {func(q url.Values) { q.Set("state", strings.Repeat("s", 600)) }, "invalid_request"},
	} {
		rec := get(x.alice, c.mod)
		loc, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != 302 || err != nil || loc.Scheme+"://"+loc.Host+loc.Path != mcpRedirect || queryOf(loc).Get("error") != c.want ||
			queryOf(loc).Get("iss") != x.issuer {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Header().Get("Location"))
		}
		if name != "state too long" && queryOf(loc).Get("state") != "st-1" {
			t.Errorf("%s: state not echoed: %s", name, loc)
		}
	}
	// a user whose sign-in is linked to no identity cannot consent
	noLink := signIn(t, x.f.DB, x.main.ID, authtest.User{Email: "nolink@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := get(noLink, nil); rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "error=access_denied") {
		t.Errorf("unlinked user: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// a pending client (not yet approved by an administrator) is refused
	if err := x.f.DB.InTenant(context.Background(), x.main.ID, func(c *store.TenantTx) error {
		return c.SetMCPClient(mcpClientID, &x.botID, "pending", storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	if rec := get(x.alice, nil); rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "error=unauthorized_client") {
		t.Errorf("pending client: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMCP_ConsentIsPrivateAndNeedsStepUp(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	rec := serve(x.h, authed(x.alice, "GET", x.authorizeURL(nil), ""))
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/agent-authorization?consent=")
	rec = corrDo(x.h, x.alice, "GET", "/api/mcp/authorizations/"+id, "")
	var v consentView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Client.Name != "Agent Host" ||
		len(v.Granted) != 1 || v.Granted[0] != x.shared || v.Agent.ID != x.botID || v.Resource != x.resA.uri || v.PolicyVersion == "" {
		t.Fatalf("consent view: %d %s", rec.Code, rec.Body)
	}
	// bob cannot see or decide alice's request
	bobID := x.main.IDs["bob"]
	bob := signIn(t, x.f.DB, x.main.ID, authtest.User{Email: "bob@a.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &bobID},
		authtest.Phr, storetest.Now)
	if rec := corrDo(x.h, bob, "GET", "/api/mcp/authorizations/"+id, ""); rec.Code != 404 {
		t.Errorf("bob reads alice's consent: %d", rec.Code)
	}
	if rec := corrDo(x.h, bob, "POST", "/api/mcp/authorizations/"+id+"/decision", `{"approve":true}`); rec.Code != 404 {
		t.Errorf("bob approves alice's consent: %d", rec.Code)
	}
	// a stale sign-in needs step-up
	stale := signIn(t, x.f.DB, x.main.ID, authtest.User{Email: "alice2@a.example", Roles: []auth.Role{auth.RoleViewer}, IdentityID: &x.aliceID},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := corrDo(x.h, stale, "POST", "/api/mcp/authorizations/"+id+"/decision", `{"approve":true}`); rec.Code != 401 ||
		!strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale approval: %d %s", rec.Code, rec.Body)
	}
	// deny goes back with access_denied; the request cannot be decided twice
	rec = corrDo(x.h, x.alice, "POST", "/api/mcp/authorizations/"+id+"/decision", `{"approve":false}`)
	m := jsonBody(t, rec)
	if rec.Code != 200 || m["approved"] != false || !strings.Contains(m["redirect_to"].(string), "error=access_denied") ||
		strings.Contains(m["redirect_to"].(string), "code=") {
		t.Errorf("deny: %d %v", rec.Code, m)
	}
	if rec := corrDo(x.h, x.alice, "POST", "/api/mcp/authorizations/"+id+"/decision", `{"approve":true}`); rec.Code != 409 {
		t.Errorf("deciding twice: %d", rec.Code)
	}
	if rec := corrDo(x.h, x.alice, "GET", "/api/mcp/authorizations/not-a-uuid", ""); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}
}

func TestMCP_TokenEndpointHygiene(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	post := func(ct, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", x.base+"/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		return serve(x.h, req)
	}
	const f = "application/x-www-form-urlencoded"
	for name, c := range map[string]struct {
		rec  *httptest.ResponseRecorder
		want string
	}{
		"json body":           {post("application/json", `{"grant_type":"authorization_code"}`), "invalid_request"},
		"repeated parameter":  {post(f, "grant_type=authorization_code&grant_type=refresh_token"), "invalid_request"},
		"refresh grant":       {post(f, "grant_type=refresh_token&refresh_token=x"), "unsupported_grant_type"},
		"client credentials":  {post(f, "grant_type=client_credentials"), "unsupported_grant_type"},
		"password":            {post(f, "grant_type=password&username=a&password=b"), "unsupported_grant_type"},
		"no grant":            {post(f, ""), "unsupported_grant_type"},
		"a client secret":     {post(f, "grant_type=authorization_code&client_secret=x"), "invalid_request"},
		"a client assertion":  {post(f, "grant_type=authorization_code&client_assertion=x"), "invalid_request"},
		"code without PKCE":   {post(f, "grant_type=authorization_code&code=abc&client_id="+url.QueryEscape(mcpClientID)+"&redirect_uri="+url.QueryEscape(mcpRedirect)+"&resource="+url.QueryEscape(x.resA.uri)), "invalid_request"},
		"query-string params": {serve(x.h, httptest.NewRequest("POST", x.base+"/oauth/token?grant_type=authorization_code", strings.NewReader(""))), "invalid_request"},
	} {
		m := jsonBody(t, c.rec)
		if c.rec.Code < 400 || m["error"] != c.want || c.rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", name, c.rec.Code, m)
		}
	}
	if rec := serve(x.h, httptest.NewRequest("GET", x.base+"/oauth/token", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET token: %d", rec.Code)
	}
	// unknown tenant
	if rec := form(x.h, "/t/nobody/oauth/token", url.Values{"grant_type": {"authorization_code"}}); rec.Code != 404 {
		t.Errorf("unknown tenant: %d", rec.Code)
	}
	// no response leaks a token or a secret
	for _, rec := range []*httptest.ResponseRecorder{post(f, "grant_type=authorization_code&code=abc")} {
		if strings.Contains(rec.Body.String(), "abc") {
			t.Errorf("the code was echoed: %s", rec.Body)
		}
	}
}

func TestMCP_OAuthEndpointsAreRateLimited(t *testing.T) {
	limits := noRateLimits
	limits.OAuth = RateLimit{Every: time.Hour, Burst: 3}
	x := newMCPFx(t, limits)
	var codes []int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", x.base+"/oauth/token", strings.NewReader("grant_type=nope"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.7:4444"
		rec := serve(x.h, req)
		codes = append(codes, rec.Code)
		if rec.Code == 429 && (rec.Header().Get("Retry-After") == "" || rec.Header().Get("Cache-Control") != "no-store") {
			t.Errorf("429 without Retry-After: %v", rec.Header())
		}
	}
	if codes[2] == 429 || codes[3] != 429 || codes[4] != 429 {
		t.Errorf("status sequence = %v, want the 4th request limited", codes)
	}
	// another address, and other routes, are unaffected
	req := httptest.NewRequest("GET", x.base+"/.well-known/jwks.json", nil)
	req.RemoteAddr = "198.51.100.8:4444"
	if rec := serve(x.h, req); rec.Code != 200 {
		t.Errorf("another IP: %d", rec.Code)
	}
	if rec := corrDo(x.h, x.admin, "GET", "/api/mcp/clients", ""); rec.Code != 200 {
		t.Errorf("admin API: %d", rec.Code)
	}
}

func TestIsOAuthPath(t *testing.T) {
	for p, want := range map[string]bool{"/t/a/oauth/token": true, "/t/a/oauth/authorize": true, "/t/a/.well-known/jwks.json": false,
		"/api/mcp/clients": false, "/t/a/bootstrap": false, "/oauth/token": false, "/t/oauth/token": false, "/t/a/oauthx": false} {
		if got := isOAuthPath(p); got != want {
			t.Errorf("isOAuthPath(%q) = %v", p, got)
		}
	}
}

// ---------------------------------------------------------------- kill switch

func TestMCP_KillSwitchRevokesAgentTokens(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	t1 := x.userToken(x.resA)["access_token"].(string)
	t2 := x.userToken(x.resB)["access_token"].(string)
	for _, c := range []struct {
		tok string
		res mcpRes
	}{{t1, x.resA}, {t2, x.resB}} {
		if jsonBody(t, x.introspect(c.tok, c.res))["active"] != true {
			t.Fatal("token not active before the kill switch")
		}
	}
	rec := corrDo(x.h, x.admin, "POST", fmt.Sprintf("/api/identities/%d/contain", x.botID), `{"reason":"agent went off the rails"}`)
	if rec.Code != 200 {
		t.Fatalf("contain: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct {
		tok string
		res mcpRes
	}{{t1, x.resA}, {t2, x.resB}} {
		if jsonBody(t, x.introspect(c.tok, c.res))["active"] != false {
			t.Error("a token survived the kill switch")
		}
	}
	rec = corrDo(x.h, x.admin, "GET", "/api/mcp/tokens", "")
	var ts []tokenView
	if err := json.Unmarshal(rec.Body.Bytes(), &ts); err != nil || len(ts) != 2 {
		t.Fatalf("tokens: %d %s", rec.Code, rec.Body)
	}
	for _, tv := range ts {
		if tv.State != "revoked" || tv.RevokedAt == nil || !strings.Contains(tv.RevokedReason, "kill switch") || tv.Agent.ID != x.botID {
			t.Errorf("token = %+v", tv)
		}
	}
	if acts := auditActions(t, x.f, x.main.ID); acts["mcp.tokens.revoke_identity"] != 1 {
		t.Errorf("audit = %v", acts)
	}
	// tenant B's ledger and tokens are untouched
	if acts := auditActions(t, x.f, x.other.ID); acts["mcp.tokens.revoke_identity"] != 0 {
		t.Errorf("tenant B audit = %v", acts)
	}
}

// ---------------------------------------------------------------- admin API

func TestMCP_AdminAPI(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	// resources: the secret is shown once; duplicates and junk are refused
	rec := corrDo(x.h, x.admin, "GET", "/api/mcp/resources", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), x.resA.secret) || !strings.Contains(rec.Body.String(), x.resA.uri) ||
		!strings.Contains(rec.Body.String(), "/.well-known/oauth-protected-resource/"+x.resA.id) {
		t.Errorf("list resources: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(x.h, x.admin, "POST", "/api/mcp/resources", fmt.Sprintf(`{"resource":%q,"name":"dup"}`, x.resA.uri)); rec.Code != 409 {
		t.Errorf("duplicate resource: %d", rec.Code)
	}
	for _, body := range []string{`{"resource":"/mcp","name":"x"}`, `{"resource":"http://x.example/mcp","name":"x"}`,
		`{"resource":"https://x.example/mcp#f","name":"x"}`, `{"resource":"https://x.example/mcp","name":""}`, `{}`} {
		if rec := corrDo(x.h, x.admin, "POST", "/api/mcp/resources", body); rec.Code != 422 {
			t.Errorf("resource %s: %d", body, rec.Code)
		}
	}
	// clients: bound to an ai_agent only
	rec = corrDo(x.h, x.admin, "GET", "/api/mcp/clients", "")
	var cs []clientView
	if err := json.Unmarshal(rec.Body.Bytes(), &cs); err != nil || len(cs) != 1 || cs[0].Status != "active" || cs[0].Agent == nil ||
		cs[0].Agent.ID != x.botID || !cs[0].HasKeys {
		t.Fatalf("clients: %d %s", rec.Code, rec.Body)
	}
	put := fmt.Sprintf("/api/mcp/clients/%s", cs[0].ID)
	for name, body := range map[string]string{
		"a person as the agent": fmt.Sprintf(`{"agent_identity_id":%d,"status":"active"}`, x.aliceID),
		"no agent":              `{"status":"active"}`,
		"bad status":            fmt.Sprintf(`{"agent_identity_id":%d,"status":"root"}`, x.botID),
		"unknown field":         fmt.Sprintf(`{"agent_identity_id":%d,"status":"active","x":1}`, x.botID),
	} {
		if rec := corrDo(x.h, x.admin, "PUT", put, body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := corrDo(x.h, x.admin, "PUT", "/api/mcp/clients/"+uuid.NewString(), `{"status":"disabled"}`); rec.Code != 404 {
		t.Errorf("unknown client: %d", rec.Code)
	}
	// disabling a client revokes its tokens
	tok := x.userToken(x.resA)["access_token"].(string)
	if rec := corrDo(x.h, x.admin, "PUT", put, `{"status":"disabled"}`); rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if jsonBody(t, x.introspect(tok, x.resA))["active"] != false {
		t.Error("a disabled client's token is still active")
	}
	// re-activating works, and a disabled resource revokes its tokens
	if rec := corrDo(x.h, x.admin, "PUT", put, fmt.Sprintf(`{"agent_identity_id":%d,"status":"active"}`, x.botID)); rec.Code != 200 {
		t.Fatalf("activate: %d %s", rec.Code, rec.Body)
	}
	tok = x.userToken(x.resA)["access_token"].(string)
	if rec := corrDo(x.h, x.admin, "PUT", "/api/mcp/resources/"+x.resA.id, `{"status":"disabled"}`); rec.Code != 200 {
		t.Fatalf("disable resource: %d %s", rec.Code, rec.Body)
	}
	if rec := x.introspect(tok, x.resA); rec.Code != 401 {
		t.Errorf("a disabled resource server can still introspect: %d", rec.Code)
	}
	// revoking one token by jti
	tb := x.userToken(x.resB)["access_token"].(string)
	rec = corrDo(x.h, x.admin, "GET", "/api/mcp/tokens", "")
	var ts []tokenView
	if err := json.Unmarshal(rec.Body.Bytes(), &ts); err != nil {
		t.Fatal(err)
	}
	var live *tokenView
	for i := range ts {
		if ts[i].State == "active" {
			live = &ts[i]
		}
	}
	if live == nil || live.Audience != x.resB.uri || live.Act == nil || live.PolicyVersion == "" {
		t.Fatalf("tokens = %+v", ts)
	}
	if rec := corrDo(x.h, x.admin, "POST", "/api/mcp/tokens/"+live.JTI+"/revoke", ""); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if jsonBody(t, x.introspect(tb, x.resB))["active"] != false {
		t.Error("revoked token still active")
	}
	if rec := corrDo(x.h, x.admin, "POST", "/api/mcp/tokens/"+uuid.NewString()+"/revoke", ""); rec.Code != 404 {
		t.Errorf("unknown token: %d", rec.Code)
	}
	// a viewer may read but not manage
	viewer := signIn(t, x.f.DB, x.main.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := corrDo(x.h, viewer, "GET", "/api/mcp/tokens", ""); rec.Code != 200 {
		t.Errorf("viewer read: %d", rec.Code)
	}
	if rec := corrDo(x.h, viewer, "POST", "/api/mcp/tokens/"+live.JTI+"/revoke", ""); rec.Code != 403 {
		t.Errorf("viewer revoke: %d", rec.Code)
	}
}

func TestMCP_CrossTenant(t *testing.T) {
	x := newMCPFx(t, noRateLimits)
	x.userToken(x.resA)
	adminB := signIn(t, x.f.DB, x.other.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	for _, p := range []string{"/api/mcp/tokens", "/api/mcp/clients", "/api/mcp/resources", "/api/mcp/decisions"} {
		rec := corrDo(x.h, adminB, "GET", p, "")
		if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Errorf("tenant B's %s = %d %s", p, rec.Code, rec.Body)
		}
	}
	rec := corrDo(x.h, x.admin, "GET", "/api/mcp/tokens", "")
	var ts []tokenView
	if err := json.Unmarshal(rec.Body.Bytes(), &ts); err != nil || len(ts) != 1 {
		t.Fatalf("tokens: %s", rec.Body)
	}
	if rec := corrDo(x.h, adminB, "POST", "/api/mcp/tokens/"+ts[0].JTI+"/revoke", ""); rec.Code != 404 {
		t.Errorf("tenant B revoking A's token: %d", rec.Code)
	}
	if rec := corrDo(x.h, adminB, "PUT", "/api/mcp/resources/"+x.resA.id, `{"status":"disabled"}`); rec.Code != 404 {
		t.Errorf("tenant B disabling A's resource: %d", rec.Code)
	}
	// tenant A's resource credentials do not open tenant B's endpoints
	tokA := x.userToken(x.resA)["access_token"].(string)
	if rec := form(x.h, "/t/"+x.other.Slug+"/oauth/introspect", url.Values{"token": {tokA}}, x.resA.id, x.resA.secret); rec.Code != 401 {
		t.Errorf("tenant A's resource secret at tenant B: %d", rec.Code)
	}
	// and a token of tenant A is not active at tenant B's issuer
	if rec := form(x.h, x.base+"/oauth/revoke", url.Values{"token": {tokA}}); rec.Code != 200 {
		t.Errorf("revoke: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- client registration (CIMD over the wire)

func TestMCP_RegisterClientFetchesTheDocument(t *testing.T) {
	var doc string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.ReplaceAll(doc, "SELF", "https://"+r.Host+r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	x := newMCPFx(t, noRateLimits)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	x.srv.mcp.HTTP = hc

	doc = `{"client_id":"SELF","client_name":"New Agent","redirect_uris":["https://new.example/cb"]}`
	id := srv.URL + "/clients/new.json"
	rec := corrDo(x.h, x.admin, "POST", "/api/mcp/clients", fmt.Sprintf(`{"client_id":%q}`, id))
	var v clientView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Status != "pending" || v.Agent != nil || v.Name != "New Agent" {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	// a pending client cannot be used until an administrator binds and activates it
	rec = serve(x.h, authed(x.alice, "GET", x.authorizeURL(func(q url.Values) {
		q.Set("client_id", id)
		q.Set("redirect_uri", "https://new.example/cb")
	}), ""))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "error=unauthorized_client") {
		t.Errorf("authorize with a pending client: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = corrDo(x.h, x.admin, "PUT", "/api/mcp/clients/"+v.ID, fmt.Sprintf(`{"agent_identity_id":%d,"status":"active"}`, x.botID))
	if rec.Code != 200 {
		t.Fatalf("activate: %d %s", rec.Code, rec.Body)
	}
	// a document that names another client_id is refused
	doc = `{"client_id":"https://victim.example/meta.json","client_name":"Evil","redirect_uris":["https://evil.example/cb"]}`
	rec = corrDo(x.h, x.admin, "POST", "/api/mcp/clients", fmt.Sprintf(`{"client_id":%q}`, srv.URL+"/clients/evil.json"))
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "invalid_client_metadata") {
		t.Errorf("mismatched document: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"http://client.example/a.json", "https://client.example/", "nonsense", ""} {
		if rec := corrDo(x.h, x.admin, "POST", "/api/mcp/clients", fmt.Sprintf(`{"client_id":%q}`, bad)); rec.Code != 422 {
			t.Errorf("client_id %q: %d", bad, rec.Code)
		}
	}
	acts := auditActions(t, x.f, x.main.ID)
	if acts["mcp.client.discovered"] < 1 || acts["mcp.client.update"] != 1 {
		t.Errorf("audit = %v", acts)
	}
}
