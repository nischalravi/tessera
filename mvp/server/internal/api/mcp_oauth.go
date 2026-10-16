package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/mcpauth"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MCP authorization server (issue #115): OAuth 2.1 for MCP clients under the
// MCP authorization spec 2025-11-25, per tenant at {PUBLIC_URL}/t/{slug}.
//
// Public (the OAuth endpoints; each opens its own tenant transaction):
//
//	GET  /t/{slug}/.well-known/oauth-authorization-server         RFC 8414 metadata
//	GET  /t/{slug}/.well-known/oauth-protected-resource/{id}      RFC 9728 metadata of a registered resource
//	GET  /t/{slug}/.well-known/jwks.json                          access-token keys
//	POST /t/{slug}/oauth/token                                    authorization_code (PKCE S256) and RFC 8693 token exchange
//	POST /t/{slug}/oauth/introspect                               RFC 7662, resource-server Basic auth
//	POST /t/{slug}/oauth/revoke                                   RFC 7009, by the token's holder
//	POST /t/{slug}/oauth/decisions                                a resource server asks about a tool call, Basic auth
//
// Signed in (browser session):
//
//	GET  /t/{slug}/oauth/authorize                                validates, stores a pending request, sends the user to the consent page
//	GET  /api/mcp/authorizations/{id}                             the consent page's data
//	POST /api/mcp/authorizations/{id}/decision                    approve or deny (step-up)
//
// Every OAuth endpoint is rate-limited per IP (ratelimit.go, bucket oauth).

func (s *Server) registerMCPRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/t/{slug}/.well-known/oauth-authorization-server", noTenant, publicRoute, s.mcpASMetadata)
	s.handle(G, "/t/{slug}/.well-known/oauth-protected-resource/{resource_id}", noTenant, publicRoute, s.mcpPRM)
	s.handle(G, "/t/{slug}/.well-known/jwks.json", noTenant, publicRoute, s.mcpJWKS)
	s.handle(P, "/t/{slug}/oauth/token", noTenant, publicRoute, s.mcpToken)
	s.handle(P, "/t/{slug}/oauth/introspect", noTenant, publicRoute, s.mcpIntrospect)
	s.handle(P, "/t/{slug}/oauth/revoke", noTenant, publicRoute, s.mcpRevoke)
	s.handle(P, "/t/{slug}/oauth/decisions", noTenant, publicRoute, s.mcpDecisions)
	s.handle(G, "/t/{slug}/oauth/authorize", noTenant, need(auth.PermAuthenticated), s.mcpAuthorize)
	s.handle(G, "/api/mcp/authorizations/{id}", read, need(auth.PermAuthenticated), s.mcpConsent)
	s.handle(P, "/api/mcp/authorizations/{id}/decision", noTenant, needStepUp(auth.PermAuthenticated, auth.StepUpPolicy), s.mcpConsentDecision)
	s.registerMCPAdminRoutes()
}

// ---------------------------------------------------------------- plumbing

// policyVersion names the policy set decisions are made under: a digest of
// the policy documents (ids and source text), "unversioned" when none load.
func (s *Server) policyVersion() string {
	pols, err := s.policies()
	if err != nil || len(pols) == 0 {
		return "unversioned"
	}
	h := sha256.New()
	for _, p := range pols {
		h.Write([]byte(p.ID + "\x00" + p.Source + "\x00"))
	}
	return "pol-" + hex.EncodeToString(h.Sum(nil))[:12]
}

func oauthWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, v)
}

func oauthFail(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="tessera"`)
	}
	oauthWrite(w, status, map[string]string{"error": code, "error_description": desc})
}

func oauthFailE(w http.ResponseWriter, e *mcpauth.OAuthError) { oauthFail(w, e.Status, e.Code, e.Desc) }

// mcpTenant resolves the {slug} of an OAuth route to an active tenant and its
// issuer URL; it writes the error response itself when it cannot.
func (s *Server) mcpTenant(w http.ResponseWriter, r *http.Request, p *params) (store.Tenant, string, bool) {
	if s.cfg.PublicURL == "" {
		oauthFail(w, http.StatusServiceUnavailable, "server_error", "TESSERA_PUBLIC_URL is not configured")
		return store.Tenant{}, "", false
	}
	t, ok, err := s.activeTenant(r.Context(), p.path["slug"])
	if err != nil {
		s.log.Error("oauth tenant lookup failed", "err", err)
		oauthFail(w, http.StatusInternalServerError, "server_error", "temporarily unavailable")
		return store.Tenant{}, "", false
	}
	if !ok {
		oauthFail(w, http.StatusNotFound, "invalid_request", "unknown tenant")
		return store.Tenant{}, "", false
	}
	return t, s.cfg.PublicURL + "/t/" + t.Slug, true
}

// mcpForm parses an application/x-www-form-urlencoded POST body (never the
// query string); a parameter given twice is refused.
func mcpForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return nil, false
	}
	if err := r.ParseForm(); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "the body could not be read")
		return nil, false
	}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			oauthFail(w, http.StatusBadRequest, "invalid_request", "parameter "+k+" is repeated")
			return nil, false
		}
	}
	return r.PostForm, true
}

// mcpResourceAuth authenticates a resource server by HTTP Basic: its id and
// secret. Nil when the credentials are absent or wrong.
func mcpResourceAuth(tx *store.TenantTx, r *http.Request) *store.MCPResource {
	id, secret, ok := r.BasicAuth()
	if !ok || !idRE.MatchString(id) || secret == "" || len(secret) > 256 {
		return nil
	}
	res, err := tx.MCPResource(id)
	if err != nil || res.Status != "active" || !seal.MatchesHash([]byte(secret), res.SecretHash) {
		return nil
	}
	return res
}

// ---------------------------------------------------------------- discovery

func (s *Server) mcpASMetadata(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	_, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/oauth/authorize",
		"token_endpoint":                                 iss + "/oauth/token",
		"introspection_endpoint":                         iss + "/oauth/introspect",
		"revocation_endpoint":                            iss + "/oauth/revoke",
		"jwks_uri":                                       iss + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", mcpauth.GrantTokenExchange},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"introspection_endpoint_auth_methods_supported":  []string{"client_secret_basic"},
		"subject_token_types_supported":                  []string{mcpauth.TypeAccessToken},
		"actor_token_types_supported":                    []string{mcpauth.TypeJWT},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"tessera_decision_endpoint":                      iss + "/oauth/decisions",
	})
	return nil, nil
}

func (s *Server) mcpPRM(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	id := p.path["resource_id"]
	var res *store.MCPResource
	if idRE.MatchString(id) {
		_ = s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			if x, err := tx.MCPResource(id); err == nil && x.Status == "active" {
				res = x
			}
			return nil
		})
	}
	if res == nil {
		oauthFail(w, http.StatusNotFound, "invalid_request", "unknown resource")
		return nil, nil
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"resource": res.Resource, "resource_name": res.Name,
		"authorization_servers": []string{iss}, "bearer_methods_supported": []string{"header"}})
	return nil, nil
}

func (s *Server) mcpJWKS(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, _, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	var set any
	if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		var err error
		set, err = keys.JWKSFor(tx, store.KeyPurposeAccessToken, s.clock())
		return err
	}); err != nil {
		return nil, err
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
	return nil, nil
}

// ---------------------------------------------------------------- token endpoint

func (s *Server) mcpToken(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	f, ok := mcpForm(w, r)
	if !ok {
		return nil, nil
	}
	if f.Get("client_secret") != "" || f.Get("client_assertion") != "" || f.Get("client_assertion_type") != "" {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "this server does not authenticate clients with secrets or assertions at the token endpoint")
		return nil, nil
	}
	var resp *mcpauth.TokenResponse
	var oe *mcpauth.OAuthError
	switch f.Get("grant_type") {
	case "authorization_code":
		in := mcpauth.CodeRequest{Code: f.Get("code"), Verifier: f.Get("code_verifier"), ClientID: f.Get("client_id"),
			RedirectURI: f.Get("redirect_uri"), Resource: f.Get("resource")}
		err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			g, err := graph.Build(tx, s.clock())
			if err != nil {
				return err
			}
			resp, oe, err = s.mcp.RedeemCode(tx, g, iss, in)
			return err
		})
		if err != nil {
			return nil, err
		}
	case mcpauth.GrantTokenExchange:
		in := mcpauth.ExchangeRequest{SubjectToken: f.Get("subject_token"), SubjectTokenType: f.Get("subject_token_type"),
			ActorToken: f.Get("actor_token"), ActorTokenType: f.Get("actor_token_type"), Resource: f.Get("resource"),
			Scope: f.Get("scope")}
		err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			g, err := graph.Build(tx, s.clock())
			if err != nil {
				return err
			}
			resp, oe, err = s.mcp.Exchange(tx, g, iss, in)
			return err
		})
		if err != nil {
			return nil, err
		}
	default:
		// refresh_token, client_credentials, password and the rest: not offered
		oauthFail(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or token exchange")
		return nil, nil
	}
	if oe != nil {
		oauthFailE(w, oe)
		return nil, nil
	}
	oauthWrite(w, http.StatusOK, resp)
	return nil, nil
}

// ---------------------------------------------------------------- introspection, revocation, decisions

func (s *Server) mcpIntrospect(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	f, ok := mcpForm(w, r)
	if !ok {
		return nil, nil
	}
	var out *mcpauth.Introspection
	var authed bool
	err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		res := mcpResourceAuth(tx, r)
		if res == nil {
			return nil
		}
		authed = true
		var err error
		out, _, err = s.mcp.Introspect(tx, iss, f.Get("token"), res)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !authed {
		oauthFail(w, http.StatusUnauthorized, "invalid_client", "resource server authentication failed")
		return nil, nil
	}
	oauthWrite(w, http.StatusOK, out)
	return nil, nil
}

// mcpRevoke is RFC 7009: whoever holds the token may revoke it. It answers
// 200 whatever the token was.
func (s *Server) mcpRevoke(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	f, ok := mcpForm(w, r)
	if !ok {
		return nil, nil
	}
	raw := f.Get("token")
	if raw != "" {
		err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
			c, err := mcpauth.Verify(tx, raw, iss, s.clock())
			if err != nil {
				if errors.Is(err, mcpauth.ErrTokenInvalid) || errors.Is(err, mcpauth.ErrTokenExpired) {
					return nil
				}
				return err
			}
			if row, err := tx.MCPToken(c.ID); err == nil && row.RevokedAt == nil {
				return s.mcp.RevokeToken(tx, c.ID, "revoked by the token holder")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	oauthWrite(w, http.StatusOK, map[string]any{})
	return nil, nil
}

type mcpDecisionBody struct {
	Token         string   `json:"token"`
	Tool          string   `json:"tool"`
	RequiredScope []string `json:"required_scope"`
}

// mcpDecisions answers a resource server's "may this token call this tool"
// and records the decision with the policy version.
func (s *Server) mcpDecisions(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	var b mcpDecisionBody
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "the body must be application/json")
		return nil, nil
	}
	if err := decodeBody(r, &b, false); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "the body is not the expected JSON object")
		return nil, nil
	}
	var allow bool
	var reason, jti string
	var authed bool
	err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		res := mcpResourceAuth(tx, r)
		if res == nil {
			return nil
		}
		authed = true
		var err error
		allow, reason, jti, err = s.mcp.DecideToolCall(tx, iss, res, mcpauth.ToolCall{Token: b.Token, Tool: b.Tool,
			RequiredScope: b.RequiredScope})
		return err
	})
	if err != nil {
		return nil, err
	}
	if !authed {
		oauthFail(w, http.StatusUnauthorized, "invalid_client", "resource server authentication failed")
		return nil, nil
	}
	oauthWrite(w, http.StatusOK, map[string]any{"allow": allow, "reason": reason, "jti": jti, "policy_version": s.policyVersion()})
	return nil, nil
}

// ---------------------------------------------------------------- authorization endpoint and consent

// principalIdentity is the graph identity of the signed-in user (the
// platform user's link), if any.
func principalIdentity(tx *store.TenantTx, pr *auth.Principal) (int64, bool, error) {
	if pr.UserID == nil {
		return 0, false, nil
	}
	u, err := tx.PlatformUser(*pr.UserID)
	if errors.Is(err, store.ErrNotFound) || err == nil && u.IdentityID == nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return *u.IdentityID, true, nil
}

// queryOf is the parsed query of u (the archtest bans .Query() calls on
// anything but a request URL).
func queryOf(u *url.URL) url.Values {
	q, _ := url.ParseQuery(u.RawQuery)
	return q
}

// authzRedirect sends the browser to a validated redirect URI with params.
func authzRedirect(w http.ResponseWriter, r *http.Request, base string, kv map[string]string) {
	u, err := url.Parse(base)
	if err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "bad redirect_uri")
		return
	}
	q := queryOf(u)
	for k, v := range kv {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound) // #nosec G710 -- the URI was matched exactly against the client's registered redirect_uris
}

func (s *Server) mcpAuthorize(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	pr := principal(r)
	t, iss, ok := s.mcpTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	if t.ID != pr.TenantID {
		oauthFail(w, http.StatusNotFound, "invalid_request", "unknown tenant")
		return nil, nil
	}
	q := r.URL.Query()
	for k, v := range q {
		if len(v) > 1 {
			oauthFail(w, http.StatusBadRequest, "invalid_request", "parameter "+k+" is repeated")
			return nil, nil
		}
	}
	client, err := s.mcp.Client(r.Context(), s.store, t.ID, q.Get("client_id"))
	var ce *mcpauth.ErrClient
	if errors.As(err, &ce) {
		oauthFail(w, http.StatusBadRequest, "invalid_request", ce.Msg)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ru := q.Get("redirect_uri")
	exact := false
	for _, u := range mcpauth.RedirectURIsOf(client) {
		exact = exact || u == ru
	}
	if !exact {
		// never redirect to an unregistered URI
		oauthFail(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered by the client")
		return nil, nil
	}
	state := q.Get("state")
	fail := func(code, desc string) (any, error) {
		authzRedirect(w, r, ru, map[string]string{"error": code, "error_description": desc, "state": state, "iss": iss})
		return nil, nil
	}
	if len(state) > 512 {
		return fail("invalid_request", "state is too long")
	}
	switch {
	case q.Get("response_type") != "code":
		return fail("unsupported_response_type", "only response_type=code is supported")
	case q.Get("code_challenge_method") != "S256" || !mcpauth.ValidChallenge(q.Get("code_challenge")):
		return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	resource := q.Get("resource")
	if err := mcpauth.ValidateResource(resource); err != nil {
		return fail("invalid_target", "resource is required (RFC 8707): "+err.Error())
	}
	scope, err := mcpauth.ParseScope(q.Get("scope"))
	if err != nil {
		return fail("invalid_scope", err.Error())
	}
	var req *store.MCPAuthRequest
	var oe *mcpauth.OAuthError
	err = s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		uid, ok, err := principalIdentity(tx, pr)
		if err != nil {
			return err
		}
		if !ok {
			oe = &mcpauth.OAuthError{Status: 403, Code: "access_denied", Desc: "your sign-in is not linked to an identity"}
			return nil
		}
		g, err := graph.Build(tx, s.clock())
		if err != nil {
			return err
		}
		req, _, oe, err = s.mcp.BeginAuthorization(tx, g, mcpauth.NewAuthRequest{Client: client, RedirectURI: ru, State: state,
			CodeChallenge: q.Get("code_challenge"), Resource: resource, Scope: scope, UserIdentity: uid})
		return err
	})
	if err != nil {
		return nil, err
	}
	if oe != nil {
		return fail(oe.Code, oe.Desc)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/agent-authorization?consent="+req.ID, http.StatusFound)
	return nil, nil
}

type consentView struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Client struct {
		ClientID     string   `json:"client_id"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Loopback     bool     `json:"loopback_redirect"`
	} `json:"client"`
	Agent struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"agent"`
	Resource      string   `json:"resource"`
	Requested     []string `json:"requested_scope"`
	Granted       []string `json:"granted_scope"`
	ExpiresAt     string   `json:"expires_at"`
	PolicyVersion string   `json:"policy_version"`
}

// ownRequest loads a pending-consent request that belongs to the signed-in user.
func ownRequest(tx *store.TenantTx, pr *auth.Principal, id string) (*store.MCPAuthRequest, bool, error) {
	if !idRE.MatchString(id) {
		return nil, false, nil
	}
	uid, ok, err := principalIdentity(tx, pr)
	if err != nil || !ok {
		return nil, false, err
	}
	req, err := tx.MCPAuthRequest(id)
	if errors.Is(err, store.ErrNotFound) || err == nil && req.UserIdentity != uid {
		return nil, false, nil
	}
	return req, err == nil, err
}

func (s *Server) mcpConsent(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	tx := store.TxFrom(r.Context())
	req, ok, err := ownRequest(tx, principal(r), p.path["id"])
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errStatus(http.StatusNotFound, "no such authorization request")
	}
	g, err := graph.Build(tx, s.clock())
	if err != nil {
		return nil, err
	}
	c, agent, granted, err := s.mcp.Grantable(tx, g, req)
	if err != nil {
		return nil, err
	}
	v := consentView{ID: req.ID, Status: req.Status, Resource: req.Resource, Requested: strings.Fields(req.Scope),
		Granted: granted, ExpiresAt: req.ExpiresAt.UTC().Format(time.RFC3339), PolicyVersion: s.policyVersion()}
	if v.Granted == nil {
		v.Granted = []string{}
	}
	v.Client.ClientID, v.Client.Name = c.ClientID, c.Name
	v.Client.RedirectURIs = mcpauth.RedirectURIsOf(c)
	v.Client.Loopback = mcpauth.HasLoopbackRedirect(v.Client.RedirectURIs)
	if agent != nil {
		v.Agent.ID, v.Agent.Name = agent.ID, agent.Name
	}
	return v, nil
}

// mcpConsentDecision approves or denies a pending request for the signed-in
// user (step-up). It runs its own transactions so the issuer lookup does not
// nest inside the write.
func (s *Server) mcpConsentDecision(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b struct {
		Approve bool `json:"approve"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	pr := principal(r)
	ctx := r.Context()
	var tenant store.Tenant
	if err := s.store.ReadSystem(ctx, "mcp consent issuer", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantByID(pr.TenantID)
		return err
	}); err != nil {
		return nil, err
	}
	iss := s.cfg.PublicURL + "/t/" + tenant.Slug
	var out map[string]any
	err := s.store.InTenant(ctx, pr.TenantID, func(tx *store.TenantTx) error {
		req, ok, err := ownRequest(tx, pr, p.path["id"])
		if err != nil {
			return err
		}
		if !ok {
			return errStatus(http.StatusNotFound, "no such authorization request")
		}
		g, err := graph.Build(tx, s.clock())
		if err != nil {
			return err
		}
		code, _, oe, err := s.mcp.Decide(tx, g, req, b.Approve)
		if err != nil {
			return err
		}
		kv := map[string]string{"state": req.State, "iss": iss}
		switch {
		case oe != nil && oe.Code == "access_denied":
			kv["error"], kv["error_description"] = oe.Code, oe.Desc
		case oe != nil:
			return errStatus(http.StatusConflict, oe.Desc)
		default:
			kv["code"] = code
		}
		u, err := url.Parse(req.RedirectURI)
		if err != nil {
			return err
		}
		q := queryOf(u)
		for k, v := range kv {
			if v != "" {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		out = map[string]any{"approved": oe == nil, "redirect_to": u.String()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	w.Header().Set("Cache-Control", "no-store")
	return out, nil
}
