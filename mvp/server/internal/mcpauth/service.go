package mcpauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Token types of RFC 8693.
const (
	TypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- an RFC 8693 type URI, not a credential
	TypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// Lifetimes.
const (
	// AuthRequestTTL is how long a pending consent request lives.
	AuthRequestTTL = 10 * time.Minute
	// CodeTTL is how long an authorization code lives after approval.
	CodeTTL = 60 * time.Second
)

// Service holds the collaborators of the authorization server. All methods
// that decide something take the caller's write transaction and record the
// decision (decision log and audit event) in it, so a decision and its record
// commit together.
type Service struct {
	// HTTP is the safehttp client for client metadata documents.
	HTTP   *http.Client
	Sealer *seal.Sealer
	Clock  func() time.Time
	// PolicyVersion names the policy set a decision used.
	PolicyVersion func() string
	// AllowLoopback lets a client_id name a loopback IP literal (dev and
	// tests); otherwise IP literals in private, loopback and link-local
	// ranges are refused before the fetch.
	AllowLoopback bool
	// TTL is the access-token lifetime; zero or more than MaxTTL means MaxTTL.
	TTL time.Duration
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) ttl() time.Duration {
	if s.TTL <= 0 || s.TTL > MaxTTL {
		return MaxTTL
	}
	return s.TTL
}

func (s *Service) policyVersion() string {
	if s.PolicyVersion != nil {
		if v := s.PolicyVersion(); v != "" {
			return v
		}
	}
	return "unversioned"
}

// OAuthError is an RFC 6749 error response. It is a result, not a Go error:
// the transaction that produced it still commits, so the denial is recorded.
type OAuthError struct {
	Status int
	Code   string
	Desc   string
}

func oerr(status int, code, desc string) *OAuthError {
	return &OAuthError{Status: status, Code: code, Desc: desc}
}

// TokenResponse is the RFC 6749 / 8693 token response. There is never a
// refresh token: an agent that needs a new token exchanges again.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
}

var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// ChallengeS256 is the S256 code challenge of a verifier.
func ChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ValidChallenge reports whether c has the shape of an S256 challenge.
func ValidChallenge(c string) bool {
	b, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil && len(b) == sha256.Size && len(c) == 43
}

// ---------------------------------------------------------------- records

// trail writes a decision-log row and its audit event in tx.
type trail struct {
	kind               string
	action             string
	allow              bool
	reason             string
	jti, clientID      string
	subject, agent     *int64
	resource, tool     string
	requested, granted string
	extra              ojson.Object
}

// clip bounds attacker-supplied text before it is stored or audited.
func clip(s string) string {
	if len(s) <= 512 {
		return strings.ToValidUTF8(s, "")
	}
	return strings.ToValidUTF8(s[:512], "")
}

func (s *Service) record(tx *store.TenantTx, t trail) error {
	t.reason, t.clientID, t.resource, t.tool = clip(t.reason), clip(t.clientID), clip(t.resource), clip(t.tool)
	t.requested, t.granted, t.jti = clip(t.requested), clip(t.granted), clip(t.jti)
	now := s.now()
	pv := s.policyVersion()
	if err := tx.InsertMCPDecision(&store.MCPDecision{At: now, Kind: t.kind, Allow: t.allow, Reason: t.reason, JTI: t.jti,
		ClientID: t.clientID, SubjectID: t.subject, AgentID: t.agent, Resource: t.resource, Tool: t.tool,
		RequestedScope: t.requested, GrantedScope: t.granted, PolicyVersion: pv}); err != nil {
		return err
	}
	d := ojson.Object{{Key: "decision", Value: map[bool]string{true: "allow", false: "deny"}[t.allow]},
		{Key: "client_id", Value: t.clientID}, {Key: "resource", Value: t.resource}}
	if t.jti != "" {
		d = append(d, ojson.KV{Key: "jti", Value: t.jti})
	}
	if t.subject != nil {
		d = append(d, ojson.KV{Key: "subject_identity_id", Value: *t.subject})
	}
	if t.agent != nil {
		d = append(d, ojson.KV{Key: "agent_identity_id", Value: *t.agent})
	}
	if t.tool != "" {
		d = append(d, ojson.KV{Key: "tool", Value: t.tool})
	}
	d = append(d, ojson.KV{Key: "requested_scope", Value: t.requested}, ojson.KV{Key: "granted_scope", Value: t.granted})
	if t.reason != "" {
		d = append(d, ojson.KV{Key: "reason", Value: t.reason})
	}
	d = append(d, t.extra...)
	out := store.OutcomeSuccess
	if !t.allow {
		out = store.OutcomeFailure
	}
	_, err := audit.Record(tx.Context(), tx, t.action, d, audit.At(now), audit.PolicyVersion(pv), audit.Outcome(out),
		audit.Target("mcp_client", t.clientID))
	return err
}

// deny records a refusal and returns it as the OAuth error.
func (s *Service) deny(tx *store.TenantTx, kind, action string, t trail, e *OAuthError) (*TokenResponse, *OAuthError, error) {
	t.kind, t.action, t.allow, t.reason = kind, action, false, e.Code+": "+e.Desc
	if err := s.record(tx, t); err != nil {
		return nil, nil, err
	}
	return nil, e, nil
}

// ---------------------------------------------------------------- helpers

func i64(v int64) *int64 { return &v }

// activeAgent returns the agent identity bound to the client when the client
// is active and the identity is an active ai_agent.
func activeAgent(tx *store.TenantTx, c *store.MCPClient) (*store.Identity, string) {
	if c.Status != "active" || c.AgentIdentityID == nil {
		return nil, "client is not approved and bound to an agent"
	}
	a, err := tx.Identity(*c.AgentIdentityID)
	if err != nil || a.Type != "ai_agent" || a.Status != "active" {
		return nil, "the agent identity is not an active ai_agent"
	}
	if contained, err := tx.MCPContained(a.ID); err != nil || contained {
		return nil, "the agent identity is contained"
	}
	return a, ""
}

// activeUser returns the identity when it is an active, uncontained person
// (or other non-agent identity).
func activeUser(tx *store.TenantTx, id int64) (*store.Identity, bool) {
	u, err := tx.Identity(id)
	if err != nil || u.Type == "ai_agent" || u.Status != "active" {
		return u, false
	}
	contained, err := tx.MCPContained(id)
	return u, err == nil && !contained
}

// liveRow reports why a token's record no longer counts: revoked, expired, or
// its client, agent or user is not active any more ("" when it is live).
func liveRow(tx *store.TenantTx, row *store.MCPToken, now time.Time) string {
	switch {
	case row.RevokedAt != nil:
		return "token is revoked"
	case !now.Before(row.ExpiresAt):
		return "token has expired"
	}
	if cl, err := tx.MCPClient(row.ClientID); err != nil || cl.Status != "active" {
		return "client is not active"
	}
	if a, err := tx.Identity(row.AgentID); err != nil || a.Status != "active" {
		return "agent is not active"
	} else if contained, err := tx.MCPContained(a.ID); err != nil || contained {
		return "agent is contained"
	}
	if _, ok := activeUser(tx, row.SubjectID); !ok {
		return "user is not active"
	}
	return ""
}

// hasDelegation reports whether the user has an unexpired delegation to the agent.
func hasDelegation(tx *store.TenantTx, agent, user int64, now time.Time) (bool, error) {
	ds, err := tx.Delegations()
	if err != nil {
		return false, err
	}
	for _, d := range ds {
		if d.AgentID == agent && d.PrincipalID == user && (d.ExpiresAt == nil || now.Before(*d.ExpiresAt)) {
			return true, nil
		}
	}
	return false, nil
}

// resourceFor returns the active registered resource server for a resource indicator.
func resourceFor(tx *store.TenantTx, uri string) (*store.MCPResource, bool) {
	r, err := tx.MCPResourceByURI(uri)
	return r, err == nil && r.Status == "active"
}

// ValidateResource checks the shape of a resource indicator (RFC 8707): an
// absolute https URI (http for loopback) without fragment.
func ValidateResource(uri string) error {
	if len(uri) > 512 || strings.ContainsAny(uri, " \t\r\n") {
		return errors.New("resource must be an absolute URI")
	}
	return ValidateRedirectURI(uri)
}

func (s *Service) issue(tx *store.TenantTx, issuer string, c *store.MCPClient, user, agent *store.Identity,
	res *store.MCPResource, scope []string, requested string, act *Actor, grant string) (*TokenResponse, *OAuthError, error) {
	now := s.now()
	ttl := s.ttl()
	jti := uuid.NewString()
	claims := Claims{Issuer: issuer, Subject: SubjectOf(user.ID), Audience: jwt.Audience{res.Resource},
		Expiry: jwt.NewNumericDate(now.Add(ttl)), NotBefore: jwt.NewNumericDate(now), IssuedAt: jwt.NewNumericDate(now),
		ID: jti, Scope: JoinScope(scope), ClientID: c.ClientID, Act: act, PolicyVersion: s.policyVersion()}
	raw, err := Mint(tx, s.Sealer, claims)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.InsertMCPToken(&store.MCPToken{JTI: jti, ClientID: c.ClientID, SubjectID: user.ID, AgentID: agent.ID,
		Audience: res.Resource, Scope: claims.Scope, Act: actJSON(act), GrantType: grant, PolicyVersion: claims.PolicyVersion,
		IssuedAt: now, ExpiresAt: now.Add(ttl)}); err != nil {
		return nil, nil, err
	}
	kind, action := store.MCPDecisionIssue, "mcp.token.issue"
	if grant == "token_exchange" {
		kind, action = store.MCPDecisionExchange, "mcp.token.exchange"
	}
	if err := s.record(tx, trail{kind: kind, action: action, allow: true, jti: jti, clientID: c.ClientID,
		subject: i64(user.ID), agent: i64(agent.ID), resource: res.Resource, requested: requested, granted: claims.Scope,
		extra: ojson.Object{{Key: "grant", Value: grant}, {Key: "act_depth", Value: act.Depth()},
			{Key: "expires_at", Value: store.RT(now.Add(ttl))}}}); err != nil {
		return nil, nil, err
	}
	return &TokenResponse{AccessToken: raw, IssuedTokenType: TypeAccessToken, TokenType: "Bearer",
		ExpiresIn: int(ttl / time.Second), Scope: claims.Scope}, nil, nil
}

// ---------------------------------------------------------------- authorization requests

// NewAuthRequest is a validated authorization request from the browser.
type NewAuthRequest struct {
	Client        *store.MCPClient
	RedirectURI   string
	State         string
	CodeChallenge string
	Resource      string
	Scope         []string
	UserIdentity  int64
}

// BeginAuthorization checks an authorization request against the graph and
// stores it pending the user's consent. The returned scope is what the user
// would be granting (user ∩ agent ∩ requested); an empty one is refused.
func (s *Service) BeginAuthorization(tx *store.TenantTx, g *graph.Snapshot, in NewAuthRequest) (*store.MCPAuthRequest, []string, *OAuthError, error) {
	now := s.now()
	t := trail{kind: store.MCPDecisionIssue, action: "mcp.authorize.deny", clientID: in.Client.ClientID,
		subject: i64(in.UserIdentity), resource: in.Resource, requested: JoinScope(in.Scope)}
	d := func(e *OAuthError) (*store.MCPAuthRequest, []string, *OAuthError, error) {
		t.reason = e.Code + ": " + e.Desc
		return nil, nil, e, s.record(tx, t)
	}
	agent, why := activeAgent(tx, in.Client)
	if agent == nil {
		return d(oerr(400, "unauthorized_client", why))
	}
	t.agent = i64(agent.ID)
	user, ok := activeUser(tx, in.UserIdentity)
	if !ok {
		return d(oerr(403, "access_denied", "your account is not an active user identity"))
	}
	if _, ok := resourceFor(tx, in.Resource); !ok {
		return d(oerr(400, "invalid_target", "resource is not a registered MCP resource"))
	}
	if del, err := hasDelegation(tx, agent.ID, user.ID, now); err != nil {
		return nil, nil, nil, err
	} else if !del {
		return d(oerr(403, "access_denied", "you have not delegated to this agent"))
	}
	granted := Effective(g, user.ID, agent.ID, in.Scope)
	if len(granted) == 0 {
		return d(oerr(400, "invalid_scope", "none of the requested scopes is allowed for you and this agent"))
	}
	req := &store.MCPAuthRequest{ClientID: in.Client.ClientID, RedirectURI: in.RedirectURI, State: in.State,
		CodeChallenge: in.CodeChallenge, Resource: in.Resource, Scope: JoinScope(in.Scope), UserIdentity: user.ID,
		CreatedAt: now, ExpiresAt: now.Add(AuthRequestTTL)}
	if err := tx.InsertMCPAuthRequest(req); err != nil {
		return nil, nil, nil, err
	}
	return req, granted, nil, nil
}

// Grantable recomputes what a pending request would grant now.
func (s *Service) Grantable(tx *store.TenantTx, g *graph.Snapshot, req *store.MCPAuthRequest) (*store.MCPClient, *store.Identity, []string, error) {
	c, err := tx.MCPClient(req.ClientID)
	if err != nil {
		return nil, nil, nil, err
	}
	agent, _ := activeAgent(tx, c)
	if agent == nil {
		return c, nil, nil, nil
	}
	task, err := ParseScope(req.Scope)
	if err != nil {
		return c, agent, nil, nil
	}
	return c, agent, Effective(g, req.UserIdentity, agent.ID, task), nil
}

// Decide approves or denies a pending request on behalf of its user. An
// approval yields the single-use code and the narrowed scope it will carry.
func (s *Service) Decide(tx *store.TenantTx, g *graph.Snapshot, req *store.MCPAuthRequest, approve bool) (code string, granted []string, oe *OAuthError, err error) {
	now := s.now()
	t := trail{kind: store.MCPDecisionIssue, action: "mcp.authorize.deny", clientID: req.ClientID, subject: i64(req.UserIdentity),
		resource: req.Resource, requested: req.Scope}
	switch {
	case req.Status != store.MCPAuthPending:
		return "", nil, oerr(400, "invalid_request", "this request was already decided"), nil
	case !now.Before(req.ExpiresAt):
		return "", nil, oerr(400, "invalid_request", "this request has expired"), nil
	}
	_, agent, granted, err := s.Grantable(tx, g, req)
	if err != nil {
		return "", nil, nil, err
	}
	if agent != nil {
		t.agent = i64(agent.ID)
	}
	if !approve || len(granted) == 0 {
		t.reason = "the user declined"
		if approve {
			t.reason = "nothing to grant"
		}
		if err := tx.DecideMCPAuthRequest(req.ID, store.MCPAuthDenied, nil, req.Scope, now); err != nil {
			return "", nil, nil, err
		}
		if err := s.record(tx, t); err != nil {
			return "", nil, nil, err
		}
		return "", nil, oerr(403, "access_denied", t.reason), nil
	}
	code = seal.RandomSecret(32)
	h := seal.SHA256Hex([]byte(code))
	if err := tx.DecideMCPAuthRequest(req.ID, store.MCPAuthApproved, &h, JoinScope(granted), now.Add(CodeTTL)); err != nil {
		return "", nil, nil, err
	}
	t.action, t.allow, t.granted = "mcp.authorize.approve", true, JoinScope(granted)
	if err := s.record(tx, t); err != nil {
		return "", nil, nil, err
	}
	return code, granted, nil, nil
}

// ---------------------------------------------------------------- authorization_code grant

// CodeRequest is a token request for the authorization_code grant.
type CodeRequest struct {
	Code, Verifier, ClientID, RedirectURI, Resource string
}

// RedeemCode exchanges an authorization code (with its PKCE verifier) for an
// access token for the code's resource. The code is single-use whatever the
// outcome of the remaining checks.
func (s *Service) RedeemCode(tx *store.TenantTx, g *graph.Snapshot, issuer string, in CodeRequest) (*TokenResponse, *OAuthError, error) {
	now := s.now()
	t := trail{clientID: in.ClientID, resource: in.Resource}
	d := func(e *OAuthError) (*TokenResponse, *OAuthError, error) {
		return s.deny(tx, store.MCPDecisionIssue, "mcp.token.deny", t, e)
	}
	if in.Code == "" || len(in.Code) > 256 || in.ClientID == "" || in.RedirectURI == "" || in.Resource == "" {
		return d(oerr(400, "invalid_request", "code, client_id, redirect_uri and resource are required"))
	}
	if !verifierRE.MatchString(in.Verifier) {
		return d(oerr(400, "invalid_request", "code_verifier is missing or malformed"))
	}
	client, err := tx.MCPClient(in.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return d(oerr(401, "invalid_client", "unknown client"))
	} else if err != nil {
		return nil, nil, err
	}
	agent, why := activeAgent(tx, client)
	if agent == nil {
		return d(oerr(401, "invalid_client", why))
	}
	t.agent = i64(agent.ID)
	req, err := tx.MCPAuthRequestByCode(seal.SHA256Hex([]byte(in.Code)))
	if errors.Is(err, store.ErrNotFound) {
		return d(oerr(400, "invalid_grant", "the code is unknown, used or expired"))
	} else if err != nil {
		return nil, nil, err
	}
	t.subject, t.requested = i64(req.UserIdentity), req.Scope
	if req.ClientID != client.ClientID || req.Status != store.MCPAuthApproved {
		return d(oerr(400, "invalid_grant", "the code is unknown, used or expired"))
	}
	// single use: consumed before any further check, so a failed attempt burns it
	if err := tx.RedeemMCPAuthRequest(req.ID); err != nil {
		return d(oerr(400, "invalid_grant", "the code is unknown, used or expired"))
	}
	switch {
	case !now.Before(req.ExpiresAt):
		return d(oerr(400, "invalid_grant", "the code is unknown, used or expired"))
	case req.RedirectURI != in.RedirectURI:
		return d(oerr(400, "invalid_grant", "redirect_uri does not match the authorization request"))
	case subtle.ConstantTimeCompare([]byte(ChallengeS256(in.Verifier)), []byte(req.CodeChallenge)) != 1:
		return d(oerr(400, "invalid_grant", "code_verifier does not match the code challenge"))
	case in.Resource != req.Resource:
		return d(oerr(400, "invalid_target", "resource does not match the authorization request"))
	}
	user, ok := activeUser(tx, req.UserIdentity)
	if !ok {
		return d(oerr(400, "invalid_grant", "the user is not active"))
	}
	res, ok := resourceFor(tx, req.Resource)
	if !ok {
		return d(oerr(400, "invalid_target", "resource is not a registered MCP resource"))
	}
	if del, err := hasDelegation(tx, agent.ID, user.ID, now); err != nil {
		return nil, nil, err
	} else if !del {
		return d(oerr(403, "access_denied", "the user's delegation to the agent has ended"))
	}
	// what the user approved, narrowed again by what is allowed now
	approved, err := ParseScope(req.Scope)
	if err != nil {
		return d(oerr(400, "invalid_scope", "malformed scope"))
	}
	scope := Effective(g, user.ID, agent.ID, approved)
	if len(scope) == 0 {
		return d(oerr(400, "invalid_scope", "nothing is allowed any more"))
	}
	act := &Actor{Sub: SubjectOf(agent.ID), ClientID: client.ClientID}
	return s.issue(tx, issuer, client, user, agent, res, scope, req.Scope, act, "authorization_code")
}

// ---------------------------------------------------------------- token exchange (RFC 8693)

// ExchangeRequest is a token-exchange request.
type ExchangeRequest struct {
	SubjectToken, SubjectTokenType string
	ActorToken, ActorTokenType     string
	Resource                       string
	Scope                          string
}

// Exchange issues a token for the subject's user, acted on by the actor's
// agent, for one resource, with scope = user ∩ agent ∩ task ∩ the subject
// token's scope. It never widens: an empty result is denied. The subject
// token and the actor assertion are both validated.
func (s *Service) Exchange(tx *store.TenantTx, g *graph.Snapshot, issuer string, in ExchangeRequest) (*TokenResponse, *OAuthError, error) {
	now := s.now()
	t := trail{resource: in.Resource, requested: in.Scope}
	d := func(e *OAuthError) (*TokenResponse, *OAuthError, error) {
		return s.deny(tx, store.MCPDecisionExchange, "mcp.token.deny", t, e)
	}
	switch {
	case in.SubjectToken == "" || in.ActorToken == "":
		return d(oerr(400, "invalid_request", "subject_token and actor_token are required"))
	case in.SubjectTokenType != TypeAccessToken:
		return d(oerr(400, "invalid_request", "subject_token_type must be "+TypeAccessToken))
	case in.ActorTokenType != TypeJWT:
		return d(oerr(400, "invalid_request", "actor_token_type must be "+TypeJWT))
	}
	task, err := ParseScope(in.Scope)
	if err != nil {
		return d(oerr(400, "invalid_scope", err.Error()))
	}
	if err := ValidateResource(in.Resource); err != nil {
		return d(oerr(400, "invalid_target", err.Error()))
	}
	res, ok := resourceFor(tx, in.Resource)
	if !ok {
		return d(oerr(400, "invalid_target", "resource is not a registered MCP resource"))
	}

	// the subject token: signature, type, lifetime, then the live record
	sc, err := Verify(tx, in.SubjectToken, issuer, now)
	if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenExpired) {
		return d(oerr(400, "invalid_grant", "subject_token is "+map[bool]string{true: "expired", false: "not valid"}[errors.Is(err, ErrTokenExpired)]))
	} else if err != nil {
		return nil, nil, err
	}
	row, err := tx.MCPToken(sc.ID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (row.RevokedAt != nil || SubjectOf(row.SubjectID) != sc.Subject) {
		return d(oerr(400, "invalid_grant", "subject_token is revoked or unknown"))
	} else if err != nil {
		return nil, nil, err
	}
	if why := liveRow(tx, row, now); why != "" {
		return d(oerr(400, "invalid_grant", "subject_token: "+why))
	}
	uid, _ := SubjectID(sc.Subject)
	t.subject = i64(uid)
	user, ok := activeUser(tx, uid)
	if !ok {
		return d(oerr(400, "invalid_grant", "the subject is not an active user"))
	}

	// the actor assertion: signed by the client's registered key
	client, aerr, err := s.verifyActor(tx, issuer, in.ActorToken, now)
	if err != nil {
		return nil, nil, err
	}
	if aerr != nil {
		return d(aerr)
	}
	t.clientID = client.ClientID
	agent, why := activeAgent(tx, client)
	if agent == nil {
		return d(oerr(401, "invalid_client", why))
	}
	t.agent = i64(agent.ID)

	// the chain: the agent acts for the user, after the actors of the subject token
	agentSub := SubjectOf(agent.ID)
	act := sc.Act
	switch {
	case act != nil && act.Sub == agentSub:
		// the same actor exchanging again: the chain is unchanged, and the token
		// may not be re-pointed at a resource the user did not consent to
		if in.Resource != row.Audience {
			return d(oerr(403, "access_denied", "the acting agent may not move this token to another resource"))
		}
	case act.Contains(agentSub):
		return d(oerr(403, "access_denied", "the agent is already in the delegation chain"))
	default:
		act = &Actor{Sub: agentSub, ClientID: client.ClientID, Act: act}
	}
	if act.Depth() > MaxActDepth {
		return d(oerr(403, "access_denied", "the delegation chain is too deep"))
	}
	if del, err := hasDelegation(tx, agent.ID, user.ID, now); err != nil {
		return nil, nil, err
	} else if !del {
		return d(oerr(403, "access_denied", "the user has no delegation to this agent"))
	}
	upstream, err := ParseScope(row.Scope)
	if err != nil {
		return d(oerr(400, "invalid_grant", "subject_token carries a malformed scope"))
	}
	scope := Effective(g, user.ID, agent.ID, task, upstream)
	if len(scope) == 0 {
		return d(oerr(403, "access_denied", "the intersection of the user's, the agent's, the task's and the subject token's scopes is empty"))
	}
	return s.issue(tx, issuer, client, user, agent, res, scope, in.Scope, act, "token_exchange")
}

// RefreshActorClient refreshes the cached metadata document of the client an
// actor assertion names, when that client is already known and its cache has
// expired, so the keys the assertion is checked against are current. It must
// run before Exchange, outside any transaction (it may fetch). It does not
// fetch for an unknown client (an anonymous caller cannot make the server
// fetch arbitrary URLs); a failed refresh is an error and the exchange fails
// closed.
func (s *Service) RefreshActorClient(ctx context.Context, db *store.DB, t tenancy.ID, rawActor string) error {
	tok, err := jwt.ParseSigned(rawActor, []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA})
	if err != nil {
		return nil // verifyActor rejects it
	}
	var peek jwt.Claims
	if tok.UnsafeClaimsWithoutVerification(&peek) != nil || peek.Issuer == "" {
		return nil
	}
	var known bool
	if err := db.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		c, err := tx.MCPClient(peek.Issuer)
		known = err == nil && !s.now().Before(c.ExpiresAt)
		return nil
	}); err != nil {
		return err
	}
	if !known {
		return nil
	}
	_, err = s.Client(ctx, db, t, peek.Issuer)
	return err
}

// verifyActor validates an actor assertion: a JWT signed (ES256, RS256 or
// EdDSA) with a key of the client's own metadata document, iss = sub =
// client_id, aud = this issuer, at most MaxTTL from expiry, a jti used once.
func (s *Service) verifyActor(tx *store.TenantTx, issuer, raw string, now time.Time) (*store.MCPClient, *OAuthError, error) {
	bad := func(msg string) (*store.MCPClient, *OAuthError, error) {
		return nil, oerr(401, "invalid_client", "actor_token: "+msg), nil
	}
	if len(raw) > MaxTokenBytes {
		return bad("too large")
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA})
	if err != nil || len(tok.Headers) != 1 || tok.Headers[0].KeyID == "" {
		return bad("not a signed JWT with a kid")
	}
	var peek jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&peek); err != nil || peek.Issuer == "" {
		return bad("malformed claims")
	}
	client, err := tx.MCPClient(peek.Issuer)
	if errors.Is(err, store.ErrNotFound) {
		return bad("unknown client")
	} else if err != nil {
		return nil, nil, err
	}
	if !now.Before(client.ExpiresAt) {
		// the cached document (and so its keys) is past its TTL: the caller must refresh it first
		return bad("the client's metadata is stale")
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal([]byte(client.JWKS), &set) != nil {
		return bad("the client has no usable keys")
	}
	ks := set.Key(tok.Headers[0].KeyID)
	if len(ks) != 1 {
		return bad("unknown key")
	}
	var c jwt.Claims
	if err := tok.Claims(ks[0].Key, &c); err != nil {
		return bad("bad signature")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: client.ClientID, Subject: client.ClientID,
		AnyAudience: []string{issuer}, Time: now}, 0); err != nil {
		return bad("invalid claims")
	}
	if c.Expiry == nil || c.ID == "" || len(c.ID) > 128 || c.Expiry.Time().Sub(now) > MaxTTL {
		return bad("exp (at most 5 minutes ahead) and jti are required")
	}
	fresh, err := tx.UseMCPActorJTI(seal.SHA256Hex([]byte(client.ClientID+"|"+c.ID)), c.Expiry.Time(), now)
	if err != nil {
		return nil, nil, err
	}
	if !fresh {
		return bad("replayed")
	}
	return client, nil, nil
}

// ---------------------------------------------------------------- introspection and decisions

// Introspection is the RFC 7662 answer. Active is false for every token that
// is not valid, revoked, expired, for another audience, or whose client, agent
// or user is no longer active.
type Introspection struct {
	Active        bool   `json:"active"`
	Scope         string `json:"scope,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	TokenType     string `json:"token_type,omitempty"`
	Exp           int64  `json:"exp,omitempty"`
	Iat           int64  `json:"iat,omitempty"`
	Sub           string `json:"sub,omitempty"`
	Aud           string `json:"aud,omitempty"`
	Iss           string `json:"iss,omitempty"`
	JTI           string `json:"jti,omitempty"`
	Act           *Actor `json:"act,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	scopes        []string
	agent         int64
}

// Introspect checks a token for the resource server res. It writes nothing.
func (s *Service) Introspect(tx *store.TenantTx, issuer, raw string, res *store.MCPResource) (*Introspection, string, error) {
	now := s.now()
	c, err := Verify(tx, raw, issuer, now)
	if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenExpired) {
		return &Introspection{}, err.Error(), nil
	} else if err != nil {
		return nil, "", err
	}
	if c.Audience[0] != res.Resource {
		return &Introspection{}, "token is for another audience", nil
	}
	row, err := tx.MCPToken(c.ID)
	if errors.Is(err, store.ErrNotFound) {
		return &Introspection{}, "token is unknown", nil
	} else if err != nil {
		return nil, "", err
	}
	if why := liveRow(tx, row, now); why != "" {
		return &Introspection{}, why, nil
	}
	scopes, _ := ParseScope(c.Scope)
	return &Introspection{Active: true, Scope: c.Scope, ClientID: c.ClientID, TokenType: "Bearer", Exp: c.Expiry.Time().Unix(),
		Iat: c.IssuedAt.Time().Unix(), Sub: c.Subject, Aud: c.Audience[0], Iss: c.Issuer, JTI: c.ID, Act: c.Act,
		PolicyVersion: c.PolicyVersion, scopes: scopes, agent: row.AgentID}, "", nil
}

// ToolCall is a resource server's question: may this token call this tool,
// which needs these scopes?
type ToolCall struct {
	Token         string
	Tool          string
	RequiredScope []string
}

// DecideToolCall answers and records the decision with the policy version. A
// call that names no required scope is denied (a tool must declare what it
// needs).
func (s *Service) DecideToolCall(tx *store.TenantTx, issuer string, res *store.MCPResource, in ToolCall) (allow bool, reason string, jti string, err error) {
	in.Tool = strings.TrimSpace(in.Tool)
	t := trail{kind: store.MCPDecisionToolCall, action: "mcp.tool_call.decision", resource: res.Resource, tool: in.Tool,
		requested: JoinScope(in.RequiredScope)}
	intro, why, err := s.Introspect(tx, issuer, in.Token, res)
	if err != nil {
		return false, "", "", err
	}
	switch {
	case in.Tool == "" || len(in.Tool) > 128:
		reason = "tool is required"
	case len(in.RequiredScope) == 0 || len(in.RequiredScope) > MaxScopes:
		reason = "required_scope must list the scopes the tool needs"
	case !intro.Active:
		reason = why
	case !Subset(in.RequiredScope, intro.scopes):
		reason = "the token's scope does not cover the tool"
	}
	if intro.Active {
		t.jti, t.clientID, t.granted = intro.JTI, intro.ClientID, intro.Scope
		if id, ok := SubjectID(intro.Sub); ok {
			t.subject = i64(id)
		}
		t.agent = i64(intro.agent)
	}
	allow = reason == ""
	t.allow, t.reason = allow, reason
	if err := s.record(tx, t); err != nil {
		return false, "", "", err
	}
	return allow, reason, t.jti, nil
}

// ---------------------------------------------------------------- revocation

// RevokeToken revokes one token by jti and records it.
func (s *Service) RevokeToken(tx *store.TenantTx, jti, reason string) error {
	now := s.now()
	row, err := tx.MCPToken(jti)
	if err != nil {
		return err
	}
	if err := tx.RevokeMCPToken(jti, reason, now); err != nil {
		return err
	}
	return s.record(tx, trail{kind: store.MCPDecisionRevoke, action: "mcp.token.revoke", allow: true, reason: reason, jti: jti,
		clientID: row.ClientID, subject: i64(row.SubjectID), agent: i64(row.AgentID), resource: row.Audience,
		granted: row.Scope})
}

// RevokeIdentity is the kill switch's hook, all in the caller's transaction:
// it marks the identity contained (so no new authorization, code redemption or
// exchange succeeds for it as agent or user), disables the clients bound to
// it, denies its pending and approved requests, and revokes every live token
// whose agent or user it is. It records the event when anything changed and
// returns the number of tokens revoked.
func (s *Service) RevokeIdentity(tx *store.TenantTx, identityID int64, reason string) (int64, error) {
	now := s.now()
	first, err := tx.MarkMCPContained(identityID, reason, now)
	if err != nil {
		return 0, err
	}
	clients, err := tx.DisableMCPClientsOfAgent(identityID, now)
	if err != nil {
		return 0, err
	}
	reqs, err := tx.DenyMCPAuthRequestsOfIdentity(identityID)
	if err != nil {
		return 0, err
	}
	n, err := tx.RevokeMCPTokensOfIdentity(identityID, reason, now)
	if err != nil || (!first && n == 0 && clients == 0 && reqs == 0) {
		return n, err
	}
	return n, s.record(tx, trail{kind: store.MCPDecisionRevoke, action: "mcp.tokens.revoke_identity", allow: true, reason: reason,
		agent: i64(identityID), extra: ojson.Object{{Key: "identity_id", Value: identityID}, {Key: "tokens_revoked", Value: n},
			{Key: "clients_disabled", Value: clients}, {Key: "requests_denied", Value: reqs}}})
}

// RevokeClient revokes every live token of a client (it was disabled).
func (s *Service) RevokeClient(tx *store.TenantTx, clientID, reason string) (int64, error) {
	n, err := tx.RevokeMCPTokensOfClient(clientID, reason, s.now())
	if err != nil || n == 0 {
		return n, err
	}
	return n, s.record(tx, trail{kind: store.MCPDecisionRevoke, action: "mcp.tokens.revoke_client", allow: true, reason: reason,
		clientID: clientID, extra: ojson.Object{{Key: "tokens_revoked", Value: n}}})
}

// RevokeResource revokes every live token for a resource (it was disabled).
func (s *Service) RevokeResource(tx *store.TenantTx, resource, reason string) (int64, error) {
	n, err := tx.RevokeMCPTokensOfAudience(resource, reason, s.now())
	if err != nil || n == 0 {
		return n, err
	}
	return n, s.record(tx, trail{kind: store.MCPDecisionRevoke, action: "mcp.tokens.revoke_resource", allow: true, reason: reason,
		resource: resource, extra: ojson.Object{{Key: "tokens_revoked", Value: n}}})
}
