package store

import (
	"database/sql"
	"time"
)

// MCP authorization server storage (schema/0290_mcp_authz.sql). Secrets are
// hashes (resource secrets, authorization codes); access tokens are never
// stored, only their jti and metadata.

// ---------------------------------------------------------------- resources

// MCPResource is a registered resource server: the audience of tokens.
type MCPResource struct {
	ID         string
	Resource   string
	Name       string
	SecretHash string
	Status     string // active | disabled
	CreatedBy  string
	CreatedAt  time.Time
}

const mcpResourceCols = `r.id, r.resource, r.name, r.secret_hash, r.status, r.created_by, r.created_at`

var (
	mcpResourcesInsert = tq("mcp_resources.insert", `
		INSERT INTO mcp_resources (id, tenant_id, resource, name, secret_hash, status, created_by, created_at)
		VALUES (@id, @tenant, @resource, @name, @secret_hash, 'active', @created_by, @created_at)`)
	mcpResourcesList = tq("mcp_resources.list", `
		SELECT `+mcpResourceCols+` FROM mcp_resources r WHERE r.tenant_id = @tenant ORDER BY r.created_at, r.id`)
	mcpResourcesGet = tq("mcp_resources.get", `
		SELECT `+mcpResourceCols+` FROM mcp_resources r WHERE r.tenant_id = @tenant AND r.id = @id`)
	mcpResourcesByURI = tq("mcp_resources.by_uri", `
		SELECT `+mcpResourceCols+` FROM mcp_resources r WHERE r.tenant_id = @tenant AND r.resource = @resource`)
	mcpResourcesSetStatus = tq("mcp_resources.set_status", `
		UPDATE mcp_resources SET status = @status WHERE tenant_id = @tenant AND id = @id`)
)

func scanMCPResource(s scanner) (*MCPResource, error) {
	var r MCPResource
	var at string
	if err := s.Scan(&r.ID, &r.Resource, &r.Name, &r.SecretHash, &r.Status, &r.CreatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	r.CreatedAt, err = ParseRT(at)
	return &r, err
}

// InsertMCPResource registers a resource server (r.ID is set when empty).
func (tx *TenantTx) InsertMCPResource(r *MCPResource) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	_, err := tx.exec(mcpResourcesInsert, sql.Named("id", r.ID), sql.Named("resource", r.Resource), sql.Named("name", r.Name),
		sql.Named("secret_hash", r.SecretHash), sql.Named("created_by", r.CreatedBy), sql.Named("created_at", RT(r.CreatedAt)))
	return err
}

// MCPResources lists the tenant's resource servers.
func (tx *TenantTx) MCPResources() ([]*MCPResource, error) {
	return collect(tx, scanMCPResource, mcpResourcesList)
}

// MCPResource returns one resource server or ErrNotFound.
func (tx *TenantTx) MCPResource(id string) (*MCPResource, error) {
	return one(tx, scanMCPResource, mcpResourcesGet, sql.Named("id", id))
}

// MCPResourceByURI returns the resource server with this resource URI or ErrNotFound.
func (tx *TenantTx) MCPResourceByURI(uri string) (*MCPResource, error) {
	return one(tx, scanMCPResource, mcpResourcesByURI, sql.Named("resource", uri))
}

// SetMCPResourceStatus enables or disables a resource server.
func (tx *TenantTx) SetMCPResourceStatus(id, status string) error {
	return tx.execOne(mcpResourcesSetStatus, sql.Named("id", id), sql.Named("status", status))
}

// ---------------------------------------------------------------- clients

// MCPClient is a CIMD client: the cached document and the admin's decision.
type MCPClient struct {
	ID              string
	ClientID        string // the metadata document URL
	Name            string
	RedirectURIs    string // JSON array
	JWKS            string // JSON Web Key Set (inline keys of the document)
	AgentIdentityID *int64
	Status          string // pending | active | disabled
	DocSHA256       string
	FetchedAt       time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const mcpClientCols = `c.id, c.client_id, c.client_name, c.redirect_uris, c.jwks, c.agent_identity_id, c.status, c.doc_sha256,
	c.fetched_at, c.expires_at, c.created_at, c.updated_at`

var (
	mcpClientsUpsert = tq("mcp_clients.upsert", `
		INSERT INTO mcp_clients (id, tenant_id, client_id, client_name, redirect_uris, jwks, status, doc_sha256, fetched_at,
			expires_at, created_at, updated_at)
		VALUES (@id, @tenant, @client_id, @client_name, @redirect_uris, @jwks, 'pending', @doc_sha256, @now, @expires_at, @now, @now)
		ON CONFLICT (tenant_id, client_id) DO UPDATE SET client_name = excluded.client_name,
			redirect_uris = excluded.redirect_uris, jwks = excluded.jwks, doc_sha256 = excluded.doc_sha256,
			fetched_at = excluded.fetched_at, expires_at = excluded.expires_at, updated_at = excluded.updated_at`)
	mcpClientsGet = tq("mcp_clients.get", `
		SELECT `+mcpClientCols+` FROM mcp_clients c WHERE c.tenant_id = @tenant AND c.client_id = @client_id`)
	mcpClientsList = tq("mcp_clients.list", `
		SELECT `+mcpClientCols+` FROM mcp_clients c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.id`)
	mcpClientsSet = tq("mcp_clients.set", `
		UPDATE mcp_clients SET agent_identity_id = @agent_identity_id, status = @status, updated_at = @now
		WHERE tenant_id = @tenant AND client_id = @client_id`)
)

func scanMCPClient(s scanner) (*MCPClient, error) {
	var c MCPClient
	var agent sql.NullInt64
	var fetched, expires, created, updated string
	if err := s.Scan(&c.ID, &c.ClientID, &c.Name, &c.RedirectURIs, &c.JWKS, &agent, &c.Status, &c.DocSHA256, &fetched,
		&expires, &created, &updated); err != nil {
		return nil, err
	}
	c.AgentIdentityID = intp(agent)
	var err error
	if c.FetchedAt, err = ParseRT(fetched); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = ParseRT(updated)
	return &c, err
}

// UpsertMCPClient stores a freshly fetched document. A new client starts
// pending and unbound; an existing client keeps its binding and status.
func (tx *TenantTx) UpsertMCPClient(c *MCPClient, now time.Time) error {
	if c.ID == "" {
		c.ID = NewID()
	}
	_, err := tx.exec(mcpClientsUpsert, sql.Named("id", c.ID), sql.Named("client_id", c.ClientID),
		sql.Named("client_name", c.Name), sql.Named("redirect_uris", c.RedirectURIs), sql.Named("jwks", c.JWKS),
		sql.Named("doc_sha256", c.DocSHA256), sql.Named("expires_at", RT(c.ExpiresAt)), sql.Named("now", RT(now)))
	return err
}

// MCPClient returns the client with this client_id URL or ErrNotFound.
func (tx *TenantTx) MCPClient(clientID string) (*MCPClient, error) {
	return one(tx, scanMCPClient, mcpClientsGet, sql.Named("client_id", clientID))
}

// MCPClients lists the tenant's clients.
func (tx *TenantTx) MCPClients() ([]*MCPClient, error) {
	return collect(tx, scanMCPClient, mcpClientsList)
}

// SetMCPClient binds a client to an agent identity (nil: unbound) and sets its status.
func (tx *TenantTx) SetMCPClient(clientID string, agentID *int64, status string, now time.Time) error {
	return tx.execOne(mcpClientsSet, sql.Named("client_id", clientID), sql.Named("agent_identity_id", IP(agentID)),
		sql.Named("status", status), sql.Named("now", RT(now)))
}

// ---------------------------------------------------------------- authorization requests

// Authorization request statuses.
const (
	MCPAuthPending  = "pending"
	MCPAuthApproved = "approved"
	MCPAuthDenied   = "denied"
	MCPAuthRedeemed = "redeemed"
)

// MCPAuthRequest is a pending authorization request, then its single-use code.
type MCPAuthRequest struct {
	ID            string
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string
	Resource      string
	Scope         string
	UserIdentity  int64
	Status        string
	CodeHash      *string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

const mcpAuthCols = `a.id, a.client_id, a.redirect_uri, a.state, a.code_challenge, a.resource, a.scope, a.user_identity_id,
	a.status, a.code_hash, a.created_at, a.expires_at`

var (
	mcpAuthInsert = tq("mcp_auth_requests.insert", `
		INSERT INTO mcp_auth_requests (id, tenant_id, client_id, redirect_uri, state, code_challenge, resource, scope,
			user_identity_id, status, created_at, expires_at)
		VALUES (@id, @tenant, @client_id, @redirect_uri, @state, @code_challenge, @resource, @scope, @user_identity_id,
			'pending', @created_at, @expires_at)`)
	mcpAuthGet = tq("mcp_auth_requests.get", `
		SELECT `+mcpAuthCols+` FROM mcp_auth_requests a WHERE a.tenant_id = @tenant AND a.id = @id`)
	mcpAuthByCode = tq("mcp_auth_requests.by_code", `
		SELECT `+mcpAuthCols+` FROM mcp_auth_requests a WHERE a.tenant_id = @tenant AND a.code_hash = @code_hash`)
	mcpAuthDecide = tq("mcp_auth_requests.decide", `
		UPDATE mcp_auth_requests SET status = @status, code_hash = @code_hash, scope = @scope, expires_at = @expires_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
	mcpAuthRedeem = tq("mcp_auth_requests.redeem", `
		UPDATE mcp_auth_requests SET status = 'redeemed' WHERE tenant_id = @tenant AND id = @id AND status = 'approved'`)
)

func scanMCPAuth(s scanner) (*MCPAuthRequest, error) {
	var a MCPAuthRequest
	var code sql.NullString
	var created, expires string
	if err := s.Scan(&a.ID, &a.ClientID, &a.RedirectURI, &a.State, &a.CodeChallenge, &a.Resource, &a.Scope,
		&a.UserIdentity, &a.Status, &code, &created, &expires); err != nil {
		return nil, err
	}
	a.CodeHash = strp(code)
	var err error
	if a.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	a.ExpiresAt, err = ParseRT(expires)
	return &a, err
}

// InsertMCPAuthRequest stores a pending request (a.ID is set when empty).
func (tx *TenantTx) InsertMCPAuthRequest(a *MCPAuthRequest) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	a.Status = MCPAuthPending
	_, err := tx.exec(mcpAuthInsert, sql.Named("id", a.ID), sql.Named("client_id", a.ClientID),
		sql.Named("redirect_uri", a.RedirectURI), sql.Named("state", a.State), sql.Named("code_challenge", a.CodeChallenge),
		sql.Named("resource", a.Resource), sql.Named("scope", a.Scope), sql.Named("user_identity_id", a.UserIdentity),
		sql.Named("created_at", RT(a.CreatedAt)), sql.Named("expires_at", RT(a.ExpiresAt)))
	return err
}

// MCPAuthRequest returns one request or ErrNotFound.
func (tx *TenantTx) MCPAuthRequest(id string) (*MCPAuthRequest, error) {
	return one(tx, scanMCPAuth, mcpAuthGet, sql.Named("id", id))
}

// MCPAuthRequestByCode returns the request whose code has this hash or ErrNotFound.
func (tx *TenantTx) MCPAuthRequestByCode(codeHash string) (*MCPAuthRequest, error) {
	return one(tx, scanMCPAuth, mcpAuthByCode, sql.Named("code_hash", codeHash))
}

// DecideMCPAuthRequest approves (with the code hash and the granted scope) or
// denies a pending request; ErrNotFound when it is not pending.
func (tx *TenantTx) DecideMCPAuthRequest(id, status string, codeHash *string, scope string, expires time.Time) error {
	return tx.execOne(mcpAuthDecide, sql.Named("id", id), sql.Named("status", status), sql.Named("code_hash", SP(codeHash)),
		sql.Named("scope", scope), sql.Named("expires_at", RT(expires)))
}

// RedeemMCPAuthRequest consumes an approved code exactly once (ErrNotFound
// when it was already redeemed).
func (tx *TenantTx) RedeemMCPAuthRequest(id string) error {
	return tx.execOne(mcpAuthRedeem, sql.Named("id", id))
}

// ---------------------------------------------------------------- tokens

// MCPToken is an issued access token's record.
type MCPToken struct {
	JTI           string
	ClientID      string
	SubjectID     int64
	AgentID       int64
	Audience      string
	Scope         string
	Act           string // JSON act chain
	GrantType     string // authorization_code | token_exchange
	PolicyVersion string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

// #nosec G101 -- a column list, not a credential
const mcpTokenCols = `t.jti, t.client_id, t.subject_identity_id, t.agent_identity_id, t.audience, t.scope, t.act, t.grant_type,
	t.policy_version, t.issued_at, t.expires_at, t.revoked_at, t.revoked_reason`

var (
	mcpTokensInsert = tq("mcp_tokens.insert", `
		INSERT INTO mcp_tokens (jti, tenant_id, client_id, subject_identity_id, agent_identity_id, audience, scope, act,
			grant_type, policy_version, issued_at, expires_at)
		VALUES (@jti, @tenant, @client_id, @subject_identity_id, @agent_identity_id, @audience, @scope, @act, @grant_type,
			@policy_version, @issued_at, @expires_at)`)
	mcpTokensGet = tq("mcp_tokens.get", `
		SELECT `+mcpTokenCols+` FROM mcp_tokens t WHERE t.tenant_id = @tenant AND t.jti = @jti`)
	mcpTokensList = tq("mcp_tokens.list", `
		SELECT `+mcpTokenCols+` FROM mcp_tokens t WHERE t.tenant_id = @tenant ORDER BY t.issued_at DESC, t.jti LIMIT 500`)
	mcpTokensRevoke = tq("mcp_tokens.revoke", `
		UPDATE mcp_tokens SET revoked_at = @now, revoked_reason = @reason
		WHERE tenant_id = @tenant AND jti = @jti AND revoked_at IS NULL`)
	mcpTokensRevokeIdentity = tq("mcp_tokens.revoke_identity", `
		UPDATE mcp_tokens SET revoked_at = @now, revoked_reason = @reason
		WHERE tenant_id = @tenant AND revoked_at IS NULL AND (agent_identity_id = @identity_id OR subject_identity_id = @identity_id)`)
	mcpTokensRevokeClient = tq("mcp_tokens.revoke_client", `
		UPDATE mcp_tokens SET revoked_at = @now, revoked_reason = @reason
		WHERE tenant_id = @tenant AND revoked_at IS NULL AND client_id = @client_id`)
	mcpTokensRevokeAudience = tq("mcp_tokens.revoke_audience", `
		UPDATE mcp_tokens SET revoked_at = @now, revoked_reason = @reason
		WHERE tenant_id = @tenant AND revoked_at IS NULL AND audience = @audience`)
)

func scanMCPToken(s scanner) (*MCPToken, error) {
	var t MCPToken
	var issued, expires string
	var revoked sql.NullString
	if err := s.Scan(&t.JTI, &t.ClientID, &t.SubjectID, &t.AgentID, &t.Audience, &t.Scope, &t.Act, &t.GrantType,
		&t.PolicyVersion, &issued, &expires, &revoked, &t.RevokedReason); err != nil {
		return nil, err
	}
	var err error
	if t.IssuedAt, err = ParseRT(issued); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	t.RevokedAt, err = rtp(revoked)
	return &t, err
}

// InsertMCPToken records an issued token.
func (tx *TenantTx) InsertMCPToken(t *MCPToken) error {
	_, err := tx.exec(mcpTokensInsert, sql.Named("jti", t.JTI), sql.Named("client_id", t.ClientID),
		sql.Named("subject_identity_id", t.SubjectID), sql.Named("agent_identity_id", t.AgentID),
		sql.Named("audience", t.Audience), sql.Named("scope", t.Scope), sql.Named("act", t.Act),
		sql.Named("grant_type", t.GrantType), sql.Named("policy_version", t.PolicyVersion),
		sql.Named("issued_at", RT(t.IssuedAt)), sql.Named("expires_at", RT(t.ExpiresAt)))
	return err
}

// MCPToken returns a token record or ErrNotFound.
func (tx *TenantTx) MCPToken(jti string) (*MCPToken, error) {
	return one(tx, scanMCPToken, mcpTokensGet, sql.Named("jti", jti))
}

// MCPTokens lists the newest 500 token records.
func (tx *TenantTx) MCPTokens() ([]*MCPToken, error) { return collect(tx, scanMCPToken, mcpTokensList) }

// RevokeMCPToken revokes one live token; ErrNotFound when unknown or already revoked.
func (tx *TenantTx) RevokeMCPToken(jti, reason string, now time.Time) error {
	return tx.execOne(mcpTokensRevoke, sql.Named("jti", jti), sql.Named("reason", reason), sql.Named("now", RT(now)))
}

func (tx *TenantTx) revokeMany(s tstmt, now time.Time, reason string, args ...sql.NamedArg) (int64, error) {
	args = append(args, sql.Named("reason", reason), sql.Named("now", RT(now)))
	res, err := tx.exec(s, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeMCPTokensOfIdentity revokes every live token whose agent or subject is
// the identity (the kill switch) and returns how many.
func (tx *TenantTx) RevokeMCPTokensOfIdentity(identityID int64, reason string, now time.Time) (int64, error) {
	return tx.revokeMany(mcpTokensRevokeIdentity, now, reason, sql.Named("identity_id", identityID))
}

// RevokeMCPTokensOfClient revokes every live token issued to a client.
func (tx *TenantTx) RevokeMCPTokensOfClient(clientID, reason string, now time.Time) (int64, error) {
	return tx.revokeMany(mcpTokensRevokeClient, now, reason, sql.Named("client_id", clientID))
}

// RevokeMCPTokensOfAudience revokes every live token for a resource.
func (tx *TenantTx) RevokeMCPTokensOfAudience(audience, reason string, now time.Time) (int64, error) {
	return tx.revokeMany(mcpTokensRevokeAudience, now, reason, sql.Named("audience", audience))
}

// ---------------------------------------------------------------- decisions

// MCP decision kinds.
const (
	MCPDecisionIssue    = "issue"
	MCPDecisionExchange = "exchange"
	MCPDecisionToolCall = "tool_call"
	MCPDecisionRevoke   = "revoke"
)

// MCPDecision is one row of the decision log.
type MCPDecision struct {
	ID             int64
	At             time.Time
	Kind           string
	Allow          bool
	Reason         string
	JTI            string
	ClientID       string
	SubjectID      *int64
	AgentID        *int64
	Resource       string
	Tool           string
	RequestedScope string
	GrantedScope   string
	PolicyVersion  string
}

var (
	mcpDecisionsInsert = tq("mcp_decisions.insert", `
		INSERT INTO mcp_decisions (tenant_id, at, kind, decision, reason, jti, client_id, subject_identity_id,
			agent_identity_id, resource, tool, requested_scope, granted_scope, policy_version)
		VALUES (@tenant, @at, @kind, @decision, @reason, @jti, @client_id, @subject_identity_id, @agent_identity_id,
			@resource, @tool, @requested_scope, @granted_scope, @policy_version)`)
	mcpDecisionsList = tq("mcp_decisions.list", `
		SELECT d.id, d.at, d.kind, d.decision, d.reason, d.jti, d.client_id, d.subject_identity_id, d.agent_identity_id,
			d.resource, d.tool, d.requested_scope, d.granted_scope, d.policy_version
		FROM mcp_decisions d WHERE d.tenant_id = @tenant ORDER BY d.id DESC LIMIT @limit`)
)

func scanMCPDecision(s scanner) (*MCPDecision, error) {
	var d MCPDecision
	var at, dec string
	var subj, agent sql.NullInt64
	if err := s.Scan(&d.ID, &at, &d.Kind, &dec, &d.Reason, &d.JTI, &d.ClientID, &subj, &agent, &d.Resource, &d.Tool,
		&d.RequestedScope, &d.GrantedScope, &d.PolicyVersion); err != nil {
		return nil, err
	}
	d.Allow = dec == "allow"
	d.SubjectID, d.AgentID = intp(subj), intp(agent)
	var err error
	d.At, err = ParseRT(at)
	return &d, err
}

// InsertMCPDecision appends to the decision log.
func (tx *TenantTx) InsertMCPDecision(d *MCPDecision) error {
	dec := "deny"
	if d.Allow {
		dec = "allow"
	}
	_, err := tx.exec(mcpDecisionsInsert, sql.Named("at", RT(d.At)), sql.Named("kind", d.Kind), sql.Named("decision", dec),
		sql.Named("reason", d.Reason), sql.Named("jti", d.JTI), sql.Named("client_id", d.ClientID),
		sql.Named("subject_identity_id", IP(d.SubjectID)), sql.Named("agent_identity_id", IP(d.AgentID)),
		sql.Named("resource", d.Resource), sql.Named("tool", d.Tool), sql.Named("requested_scope", d.RequestedScope),
		sql.Named("granted_scope", d.GrantedScope), sql.Named("policy_version", d.PolicyVersion))
	return err
}

// MCPDecisions lists the newest decisions (limit 1..500).
func (tx *TenantTx) MCPDecisions(limit int) ([]*MCPDecision, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	return collect(tx, scanMCPDecision, mcpDecisionsList, sql.Named("limit", limit))
}

// ---------------------------------------------------------------- actor assertion replay

var (
	mcpJTIPurge = tq("mcp_actor_jtis.purge", `DELETE FROM mcp_actor_jtis WHERE tenant_id = @tenant AND expires_at <= @now`)
	mcpJTISeen  = tq("mcp_actor_jtis.seen", `
		SELECT count(*) FROM mcp_actor_jtis j WHERE j.tenant_id = @tenant AND j.jti_hash = @jti_hash`)
	mcpJTIInsert = tq("mcp_actor_jtis.insert", `
		INSERT INTO mcp_actor_jtis (tenant_id, jti_hash, expires_at) VALUES (@tenant, @jti_hash, @expires_at)`)
)

// UseMCPActorJTI records an actor assertion's jti hash and reports false when
// it was already used (a replay). Expired entries are purged first.
func (tx *TenantTx) UseMCPActorJTI(jtiHash string, expires, now time.Time) (bool, error) {
	if _, err := tx.exec(mcpJTIPurge, sql.Named("now", RT(now))); err != nil {
		return false, err
	}
	n, err := tx.count(mcpJTISeen, sql.Named("jti_hash", jtiHash))
	if err != nil || n > 0 {
		return false, err
	}
	_, err = tx.exec(mcpJTIInsert, sql.Named("jti_hash", jtiHash), sql.Named("expires_at", RT(expires)))
	return err == nil, err
}
