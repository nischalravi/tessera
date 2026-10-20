package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/mcpauth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Agent authorization admin API (issue #115), behind the Agent authorization
// page:
//
//	GET  /api/mcp/clients                      registered clients (graph.read)
//	POST /api/mcp/clients {client_id}          fetch and register a client metadata document, pending (agents.manage, step-up)
//	PUT  /api/mcp/clients/{id}                 bind to an agent identity and activate or disable (agents.manage, step-up)
//	GET  /api/mcp/resources                    resource servers (graph.read)
//	POST /api/mcp/resources {resource, name}   register one; the secret is shown once (agents.manage, step-up)
//	PUT  /api/mcp/resources/{id} {status}      enable or disable (agents.manage, step-up)
//	GET  /api/mcp/tokens                       newest issued tokens, with state (graph.read)
//	POST /api/mcp/tokens/{jti}/revoke          revoke one token (agents.manage, step-up)
//	GET  /api/mcp/decisions                    the decision log (graph.read)

func (s *Server) registerMCPAdminRoutes() {
	const G, P, U = http.MethodGet, http.MethodPost, http.MethodPut
	manage := needStepUp(auth.PermAgentsManage, auth.StepUpPolicy)
	s.handle(G, "/api/mcp/clients", read, need(auth.PermGraphRead), s.rd(s.mcpListClients))
	s.handle(P, "/api/mcp/clients", noTenant, manage, s.mcpRegisterClient)
	s.handle(U, "/api/mcp/clients/{id}", write, manage, s.rd(s.mcpUpdateClient))
	s.handle(G, "/api/mcp/resources", read, need(auth.PermGraphRead), s.rd(s.mcpListResources))
	s.handle(P, "/api/mcp/resources", write, manage, s.rd(s.mcpCreateResource))
	s.handle(U, "/api/mcp/resources/{id}", write, manage, s.rd(s.mcpUpdateResource))
	s.handle(G, "/api/mcp/tokens", read, need(auth.PermGraphRead), s.rd(s.mcpListTokens))
	s.handle(P, "/api/mcp/tokens/{jti}/revoke", write, manage, s.rd(s.mcpRevokeToken))
	s.handle(G, "/api/mcp/decisions", read, need(auth.PermGraphRead), s.rd(s.mcpListDecisions))
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

type mcpNameRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func mcpRefOf(ids map[int64]*store.Identity, id int64) *mcpNameRef {
	if i := ids[id]; i != nil {
		return &mcpNameRef{ID: id, Name: i.Name}
	}
	return &mcpNameRef{ID: id, Name: "(unknown)"}
}

type mcpClientView struct {
	ID               string      `json:"id"`
	ClientID         string      `json:"client_id"`
	Name             string      `json:"name"`
	RedirectURIs     []string    `json:"redirect_uris"`
	LoopbackRedirect bool        `json:"loopback_redirect"`
	HasKeys          bool        `json:"has_keys"`
	Agent            *mcpNameRef `json:"agent"`
	Status           string      `json:"status"`
	FetchedAt        string      `json:"fetched_at"`
	ExpiresAt        string      `json:"expires_at"`
	DocSHA256        string      `json:"doc_sha256"`
}

func clientViewOf(c *store.MCPClient, ids map[int64]*store.Identity) mcpClientView {
	uris := mcpauth.RedirectURIsOf(c)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	_ = json.Unmarshal([]byte(c.JWKS), &set)
	v := mcpClientView{ID: c.ID, ClientID: c.ClientID, Name: c.Name, RedirectURIs: uris, LoopbackRedirect: mcpauth.HasLoopbackRedirect(uris),
		HasKeys: len(set.Keys) > 0, Status: c.Status, FetchedAt: iso(c.FetchedAt), ExpiresAt: iso(c.ExpiresAt), DocSHA256: c.DocSHA256}
	if c.AgentIdentityID != nil {
		v.Agent = mcpRefOf(ids, *c.AgentIdentityID)
	}
	return v
}

func (s *Server) mcpListClients(r *http.Request, _ *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	ids, _, err := tx.IdentityMap()
	if err != nil {
		return 0, nil, err
	}
	cs, err := tx.MCPClients()
	if err != nil {
		return 0, nil, err
	}
	out := []mcpClientView{}
	for _, c := range cs {
		out = append(out, clientViewOf(c, ids))
	}
	return http.StatusOK, out, nil
}

// mcpRegisterClient fetches the client's metadata document (an outbound call,
// so no transaction is open while it runs) and stores it pending.
func (s *Server) mcpRegisterClient(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	pr := principal(r)
	c, err := s.mcp.Client(r.Context(), s.store, pr.TenantID, strings.TrimSpace(b.ClientID))
	var ce *mcpauth.ErrClient
	if errors.As(err, &ce) {
		return nil, badRequest("invalid_client_metadata", ce.Msg)
	}
	if err != nil {
		return nil, err
	}
	var ids map[int64]*store.Identity
	if err := s.store.ReadTenant(r.Context(), pr.TenantID, func(tx *store.TenantTx) error {
		var err error
		ids, _, err = tx.IdentityMap()
		return err
	}); err != nil {
		return nil, err
	}
	return clientViewOf(c, ids), nil
}

func (s *Server) mcpUpdateClient(r *http.Request, p *params) (int, any, error) {
	var b struct {
		AgentIdentityID *int64 `json:"agent_identity_id"`
		Status          string `json:"status"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, errStatus(http.StatusNotFound, "no such client")
	}
	if b.Status != "pending" && b.Status != "active" && b.Status != "disabled" {
		return 0, nil, badRequest("invalid_status", "status must be pending, active or disabled")
	}
	tx := store.TxFrom(r.Context())
	cs, err := tx.MCPClients()
	if err != nil {
		return 0, nil, err
	}
	var cur *store.MCPClient
	for _, c := range cs {
		if c.ID == id {
			cur = c
		}
	}
	if cur == nil {
		return 0, nil, errStatus(http.StatusNotFound, "no such client")
	}
	ids, _, err := tx.IdentityMap()
	if err != nil {
		return 0, nil, err
	}
	if b.Status == "active" {
		a := (*store.Identity)(nil)
		if b.AgentIdentityID != nil {
			a = ids[*b.AgentIdentityID]
		}
		if a == nil || a.Type != "ai_agent" || a.Status != "active" {
			return 0, nil, badRequest("invalid_agent", "an active client must be bound to an active ai_agent identity")
		}
	}
	now := s.clock()
	if err := tx.SetMCPClient(cur.ClientID, b.AgentIdentityID, b.Status, now); err != nil {
		return 0, nil, err
	}
	rebound := (cur.AgentIdentityID == nil) != (b.AgentIdentityID == nil) ||
		cur.AgentIdentityID != nil && b.AgentIdentityID != nil && *cur.AgentIdentityID != *b.AgentIdentityID
	var revoked int64
	if b.Status != "active" || rebound {
		// a disabled client, or one moved to another agent ceiling, loses its tokens
		if revoked, err = s.mcp.RevokeClient(tx, cur.ClientID, "client "+b.Status+" or rebound by an administrator"); err != nil {
			return 0, nil, err
		}
	}
	detail := ojson.Object{{Key: "client_id", Value: cur.ClientID}, {Key: "status", Value: b.Status},
		{Key: "previous_status", Value: cur.Status}, {Key: "tokens_revoked", Value: revoked}}
	if b.AgentIdentityID != nil {
		detail = append(detail, ojson.KV{Key: "agent_identity_id", Value: *b.AgentIdentityID})
	}
	if err := tx.Audit(now, actor(r), "mcp.client.update", detail); err != nil {
		return 0, nil, err
	}
	upd, err := tx.MCPClient(cur.ClientID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, clientViewOf(upd, ids), nil
}

type resourceView struct {
	ID          string `json:"id"`
	Resource    string `json:"resource"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	MetadataURL string `json:"metadata_path"`
	Secret      string `json:"secret,omitempty"`
}

func (s *Server) resourceViewOf(slug string, x *store.MCPResource) resourceView {
	return resourceView{ID: x.ID, Resource: x.Resource, Name: x.Name, Status: x.Status, CreatedBy: x.CreatedBy,
		CreatedAt: iso(x.CreatedAt), MetadataURL: "/t/" + slug + mcpIssuerSuffix + "/.well-known/oauth-protected-resource/" + x.ID}
}

// mcpSlug is the principal's tenant slug (a read-only lookup, safe to call
// inside the request's transaction).
func (s *Server) mcpSlug(r *http.Request) (string, error) {
	var slug string
	err := s.store.ReadSystem(r.Context(), "mcp slug", func(st *store.SystemTx) error {
		t, err := st.TenantByID(principal(r).TenantID)
		slug = t.Slug
		return err
	})
	return slug, err
}

func (s *Server) mcpListResources(r *http.Request, _ *params) (int, any, error) {
	rs, err := store.TxFrom(r.Context()).MCPResources()
	if err != nil {
		return 0, nil, err
	}
	slug, err := s.mcpSlug(r)
	if err != nil {
		return 0, nil, err
	}
	out := []resourceView{}
	for _, x := range rs {
		out = append(out, s.resourceViewOf(slug, x))
	}
	return http.StatusOK, out, nil
}

func (s *Server) mcpCreateResource(r *http.Request, _ *params) (int, any, error) {
	var b struct {
		Resource string `json:"resource"`
		Name     string `json:"name"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	b.Resource, b.Name = strings.TrimSpace(b.Resource), strings.TrimSpace(b.Name)
	if err := mcpauth.ValidateResource(b.Resource); err != nil {
		return 0, nil, badRequest("invalid_resource", err.Error())
	}
	if n := len([]rune(b.Name)); n < 1 || n > 100 {
		return 0, nil, badRequest("invalid_name", "name is required (at most 100 characters)")
	}
	tx := store.TxFrom(r.Context())
	if _, err := tx.MCPResourceByURI(b.Resource); err == nil {
		return 0, nil, &readiness.Error{Status: http.StatusConflict, Code: "resource_exists", Msg: "that resource is already registered"}
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, nil, err
	}
	secret := seal.RandomSecret(32)
	now := s.clock()
	x := &store.MCPResource{Resource: b.Resource, Name: b.Name, SecretHash: seal.SHA256Hex([]byte(secret)), CreatedBy: actor(r), CreatedAt: now}
	if err := tx.InsertMCPResource(x); err != nil {
		return 0, nil, err
	}
	if err := tx.Audit(now, actor(r), "mcp.resource.register", ojson.Object{{Key: "resource", Value: b.Resource},
		{Key: "resource_id", Value: x.ID}, {Key: "name", Value: b.Name}}); err != nil {
		return 0, nil, err
	}
	slug, err := s.mcpSlug(r)
	if err != nil {
		return 0, nil, err
	}
	v := s.resourceViewOf(slug, x)
	v.Secret = secret // shown once; only its hash is stored
	return http.StatusCreated, v, nil
}

func (s *Server) mcpUpdateResource(r *http.Request, p *params) (int, any, error) {
	var b struct {
		Status string `json:"status"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return 0, nil, err
	}
	if b.Status != "active" && b.Status != "disabled" {
		return 0, nil, badRequest("invalid_status", "status must be active or disabled")
	}
	id := p.path["id"]
	if !idRE.MatchString(id) {
		return 0, nil, errStatus(http.StatusNotFound, "no such resource")
	}
	tx := store.TxFrom(r.Context())
	x, err := tx.MCPResource(id)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, errStatus(http.StatusNotFound, "no such resource")
	}
	if err != nil {
		return 0, nil, err
	}
	if err := tx.SetMCPResourceStatus(id, b.Status); err != nil {
		return 0, nil, err
	}
	var revoked int64
	if b.Status == "disabled" {
		if revoked, err = s.mcp.RevokeResource(tx, x.Resource, "resource disabled by an administrator"); err != nil {
			return 0, nil, err
		}
	}
	if err := tx.Audit(s.clock(), actor(r), "mcp.resource.update", ojson.Object{{Key: "resource", Value: x.Resource},
		{Key: "status", Value: b.Status}, {Key: "tokens_revoked", Value: revoked}}); err != nil {
		return 0, nil, err
	}
	x.Status = b.Status
	slug, err := s.mcpSlug(r)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, s.resourceViewOf(slug, x), nil
}

type tokenView struct {
	JTI           string          `json:"jti"`
	ClientID      string          `json:"client_id"`
	Subject       *mcpNameRef     `json:"subject"`
	Agent         *mcpNameRef     `json:"agent"`
	Audience      string          `json:"audience"`
	Scope         []string        `json:"scope"`
	Act           json.RawMessage `json:"act"`
	Grant         string          `json:"grant"`
	PolicyVersion string          `json:"policy_version"`
	IssuedAt      string          `json:"issued_at"`
	ExpiresAt     string          `json:"expires_at"`
	RevokedAt     *string         `json:"revoked_at"`
	RevokedReason string          `json:"revoked_reason"`
	State         string          `json:"state"` // active | expired | revoked
}

func (s *Server) mcpListTokens(r *http.Request, _ *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	ids, _, err := tx.IdentityMap()
	if err != nil {
		return 0, nil, err
	}
	ts, err := tx.MCPTokens()
	if err != nil {
		return 0, nil, err
	}
	now := s.clock()
	out := []tokenView{}
	for _, t := range ts {
		state := "active"
		switch {
		case t.RevokedAt != nil:
			state = "revoked"
		case !now.Before(t.ExpiresAt):
			state = "expired"
		}
		act := json.RawMessage(t.Act)
		if !json.Valid(act) {
			act = json.RawMessage("null")
		}
		out = append(out, tokenView{JTI: t.JTI, ClientID: t.ClientID, Subject: mcpRefOf(ids, t.SubjectID), Agent: mcpRefOf(ids, t.AgentID),
			Audience: t.Audience, Scope: strings.Fields(t.Scope), Act: act, Grant: t.GrantType, PolicyVersion: t.PolicyVersion,
			IssuedAt: iso(t.IssuedAt), ExpiresAt: iso(t.ExpiresAt), RevokedAt: isoPtr(t.RevokedAt), RevokedReason: t.RevokedReason,
			State: state})
	}
	return http.StatusOK, out, nil
}

func (s *Server) mcpRevokeToken(r *http.Request, p *params) (int, any, error) {
	jti := p.path["jti"]
	if !idRE.MatchString(jti) {
		return 0, nil, errStatus(http.StatusNotFound, "no such token")
	}
	tx := store.TxFrom(r.Context())
	row, err := tx.MCPToken(jti)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, errStatus(http.StatusNotFound, "no such token")
	}
	if err != nil {
		return 0, nil, err
	}
	if row.RevokedAt == nil {
		if err := s.mcp.RevokeToken(tx, jti, "revoked by "+actor(r)); err != nil {
			return 0, nil, err
		}
	}
	return http.StatusOK, map[string]any{"revoked": true, "jti": jti}, nil
}

type mcpDecisionView struct {
	ID             int64       `json:"id"`
	At             string      `json:"at"`
	Kind           string      `json:"kind"`
	Allow          bool        `json:"allow"`
	Reason         string      `json:"reason"`
	JTI            string      `json:"jti"`
	ClientID       string      `json:"client_id"`
	Subject        *mcpNameRef `json:"subject"`
	Agent          *mcpNameRef `json:"agent"`
	Resource       string      `json:"resource"`
	Tool           string      `json:"tool"`
	RequestedScope []string    `json:"requested_scope"`
	GrantedScope   []string    `json:"granted_scope"`
	PolicyVersion  string      `json:"policy_version"`
}

func (s *Server) mcpListDecisions(r *http.Request, p *params) (int, any, error) {
	tx := store.TxFrom(r.Context())
	ids, _, err := tx.IdentityMap()
	if err != nil {
		return 0, nil, err
	}
	ds, err := tx.MCPDecisions(boundedLimit(p.queryInt("limit", 200, ptr64(1), ptr64(mcpMaxLimit)), 200))
	if err != nil {
		return 0, nil, err
	}
	out := []mcpDecisionView{}
	for _, d := range ds {
		v := mcpDecisionView{ID: d.ID, At: iso(d.At), Kind: d.Kind, Allow: d.Allow, Reason: d.Reason, JTI: d.JTI, ClientID: d.ClientID,
			Resource: d.Resource, Tool: d.Tool, RequestedScope: strings.Fields(d.RequestedScope),
			GrantedScope: strings.Fields(d.GrantedScope), PolicyVersion: d.PolicyVersion}
		if d.SubjectID != nil {
			v.Subject = mcpRefOf(ids, *d.SubjectID)
		}
		if d.AgentID != nil {
			v.Agent = mcpRefOf(ids, *d.AgentID)
		}
		out = append(out, v)
	}
	if err := validated(p, nil); err != nil {
		return 0, nil, err
	}
	return http.StatusOK, out, nil
}

func ptr64(v int64) *int64 { return &v }

// boundedLimit converts a query limit to int only inside 1..max (the validator
// has already refused anything else with a 422; this keeps the conversion safe
// on its own, on any int width).
func boundedLimit(v int64, def int) int {
	if v < 1 || v > mcpMaxLimit {
		return def
	}
	return int(v)
}

// mcpMaxLimit is the largest page of MCP decisions one request returns.
const mcpMaxLimit = 500
