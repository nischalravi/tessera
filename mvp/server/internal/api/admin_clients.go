package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The admin routes (design §16.1): the tenant's OAuth clients, and (issue #498) creating, re-keying and revoking
// machine clients from the UI as well as with `tessera admin add-client` (cmd/tessera).
//
//	GET  /api/admin/api-clients                          admin.read
//	GET  /api/admin/api-clients/{client_id}              admin.read
//	POST /api/admin/api-clients                          create a machine client {name, owner, scopes, roles, dpop_required, jwks}
//	POST /api/admin/api-clients/{client_id}/keys         {jwks, mode: add|replace}: rotate the client's public keys
//	POST /api/admin/api-clients/{client_id}/revoke       disable the client: no new token, and its tokens stop working
//
// The three changes need admin.change.request and a fresh passkey sign-in (step-up), which a machine principal can
// never satisfy, and each writes its audit event in the same transaction. A machine client never gets the admin
// scope or an admin role, and only public keys are accepted: the client keeps its private key.
func (s *Server) registerAdminClientRoutes() {
	G, P := http.MethodGet, http.MethodPost
	change := needStepUp(auth.PermAdminChangeReq, auth.StepUpAdmin)
	s.handle(G, "/api/admin/api-clients", read, need(auth.PermAdminRead), s.adminListAPIClients)
	s.handle(G, "/api/admin/api-clients/{client_id}", read, need(auth.PermAdminRead), s.adminGetAPIClient)
	s.handle(P, "/api/admin/api-clients", write, change, s.adminCreateAPIClient)
	s.handle(P, "/api/admin/api-clients/{client_id}/keys", write, change, s.adminRotateAPIClientKeys)
	s.handle(P, "/api/admin/api-clients/{client_id}/revoke", write, change, s.adminRevokeAPIClient)
}

// machineClientScopes and machineClientRoles are what a UI-created machine client may hold: no admin scope and no
// admin role (§9.5); approvals and policy changes stay human-only.
var (
	machineClientScopes = []string{"tessera:read", "tessera:write", "tessera:audit", oauth.ScopeIntrospect, oauth.ScopeEmailDSN}
	machineClientRoles  = []string{string(auth.RoleViewer), string(auth.RoleOperator), string(auth.RoleAuditor)}
)

// ensureWithinCreator refuses roles and scopes whose effective permissions (perms(roles) ∩ perms(scopes), the same
// rule a token principal gets) the signed-in admin does not hold now (issue #509). Without it a tenant admin, who has
// no data-plane permission by design, could mint an operator client and use it for data-plane work. The check is
// against the caller's active permissions, so an admin whose roles are inactive (no step-up) holds fewer.
func ensureWithinCreator(r *http.Request, roles, scopes []string) error {
	_, active, _ := auth.MachineRoles(roles)
	want := auth.EffectivePermissions(&auth.Principal{ActiveRoles: active, Scopes: auth.ScopeSetOf(scopes)})
	// config.propose is vouched for by its own two-admin grant (api_client.propose.grant), as in auth.ClientExceedsApprover:
	// no person holds it, so without this nobody could rotate a proposer client's keys (issue #739). Registration still
	// refuses the scope (machineClientScopes).
	delete(want, auth.PermConfigPropose)
	have := auth.EffectivePermissions(principal(r))
	var missing []string
	for _, p := range want.Sorted() {
		if !have.Has(p) {
			missing = append(missing, string(p))
		}
	}
	if len(missing) > 0 {
		return &readiness.Error{Status: http.StatusForbidden, Code: "exceeds_creator",
			Msg: "a client cannot hold permissions its creator lacks: " + strings.Join(missing, ", ")}
	}
	return nil
}

// approverOf is the signed-in admin who vouches for a client's permissions now (store.APIClient.ApprovedBy, issue #522).
func approverOf(r *http.Request) string {
	if pr := principal(r); pr != nil && pr.UserID != nil {
		return pr.UserID.String()
	}
	return ""
}

// clientView is an OAuth client as the admin API shows it: the registered
// public keys (kid, algorithm, RFC 7638 thumbprint) and never any secret (a
// machine client has none: it authenticates with a key only it holds).
func clientView(c *store.APIClient) ojson.Object {
	keys := []ojson.Object{}
	if len(c.JWKS) > 0 {
		if set, _, err := oauth.ParseClientJWKS(c.JWKS); err == nil {
			keys = clientKeys(set)
		}
	}
	var owner, lastUsed any
	if c.OwnerUserID != nil {
		owner = c.OwnerUserID.String()
	}
	if c.LastUsedAt != nil {
		lastUsed = rt3339(*c.LastUsedAt)
	}
	return ojson.Object{{Key: "client_id", Value: c.ClientID}, {Key: "name", Value: c.Name}, {Key: "kind", Value: c.Kind},
		{Key: "status", Value: c.Status}, {Key: "grant_types", Value: nonNil(c.GrantTypes)},
		{Key: "token_endpoint_auth_method", Value: c.TokenEndpointAuthMethod}, {Key: "dpop_required", Value: c.DPoPRequired},
		{Key: "allowed_scopes", Value: nonNil(c.AllowedScopes)}, {Key: "roles", Value: nonNil(c.Roles)},
		{Key: "owner_user_id", Value: owner}, {Key: "keys", Value: keys}, {Key: "created_at", Value: rt3339(c.CreatedAt)},
		{Key: "last_used_at", Value: lastUsed}}
}

func clientKeys(set jose.JSONWebKeySet) []ojson.Object {
	out := []ojson.Object{}
	for i := range set.Keys {
		k := &set.Keys[i]
		jkt, err := dpop.Thumbprint(k)
		if err != nil {
			continue
		}
		alg := k.Algorithm
		if alg == "" {
			alg = keyAlg(k)
		}
		out = append(out, ojson.Object{{Key: "kid", Value: k.KeyID}, {Key: "alg", Value: alg}, {Key: "jkt", Value: jkt}})
	}
	return out
}

// keyAlg is the signature algorithm a registered key verifies.
func keyAlg(k *jose.JSONWebKey) string {
	if _, ok := k.Key.(ed25519.PublicKey); ok {
		return "EdDSA"
	}
	return "ES256"
}

// adminListAPIClients is GET /api/admin/api-clients: this tenant's clients,
// the first-party CLI included, oldest first.
func (s *Server) adminListAPIClients(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	cs, err := store.TxFrom(r.Context()).APIClients()
	if err != nil {
		return nil, err
	}
	out := make([]ojson.Object, 0, len(cs))
	for _, c := range cs {
		out = append(out, clientView(c))
	}
	return out, nil
}

// adminGetAPIClient is GET /api/admin/api-clients/{client_id}. Another
// tenant's client is 404, like a missing one.
func (s *Server) adminGetAPIClient(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["client_id"]
	if len(id) > 64 {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	c, err := store.TxFrom(r.Context()).APIClientByClientID(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	if err != nil {
		return nil, err
	}
	return clientView(c), nil
}

type createClientBody struct {
	Name         string          `json:"name"`
	Owner        string          `json:"owner"` // a user id or e-mail in this tenant: the person accountable for the client
	Scopes       []string        `json:"scopes"`
	Roles        []string        `json:"roles"`
	DPoPRequired *bool           `json:"dpop_required"`
	JWKS         json.RawMessage `json:"jwks"` // public keys only
}

// pickList checks every entry against allowed and returns them without repeats.
func pickList(field string, in, allowed []string) ([]string, error) {
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if !slices.Contains(allowed, v) {
			return nil, badRequest("invalid_"+field, field+": "+strconv.Quote(v)+" is not allowed here (one of "+strings.Join(allowed, ", ")+")")
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, badRequest("invalid_"+field, field+": at least one is required")
	}
	return out, nil
}

func newClientID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tsc_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

func jwkThumbprints(set jose.JSONWebKeySet) []any {
	out := []any{}
	for i := range set.Keys {
		if jkt, err := dpop.Thumbprint(&set.Keys[i]); err == nil {
			out = append(out, jkt)
		}
	}
	return out
}

func stringsAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func (s *Server) adminCreateAPIClient(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b createClientBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || len([]rune(name)) > 200 {
		return nil, badRequest("invalid_name", "name is required (at most 200 characters)")
	}
	scopes, err := pickList("scopes", b.Scopes, machineClientScopes)
	if err != nil {
		return nil, err
	}
	if len(b.Roles) == 0 {
		return nil, badRequest("invalid_roles", "roles: at least one of "+strings.Join(machineClientRoles, ", ")+" is required, even for a client "+
			"with only the tessera:email-dsn scope (the scope grants email.dsn alone; the role is what the scopes narrow)")
	}
	roles, err := pickList("roles", b.Roles, machineClientRoles)
	if err != nil {
		return nil, err
	}
	if err := ensureWithinCreator(r, roles, scopes); err != nil {
		return nil, err
	}
	set, jwks, err := oauth.ParseClientJWKS(b.JWKS)
	if err != nil {
		return nil, badRequest("invalid_jwks", err.Error())
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	owner, err := findClientOwner(tx, b.Owner)
	if err != nil {
		return nil, err
	}
	clientID, err := newClientID()
	if err != nil {
		return nil, err
	}
	c := &store.APIClient{ClientID: clientID, Name: name, Kind: store.ClientMachine, // #nosec G101 -- names of an auth method and a grant, not a credential
		GrantTypes: []string{oauth.GrantClientCredentials}, TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks,
		DPoPRequired: b.DPoPRequired == nil || *b.DPoPRequired, AllowedScopes: scopes, Roles: roles, OwnerUserID: &owner.ID,
		ApprovedBy: approverOf(r), Status: store.ClientActive, CreatedAt: now}
	if err := tx.InsertAPIClient(c); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor(r), "oauth.client.created", ojson.Object{{Key: "client_id", Value: c.ClientID},
		{Key: "name", Value: c.Name}, {Key: "kind", Value: c.Kind}, {Key: "owner_user_id", Value: owner.ID.String()},
		{Key: "roles", Value: stringsAny(roles)}, {Key: "scopes", Value: stringsAny(scopes)}, {Key: "dpop_required", Value: c.DPoPRequired},
		{Key: "key_thumbprints", Value: jwkThumbprints(set)}}); err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, clientView(c)}, nil
}

// findClientOwner resolves an owner given as a user id or an e-mail to an active user of the tenant.
func findClientOwner(tx *store.TenantTx, owner string) (*store.PlatformUser, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" || len(owner) > 320 {
		return nil, badRequest("invalid_owner", "owner is required: the user accountable for this client (an id or an e-mail)")
	}
	users, err := tx.PlatformUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID.String() == owner || (u.Email != nil && strings.EqualFold(*u.Email, owner)) {
			if u.Status != "active" {
				return nil, badRequest("invalid_owner", "the owner is not an active user")
			}
			return u, nil
		}
	}
	return nil, badRequest("invalid_owner", "no such user in this tenant")
}

// machineClientOf loads a machine client of this tenant; the CLI client and another tenant's client are 404.
func machineClientOf(r *http.Request, p *params) (*store.APIClient, error) {
	id := p.path["client_id"]
	if len(id) > 64 {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	c, err := store.TxFrom(r.Context()).APIClientByClientID(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.Kind != store.ClientMachine) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	return c, err
}

type rotateKeysBody struct {
	JWKS json.RawMessage `json:"jwks"`
	Mode string          `json:"mode"` // add: keep the current keys and add these (an overlap); replace: these only
}

func (s *Server) adminRotateAPIClientKeys(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b rotateKeysBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.Mode != "add" && b.Mode != "replace" {
		return nil, badRequest("invalid_mode", "mode is add (keep the current keys during the overlap) or replace")
	}
	c, err := machineClientOf(r, p)
	if err != nil {
		return nil, err
	}
	// new keys hand the client to whoever holds them: the rotating admin must hold everything the client can do
	if err := ensureWithinCreator(r, c.Roles, c.AllowedScopes); err != nil {
		return nil, err
	}
	incoming, _, err := oauth.ParseClientJWKS(b.JWKS)
	if err != nil {
		return nil, badRequest("invalid_jwks", err.Error())
	}
	next := incoming
	if b.Mode == "add" && len(c.JWKS) > 0 {
		cur, _, err := oauth.ParseClientJWKS(c.JWKS)
		if err != nil {
			return nil, err
		}
		have := map[string]bool{}
		for i := range cur.Keys {
			have[cur.Keys[i].KeyID] = true
		}
		for _, k := range incoming.Keys {
			if have[k.KeyID] {
				return nil, badRequest("invalid_jwks", "kid "+strconv.Quote(k.KeyID)+" is already registered: give the new key its own kid")
			}
		}
		next = jose.JSONWebKeySet{Keys: append(slices.Clone(cur.Keys), incoming.Keys...)}
	}
	_, jwks, err := oauth.ParseClientJWKS(mustJSON(next))
	if err != nil {
		return nil, badRequest("invalid_jwks", err.Error())
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := tx.SetAPIClientKeys(c.ClientID, jwks); err != nil {
		return nil, err
	}
	c.JWKS = jwks
	// the rotating admin holds everything the client can do (checked above) and now vouches for it (issue #522)
	if who := approverOf(r); who != "" {
		if err := tx.SetAPIClientApprover(c.ClientID, who); err != nil {
			return nil, err
		}
		c.ApprovedBy = who
	}
	if err := tx.Audit(now, actor(r), "oauth.client.keys_rotated", ojson.Object{{Key: "client_id", Value: c.ClientID}, {Key: "mode", Value: b.Mode},
		{Key: "key_thumbprints", Value: jwkThumbprints(next)}, {Key: "added_thumbprints", Value: jwkThumbprints(incoming)}}); err != nil {
		return nil, err
	}
	return clientView(c), nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v) // a key set always marshals
	return b
}

func (s *Server) adminRevokeAPIClient(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	c, err := machineClientOf(r, p)
	if err != nil {
		return nil, err
	}
	if c.Status == store.ClientDisabled {
		return nil, errStatus(http.StatusConflict, "the client is already revoked")
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	if err := tx.SetAPIClientStatus(c.ClientID, store.ClientDisabled); err != nil {
		return nil, err
	}
	c.Status = store.ClientDisabled
	if err := tx.Audit(now, actor(r), "oauth.client.revoked", ojson.Object{{Key: "client_id", Value: c.ClientID}, {Key: "name", Value: c.Name}}); err != nil {
		return nil, err
	}
	return clientView(c), nil
}
