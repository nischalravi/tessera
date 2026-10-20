package api

import (
	"crypto/ed25519"
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The admin routes (design §16.1). Phase 0 PR11 has the read-only view of the
// tenant's OAuth clients; a machine client is created with
// `tessera admin add-client` (cmd/tessera) until the change-request workflow
// of PR12 takes over creation and changes.
//
//	GET /api/admin/api-clients               admin.read
//	GET /api/admin/api-clients/{client_id}   admin.read
func (s *Server) registerAdminClientRoutes() {
	G := http.MethodGet
	s.handle(G, "/api/admin/api-clients", read, need(auth.PermAdminRead), s.adminListAPIClients)
	s.handle(G, "/api/admin/api-clients/{client_id}", read, need(auth.PermAdminRead), s.adminGetAPIClient)
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
