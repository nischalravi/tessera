package oauth

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The public routes of the authorization server (design §16.1). The API
// registers each of them on its own route table (internal/api, so that they
// are on the public allow-list and audited); Handler serves the same routes
// on a plain mux for tests.
//
//	GET  /t/{slug}/.well-known/oauth-authorization-server   RFC 8414 metadata
//	GET  /t/{slug}/.well-known/jwks.json                    the tenant's access-token keys
//	GET  /.well-known/oauth-protected-resource              RFC 9728 metadata
//	POST /t/{slug}/oauth/device_authorization               RFC 8628
//	POST /t/{slug}/oauth/token                              device_code, refresh_token and client_credentials grants
//	POST /t/{slug}/oauth/revoke                             RFC 7009
//	POST /t/{slug}/oauth/introspect                         RFC 7662 (machine clients with tessera:introspect)

// Route patterns.
const (
	PathMetadata          = "/t/{slug}/.well-known/oauth-authorization-server"
	PathJWKS              = "/t/{slug}/.well-known/jwks.json"
	PathProtectedResource = "/.well-known/oauth-protected-resource"
	PathDeviceAuth        = "/t/{slug}/oauth/device_authorization"
	PathToken             = "/t/{slug}/oauth/token" // #nosec G101 -- a URL path pattern, not a credential
	PathRevoke            = "/t/{slug}/oauth/revoke"
	PathIntrospect        = "/t/{slug}/oauth/introspect"
)

// Scopes lists the scopes Tessera tokens can carry.
var Scopes = []string{"tessera:read", "tessera:write", "tessera:audit", "tessera:admin"}

// MachineScopes are the scopes a machine client can be registered with: the
// token scopes, and ScopeIntrospect (the right to call the introspection
// endpoint).
var MachineScopes = append(slices.Clone(Scopes), ScopeIntrospect)

// DPoPAlgs are the DPoP proof algorithms the server accepts.
var DPoPAlgs = []string{"ES256", "EdDSA"}

// Handler serves the public routes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	slugged := func(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { h(w, r, r.PathValue("slug")) }
	}
	mux.HandleFunc("GET "+PathMetadata, slugged(s.Metadata))
	mux.HandleFunc("GET "+PathJWKS, slugged(s.JWKS))
	mux.HandleFunc("GET "+PathProtectedResource, s.ProtectedResource)
	mux.HandleFunc("POST "+PathDeviceAuth, slugged(s.DeviceAuthorization))
	mux.HandleFunc("POST "+PathToken, slugged(s.Token))
	mux.HandleFunc("POST "+PathRevoke, slugged(s.Revoke))
	mux.HandleFunc("POST "+PathIntrospect, slugged(s.Introspect))
	return mux
}

// Metadata is the RFC 8414 authorization server metadata of a tenant's issuer.
func (s *Service) Metadata(w http.ResponseWriter, r *http.Request, slug string) {
	_, ok, err := s.tenantBySlug(r.Context(), slug)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeDoc(w, map[string]any{
		"issuer":                        s.Issuer(slug),
		"token_endpoint":                s.endpoint(slug, "token"),
		"device_authorization_endpoint": s.endpoint(slug, "device_authorization"),
		"revocation_endpoint":           s.endpoint(slug, "revoke"),
		"introspection_endpoint":        s.endpoint(slug, "introspect"),
		"jwks_uri":                      s.Issuer(slug) + "/.well-known/jwks.json",
		// no authorization endpoint: only the device, refresh and client
		// credentials grants exist
		"response_types_supported": []string{},
		"grant_types_supported":    []string{GrantDeviceCode, GrantRefresh, GrantClientCredentials},
		// "none" is the public CLI client; machine clients use private_key_jwt
		"token_endpoint_auth_methods_supported":                    []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported":         AssertionAlgs,
		"revocation_endpoint_auth_methods_supported":               []string{"none"},
		"introspection_endpoint_auth_methods_supported":            []string{"private_key_jwt"},
		"introspection_endpoint_auth_signing_alg_values_supported": AssertionAlgs,
		"dpop_signing_alg_values_supported":                        DPoPAlgs,
		"scopes_supported":                                         MachineScopes,
		"authorization_response_iss_parameter_supported":           true,
	})
}

// JWKS publishes the tenant's public access-token keys (next, active and
// retired for 24 h; never a revoked one, never a private member).
func (s *Service) JWKS(w http.ResponseWriter, r *http.Request, slug string) {
	t, ok, err := s.tenantBySlug(r.Context(), slug)
	if err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	if !ok {
		notFound(w)
		return
	}
	var set any
	if err := s.db.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		var err error
		set, err = keys.JWKSFor(tx, store.KeyPurposeAccessToken, s.now(), s.cfg.Log)
		return err
	}); err != nil {
		serverError(w, s.cfg.Log, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeDoc(w, set)
}

// ProtectedResource is the RFC 9728 metadata of the API. The resource is one
// for all tenants, while the authorization server is per tenant, so
// authorization_servers holds the issuer template; a client fills in the
// tenant slug it signs in to.
func (s *Service) ProtectedResource(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeDoc(w, map[string]any{
		"resource":                              s.cfg.APIAudience,
		"authorization_servers":                 []string{s.cfg.PublicURL + "/t/{slug}"},
		"bearer_methods_supported":              []string{"header"},
		"dpop_bound_access_tokens_required":     true,
		"dpop_signing_alg_values_supported":     DPoPAlgs,
		"scopes_supported":                      Scopes,
		"resource_name":                         "Tessera API",
		"tessera_authorization_server_template": s.cfg.PublicURL + "/t/{slug}",
	})
}

// writeDoc writes a public metadata document (cacheable, unlike token
// responses).
func writeDoc(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b) // #nosec G705 -- JSON-encoded body served as application/json with nosniff
}
