package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The public documents of the AWS federation (differentiators plan EP-2). The
// customer's IAM OIDC provider is created from the issuer URL; AWS reads the
// discovery document and then the JWKS. The connector's token itself is never
// served: it is minted in process (awsorg.Federation) and sent to STS.
//
//	GET /t/{slug}/aws/.well-known/openid-configuration   OIDC discovery
//	GET /t/{slug}/aws/.well-known/jwks.json              the tenant's public signing keys
//
// The issuer is {PUBLIC_URL}/t/{slug}/aws. It signs with the tenant's
// access-token keys, as the MCP issuer does; the distinct issuer and the
// audience sts.amazonaws.com keep a federation token out of the API.
func (s *Server) registerAWSFederationRoutes() {
	s.handle(http.MethodGet, "/t/{slug}/aws/.well-known/openid-configuration", noTenant, publicRoute, s.awsOIDCDiscovery)
	s.handle(http.MethodGet, "/t/{slug}/aws/.well-known/jwks.json", noTenant, publicRoute, s.awsJWKS)
}

// awsFederationTenant resolves the slug of a public federation route. An
// unknown or inactive tenant, and a server without a public URL, answer with
// no detail.
func (s *Server) awsFederationTenant(w http.ResponseWriter, r *http.Request, p *params) (store.Tenant, bool) {
	if s.cfg.PublicURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return store.Tenant{}, false
	}
	t, ok, err := s.activeTenant(r.Context(), p.path["slug"])
	if err != nil {
		s.log.Error("aws federation tenant lookup failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return store.Tenant{}, false
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return store.Tenant{}, false
	}
	return t, true
}

func (s *Server) awsOIDCDiscovery(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, ok := s.awsFederationTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	iss := awsorg.IssuerURL(s.cfg.PublicURL, t.Slug)
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{keys.AlgES256},
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti"},
	})
	return nil, nil
}

func (s *Server) awsJWKS(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, ok := s.awsFederationTenant(w, r, p)
	if !ok {
		return nil, nil
	}
	var set any
	if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		var err error
		set, err = keys.JWKSFor(tx, store.KeyPurposeAccessToken, s.clock(), s.log)
		return err
	}); err != nil {
		return nil, err
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
	return nil, nil
}

// awsFederation is what the customer needs to trust this connector: the
// provider URL and client id of the IAM OIDC provider, and the sub the role's
// trust policy pins.
type awsFederation struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Subject  string `json:"subject"`
	// TrustPolicy is the role's trust policy with the account id left as
	// {ACCOUNT_ID}: Federated is that account's IAM OIDC provider.
	TrustPolicy string `json:"trust_policy"`
}
