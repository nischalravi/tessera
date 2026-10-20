package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
)

// The OAuth authorization server's routes (design §16.1, §19 PR10). The
// handlers live in internal/oauth; this file puts them on the route table so
// that the public ones are on the allow-list and every request is audited.
//
// Public (the credential is the device code, the refresh token or the DPoP
// proof itself; unknown tenants are 404):
//
//	GET  /t/{slug}/.well-known/oauth-authorization-server
//	GET  /t/{slug}/.well-known/jwks.json
//	GET  /.well-known/oauth-protected-resource
//	POST /t/{slug}/oauth/device_authorization
//	POST /t/{slug}/oauth/token
//	POST /t/{slug}/oauth/revoke
//
// Session routes (the browser approving a device):
//
//	POST /api/auth/device/lookup    {user_code}: who is asking, from where
//	POST /api/auth/device/approve   {user_code, decision}: needs a sign-in within 300 s (STEP_UP_ADMIN)
func (s *Server) registerOAuthRoutes() {
	G, P := http.MethodGet, http.MethodPost
	slugged := func(h func(http.ResponseWriter, *http.Request, string)) handlerFunc {
		return func(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
			h(w, r, p.path["slug"])
			return nil, nil // the handler wrote the response
		}
	}
	plain := func(h func(http.ResponseWriter, *http.Request)) handlerFunc {
		return func(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
			h(w, r)
			return nil, nil
		}
	}
	// the handlers open their own transactions (noTenant): the tenant is the
	// path's slug or the signed-in principal's, never a header or a body field
	s.handle(G, oauth.PathMetadata, noTenant, publicRoute, slugged(s.oauth.Metadata))
	s.handle(G, oauth.PathJWKS, noTenant, publicRoute, slugged(s.oauth.JWKS))
	s.handle(G, oauth.PathProtectedResource, noTenant, publicRoute, plain(s.oauth.ProtectedResource))
	s.handle(P, oauth.PathDeviceAuth, noTenant, publicRoute, slugged(s.oauth.DeviceAuthorization))
	s.handle(P, oauth.PathToken, noTenant, publicRoute, slugged(s.oauth.Token))
	s.handle(P, oauth.PathRevoke, noTenant, publicRoute, slugged(s.oauth.Revoke))
	s.handle(P, "/api/auth/device/lookup", noTenant, need(auth.PermAuthenticated), plain(s.oauth.DeviceLookup))
	s.handle(P, "/api/auth/device/approve", noTenant, needStepUp(auth.PermAuthenticated, auth.StepUpAdmin), plain(s.oauth.DeviceApprove))
}
