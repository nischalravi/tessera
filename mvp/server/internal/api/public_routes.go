package api

import (
	"fmt"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
)

// Route is what a registered route requires (design §12.4): Public routes
// are served without authentication and must be on publicRoutes; every
// other route declares the permission it needs and, for sensitive actions,
// an authentication requirement (step-up).
type Route struct {
	Public bool
	Perm   auth.Permission
	Authn  *auth.AuthnRequirement
	// BodyType is the one non-JSON media type the route takes as its body
	// (the flat-file upload takes text/csv). Every other unsafe request must
	// be application/json. The type must not be CORS-safelisted, so a
	// cross-site form cannot send it (text/plain, for one, is).
	BodyType string
	// NoConditionalAccess exempts a step-up route from the tenant's
	// privileged-scope conditional access policies (still permission and
	// step-up). Only the conditional access management routes set it: a policy
	// that denies the admin's own network must not lock the admin out of
	// fixing it.
	NoConditionalAccess bool
}

// publicRoute is the requirement of a route on the allow-list.
var publicRoute = Route{Public: true}

// need declares a permission.
func need(p auth.Permission) Route { return Route{Perm: p} }

// needStepUp declares a permission and an authentication requirement.
func needStepUp(p auth.Permission, req auth.AuthnRequirement) Route {
	r := req
	return Route{Perm: p, Authn: &r}
}

// needStepUpExempt is needStepUp for a route conditional access never
// blocks (see Route.NoConditionalAccess).
func needStepUpExempt(p auth.Permission, req auth.AuthnRequirement) Route {
	r := needStepUp(p, req)
	r.NoConditionalAccess = true
	return r
}

// publicRoutes is the exact allow-list of routes served without a session
// (design §16.1). Every other route answers 401 login_required to an
// unauthenticated caller. testdata/contract/public_routes.golden snapshots
// this list, so adding to it needs a reviewed diff.
//
// The OAuth AS routes (PR10, PR11) are public because their credential is the
// device code, the refresh token, the DPoP proof or the machine client's signed
// assertion in the request itself.
var publicRoutes = []string{
	"GET /api/health",
	"GET /api/auth/discover",
	"GET /api/auth/login",
	"GET /api/auth/oidc/{connection_id}/callback",
	"GET /api/auth/saml/{connection_id}/metadata",
	"POST /api/auth/saml/{connection_id}/acs",
	"GET /api/auth/oauth2/{connection_id}/callback",
	"GET /api/auth/cas/{connection_id}/callback",
	"POST /api/auth/wsfed/{connection_id}/callback",
	"GET /t/{slug}/bootstrap",
	"POST /api/auth/break-glass/options",
	"POST /api/auth/break-glass/verify",
	// SSF push delivery (RFC 8935): authenticated by the stream's bearer secret (ssf.go).
	"POST /public/t/{slug}/ssf/{transmitter_id}/events",
	"GET /t/{slug}/.well-known/oauth-authorization-server",
	"GET /t/{slug}/.well-known/jwks.json",
	"GET /.well-known/oauth-protected-resource",
	"POST /t/{slug}/oauth/device_authorization",
	"POST /t/{slug}/oauth/token",
	"POST /t/{slug}/oauth/revoke",
	"POST /public/t/{slug}/claim/start",
	"POST /public/t/{slug}/claim/verify/send",
	"POST /public/t/{slug}/claim/verify/check",
	"GET /public/t/{slug}/claim/status",
	"POST /public/t/{slug}/claim/existing-account",
	"POST /public/t/{slug}/claim/credential",
	"POST /public/t/{slug}/claim/resend",
	"POST /t/{slug}/oauth/introspect",
}

// PublicRoutes returns the allow-list.
func PublicRoutes() []string { return slices.Clone(publicRoutes) }

func isPublicRoute(method, pattern string) bool {
	return slices.Contains(publicRoutes, method+" "+pattern)
}

// checkPublicRoutes verifies at startup that no registered route is public
// unless it is on the allow-list (handle also refuses that) and that every
// non-public route declares a permission.
func (s *Server) checkPublicRoutes() {
	for _, rt := range s.routes {
		if rt.spec.Public != isPublicRoute(rt.method, rt.pattern) {
			panic(fmt.Sprintf("api: %s %s: public=%t disagrees with the allow-list", rt.method, rt.pattern, rt.spec.Public))
		}
		if !rt.spec.Public && rt.spec.Perm == "" {
			panic(fmt.Sprintf("api: route %s %s declares no permission", rt.method, rt.pattern))
		}
	}
}
