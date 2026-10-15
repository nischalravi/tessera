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

// publicRoutes is the exact allow-list of routes served without a session
// (design §16.1). Every other route answers 401 login_required to an
// unauthenticated caller. testdata/contract/public_routes.golden snapshots
// this list, so adding to it needs a reviewed diff.
//
// The well-known documents and the OAuth AS routes of §16.1 join with the PR
// that adds them (PR10).
var publicRoutes = []string{
	"GET /api/health",
	"GET /api/auth/discover",
	"GET /api/auth/login",
	"GET /api/auth/oidc/{connection_id}/callback",
	"GET /api/auth/saml/{connection_id}/metadata",
	"POST /api/auth/saml/{connection_id}/acs",
	"GET /api/auth/oauth2/{connection_id}/callback",
	"GET /t/{slug}/bootstrap",
	"POST /public/t/{slug}/claim/start",
	"POST /public/t/{slug}/claim/verify/send",
	"POST /public/t/{slug}/claim/verify/check",
	"GET /public/t/{slug}/claim/status",
	"POST /public/t/{slug}/claim/existing-account",
	"GET /public/t/{slug}/claim/terms",
	"POST /public/t/{slug}/claim/terms/accept",
	"POST /public/t/{slug}/claim/consent",
	"POST /public/t/{slug}/claim/credential",
	"POST /public/t/{slug}/claim/resend",
	"POST /public/t/{slug}/guest/renewal-request",
	"GET /public/t/{slug}/register/sponsors",
	"POST /public/t/{slug}/register",
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
