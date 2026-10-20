package api

import (
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The request pipeline's authentication and authorization steps (design
// §5.2 steps 4 and 6) and the session routes of §16.1.

// authorize authenticates the request (unless the route is public), hands
// the principal to the audit middleware, enforces CSRF and JSON bodies on
// unsafe requests, and checks the route's declared permission and
// authentication requirement. It writes the refusal itself and returns false
// when the request must stop.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, rt *route) (*http.Request, bool) {
	if rt.spec.Public {
		audit.SetAnonymous(r.Context(), "public_route")
		return r, true
	}
	p, fail, err := s.authn.AuthenticateRequest(r)
	if err != nil {
		// The session or token could not be checked: fail closed.
		s.log.Error("authentication failed", "method", r.Method, "path", r.URL.Path, "err", err)
		audit.SetAnonymous(r.Context(), "authentication_error")
		if timedOut(r, err) {
			writeTimedOut(w)
			return r, false
		}
		s.log.Error("authentication failed", "method", r.Method, "path", r.URL.Path, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return r, false
	}
	if p == nil {
		if fail == nil {
			fail = &auth.Failure{Reason: auth.FailNoSession}
		}
		audit.SetAnonymous(r.Context(), fail.Reason)
		// a refused DPoP token carries the RFC 9449 §7.1 challenge (and a nonce to use)
		if fail.Challenge != "" {
			w.Header().Set("WWW-Authenticate", fail.Challenge)
		}
		if fail.Nonce != "" {
			w.Header().Set("DPoP-Nonce", fail.Nonce)
		}
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusUnauthorized, Error: "login_required"})
		return r, false
	}
	markAuthenticated(r.Context())
	now := s.clock()
	ctx := auth.WithPrincipal(r.Context(), p)
	sid := p.SessionID.String()
	ap := audit.Principal{Tenant: p.TenantID, Actor: p.AuditActor(), SessionID: &sid, Authn: p.AuditAuthn(now)}
	if p.Via == auth.ViaDPoP {
		ap.ClientID = &p.ClientID
	}
	ctx = audit.SetPrincipal(ctx, ap)
	r = r.WithContext(ctx)
	if !auth.SafeMethod(r.Method) {
		if hasBody(r) && !jsonContentType(r) {
			writeJSON(w, http.StatusUnsupportedMediaType, ojson.Object{{Key: "error", Value: "unsupported_media_type"},
				{Key: "detail", Value: "request bodies must be application/json"}})
			return r, false
		}
		// CSRF protects ambient credentials: a DPoP token is not sent by a
		// browser on its own, and its proof is bound to the request
		if p.Via != auth.ViaDPoP {
			if err := auth.CheckCSRF(r, p, s.csrfOrigins()); err != nil {
				writeJSON(w, http.StatusForbidden, ojson.Object{{Key: "error", Value: "csrf_failed"}})
				return r, false
			}
		}
	}
	d := auth.Check(p, rt.spec.Perm, rt.spec.Authn, now)
	if rt.spec.Authn != nil && !rt.spec.NoConditionalAccess && p.Kind == auth.KindUser &&
		(d == nil || d.Error == "step_up_required") {
		// a privileged action: the tenant's conditional access policies may
		// deny it or add a step-up of their own (access.go)
		var err error
		if d, err = s.accessCheck(r.Context(), r, nil, p, rt.spec.Perm, rt.spec.Authn, rt.method+" "+rt.pattern); err != nil {
			s.log.Error("conditional access failed", "method", r.Method, "path", r.URL.Path, "err", err)
			writeAuditUnavailable(w, r)
			return r, false
		}
	}
	if d != nil {
		if p.Via == auth.ViaDPoP {
			auth.WriteDenialScheme(w, d, "DPoP")
		} else {
			auth.WriteDenial(w, d)
		}
		return r, false
	}
	return r, true
}

// hasBody reports whether the request carries a body.
func hasBody(r *http.Request) bool { return r.ContentLength != 0 }

// jsonContentType reports whether the body is declared as JSON.
func jsonContentType(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// principal returns the request's authenticated principal. Every non-public
// route runs after authorize, so it is always there; a missing one is a
// programming error and fails loudly rather than running unattributed.
func principal(r *http.Request) *auth.Principal {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		panic("api: no principal in the request context (route not behind authorize)")
	}
	return p
}

// denial is an authorization refusal decided inside a handler (for example
// a revoke with dry_run=false). writeError renders it.
type denial struct{ d *auth.Denial }

func (d denial) Error() string { return d.d.Error }

// deniedBody is a refusal a handler answers with instead of returning an
// error, so the request's transaction commits and keeps the access.decision
// event of a conditional access refusal. dispatch writes it after the commit.
type deniedBody struct{ d *auth.Denial }

// ---------------------------------------------------------------- session routes

func (s *Server) registerAuthRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/auth/session", read, need(auth.PermAuthenticated), s.authSession)
	s.handle(P, "/api/auth/logout", write, need(auth.PermAuthenticated), s.authLogout)
	s.handle(G, "/api/auth/sessions", read, need(auth.PermAuthenticated), s.authSessions)
	s.handle(http.MethodDelete, "/api/auth/sessions/{session_id}", write, need(auth.PermAuthenticated), s.authRevokeSession)
}

func rt3339(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func roleNames(rs []auth.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// authSession is GET /api/auth/session: who is signed in, their roles
// (active and inactive with the reason), the authentication summary, the
// CSRF token and the session's expiry.
func (s *Server) authSession(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	p := principal(r)
	tx := store.TxFrom(r.Context())
	u, err := tx.PlatformUser(*p.UserID)
	if err != nil {
		return nil, err
	}
	var tenant store.Tenant
	if err := s.store.ReadSystem(r.Context(), "session tenant", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantByID(p.TenantID)
		return err
	}); err != nil {
		return nil, err
	}
	inactive := []ojson.Object{}
	for _, role := range auth.AllRoles() {
		if why, ok := p.InactiveRoles[role]; ok {
			inactive = append(inactive, ojson.Object{{Key: "role", Value: string(role)}, {Key: "reason", Value: why}})
		}
	}
	perms := []string{}
	for _, perm := range auth.EffectivePermissions(p).Sorted() {
		perms = append(perms, string(perm))
	}
	a, sess := p.Authn, p.Session()
	methods := a.Methods
	if methods == nil {
		methods = []string{}
	}
	return ojson.Object{
		{Key: "user", Value: ojson.Object{{Key: "id", Value: u.ID.String()}, {Key: "email", Value: u.Email},
			{Key: "display_name", Value: u.DisplayName}, {Key: "identity_id", Value: u.IdentityID}}},
		{Key: "tenant", Value: ojson.Object{{Key: "id", Value: tenant.ID.String()}, {Key: "slug", Value: tenant.Slug},
			{Key: "name", Value: tenant.Name}}},
		{Key: "roles", Value: roleNames(p.AssignedRoles.Sorted())},
		{Key: "active_roles", Value: roleNames(p.ActiveRoles.Sorted())},
		{Key: "inactive_roles", Value: inactive},
		{Key: "permissions", Value: perms},
		{Key: "authn", Value: ojson.Object{{Key: "aal", Value: a.AAL}, {Key: "phishing_resistant", Value: a.PhishingResistant},
			{Key: "phr_basis", Value: a.PhrBasis}, {Key: "acr", Value: string(a.TesseraACR)}, {Key: "methods", Value: methods},
			{Key: "auth_time", Value: rt3339(a.AuthTime)}}},
		{Key: "session", Value: ojson.Object{{Key: "id", Value: sess.ID.String()},
			{Key: "idle_expires_at", Value: rt3339(sess.IdleExpiresAt)},
			{Key: "absolute_expires_at", Value: rt3339(sess.AbsoluteExpiresAt)}}},
		{Key: "csrf_token", Value: p.CSRFToken()},
	}, nil
}

// authLogout is POST /api/auth/logout: it revokes the current session and
// clears the cookie.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	p := principal(r)
	tx := store.TxFrom(r.Context())
	now := s.clock()
	if err := auth.RevokeSession(tx, *p.SessionID, auth.RevokedLogout, now); err != nil {
		return nil, err
	}
	if _, err := audit.Record(r.Context(), tx, "auth.logout", ojson.Object{{Key: "session_id", Value: p.SessionID.String()}},
		audit.At(now), audit.Target("session", p.SessionID.String())); err != nil {
		return nil, err
	}
	http.SetCookie(w, s.authn.Cookies.Clear())
	return ojson.Object{{Key: "status", Value: "signed_out"}}, nil
}

// authSessions is GET /api/auth/sessions: the caller's own sessions.
func (s *Server) authSessions(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	p := principal(r)
	ss, err := store.TxFrom(r.Context()).SessionsForUser(*p.UserID)
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, x := range ss {
		var revoked any
		if x.RevokedAt != nil {
			revoked = rt3339(*x.RevokedAt)
		}
		out = append(out, ojson.Object{{Key: "id", Value: x.ID.String()}, {Key: "kind", Value: x.Kind},
			{Key: "status", Value: x.Status}, {Key: "current", Value: x.ID == *p.SessionID},
			{Key: "created_at", Value: rt3339(x.CreatedAt)}, {Key: "last_activity_at", Value: rt3339(x.LastActivityAt)},
			{Key: "idle_expires_at", Value: rt3339(x.IdleExpiresAt)},
			{Key: "absolute_expires_at", Value: rt3339(x.AbsoluteExpiresAt)},
			{Key: "revoked_at", Value: revoked}, {Key: "revoked_reason", Value: x.RevokedReason},
			{Key: "ip_first", Value: x.IPFirst}})
	}
	return out, nil
}

// authRevokeSession is DELETE /api/auth/sessions/{session_id}: the caller's
// own session, or (admin.sessions.revoke with STEP_UP_ADMIN) another user's
// in the same tenant. Any other session id is 404, like a missing one.
func (s *Server) authRevokeSession(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	pr := principal(r)
	id, err := uuid.Parse(p.path["session_id"])
	if err != nil {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	tx := store.TxFrom(r.Context())
	sess, err := tx.Session(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "Not Found")
	}
	if err != nil {
		return nil, err
	}
	now := s.clock()
	reason := auth.RevokedLogout
	if sess.UserID != *pr.UserID {
		d := auth.Check(pr, auth.PermAdminSessionsRev, &auth.StepUpAdmin, now)
		switch {
		case d == nil:
		case d.Error == "forbidden":
			return nil, errStatus(http.StatusNotFound, "Not Found")
		default:
			return nil, denial{d}
		}
		reason = auth.RevokedAdmin
	}
	if err := auth.RevokeSession(tx, id, reason, now); errors.Is(err, store.ErrSessionInactive) {
		return nil, errStatus(http.StatusConflict, "session is not active")
	} else if err != nil {
		return nil, err
	}
	if _, err := audit.Record(r.Context(), tx, "auth.session.revoked", ojson.Object{{Key: "session_id", Value: id.String()},
		{Key: "reason", Value: reason}}, audit.At(now), audit.Target("session", id.String())); err != nil {
		return nil, err
	}
	if id == *pr.SessionID {
		http.SetCookie(w, s.authn.Cookies.Clear())
	}
	return ojson.Object{{Key: "id", Value: id.String()}, {Key: "status", Value: store.SessionRevoked}}, nil
}
