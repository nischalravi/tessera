package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// How a principal was authenticated.
const (
	ViaCookie = "cookie"
	ViaDPoP   = "dpop" // PR10
)

// Reasons an authentication failed (recorded as the anonymous_reason of the
// request's http.request event; the client only sees 401 login_required).
const (
	FailNoSession      = "no_session"
	FailInvalidSession = "invalid_session"
	FailExpired        = "session_expired"
	FailRevoked        = "session_revoked"
	FailUserDisabled   = "user_disabled"
	// FailIdentityDisabled: the user's linked governed identity is not active
	// (disabled, terminated or merged; #316, #331).
	FailIdentityDisabled = "identity_disabled"
	FailTenantInactive   = "tenant_inactive"
)

// Authenticator resolves the session cookie of a request to a Principal
// (design §12.4, cookie path; the DPoP token path arrives in PR10).
type Authenticator struct {
	DB      *store.DB
	Clock   func() time.Time
	Cookies Cookies
	// Tokens verifies Authorization: DPoP credentials (internal/oauth). Nil:
	// every Authorization header is refused (token.go).
	Tokens TokenVerifier
}

// RequestSession returns the tenant and id of the session the request's
// cookie names, whatever its state; ok is false without such a session.
func (a *Authenticator) RequestSession(r *http.Request) (t tenancy.ID, sid uuid.UUID, ok bool, err error) {
	c, err := r.Cookie(a.Cookies.Name())
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return t, sid, false, nil
	}
	hash := HashSecret(c.Value)
	err = a.DB.ReadSystem(r.Context(), "session lookup", func(s *store.SystemTx) error {
		var err error
		t, sid, err = s.LookupSessionBySecretHash(hash)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return t, sid, false, nil
	}
	return t, sid, err == nil, err
}

// Authenticate returns the request's principal, or "" and a failure reason
// (FailNoSession, ...) when the request is not authenticated. err is set
// only when the session could not be checked (the database failed): the
// caller must fail closed.
//
// The tenant comes only from the session row (§14.2): the cookie's hash is
// looked up once outside a tenant transaction, which yields just (tenant,
// sid), and everything else is read inside that tenant. Idle and absolute
// expiry are enforced here on every request; activity is recorded at most
// once per TouchInterval.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, string, error) {
	p, f, err := a.AuthenticateRequest(r)
	if f != nil {
		return p, f.Reason, err
	}
	return p, "", err
}

// AuthenticateRequest is Authenticate with the failure's challenge. A request
// carrying an Authorization header is a token request: it is authenticated
// by its DPoP-bound access token only, never by a cookie it may also carry.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*Principal, *Failure, error) {
	if len(r.Header.Values("Authorization")) > 0 {
		return a.authenticateToken(r)
	}
	p, reason, err := a.authenticateCookie(r)
	if reason != "" {
		return p, &Failure{Reason: reason}, err
	}
	return p, nil, err
}

func (a *Authenticator) authenticateCookie(r *http.Request) (*Principal, string, error) {
	c, err := r.Cookie(a.Cookies.Name())
	if err != nil || c.Value == "" {
		return nil, FailNoSession, nil
	}
	if len(c.Value) > 128 {
		return nil, FailInvalidSession, nil
	}
	hash := HashSecret(c.Value)
	ctx := r.Context()
	var tid tenancy.ID
	var sid uuid.UUID
	var tenant store.Tenant
	err = a.DB.ReadSystem(ctx, "session lookup", func(s *store.SystemTx) error {
		t, id, err := s.LookupSessionBySecretHash(hash)
		if err != nil {
			return err
		}
		tid, sid = t, id
		tenant, err = s.TenantByID(t)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, FailInvalidSession, nil
	}
	if err != nil {
		return nil, "", err
	}
	// A tenant in operator recovery (§15.5) stays signed-in: the existing
	// admins' sessions must work so they can cancel the recovery.
	if (tenant.Status != "active" && tenant.Status != "recovery") || tid == tenancy.Platform {
		return nil, FailTenantInactive, nil
	}
	now := a.Clock().UTC()
	var p *Principal
	var reason string
	var expire, touch bool
	err = a.DB.ReadTenant(ctx, tid, func(tx *store.TenantTx) error {
		s, err := tx.Session(sid)
		if err != nil {
			return err
		}
		// The lookup matched on the hash; compare again inside the tenant,
		// in constant time, before trusting the row.
		if s.SecretHash == nil || subtle.ConstantTimeCompare([]byte(*s.SecretHash), []byte(hash)) != 1 ||
			(s.Kind != store.SessionBrowser && s.Kind != store.SessionBreakGlass) {
			reason = FailInvalidSession
			return nil
		}
		switch {
		case s.Status == store.SessionRevoked:
			reason = FailRevoked
			return nil
		case s.Status != store.SessionActive:
			reason = FailExpired
			return nil
		case !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt):
			reason, expire = FailExpired, true
			return nil
		}
		u, err := tx.PlatformUser(s.UserID)
		if err != nil {
			return err
		}
		if u.Status != "active" {
			reason = FailUserDisabled
			return nil
		}
		if off, err := IdentityInactive(tx, u); err != nil {
			return err
		} else if off {
			reason = FailIdentityDisabled
			return nil
		}
		rec, err := tx.AuthnContext(s.CurrentAuthnContextID)
		if err != nil {
			return err
		}
		as, err := tx.RoleAssignments(u.ID)
		if err != nil {
			return err
		}
		authn := ContextFromRecord(rec)
		assigned := AssignedRoles(as, now)
		// the floors of the session's own tenant (§18.3), read with the session
		active, inactive := ActivateRoles(assigned, &authn, TenantSettings(tenant.Settings), now)
		uid, sessID := u.ID, s.ID
		display := u.DisplayName
		if u.Email != nil && *u.Email != "" {
			display = *u.Email
		}
		p = &Principal{Kind: KindUser, TenantID: tid, UserID: &uid, Display: display, SessionID: &sessID,
			Authn: &authn, AssignedRoles: assigned, ActiveRoles: active, InactiveRoles: inactive, Via: ViaCookie,
			session: s}
		if s.CSRFSecret != nil {
			p.csrfSecret = *s.CSRFSecret
		}
		touch = now.Sub(s.LastActivityAt) >= TouchInterval
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, FailInvalidSession, nil
	}
	if err != nil {
		return nil, "", err
	}
	if expire {
		// best effort: the request is refused either way
		_ = a.DB.InTenant(context.WithoutCancel(ctx), tid, func(tx *store.TenantTx) error { return tx.ExpireSession(sid) })
	}
	if p == nil {
		return nil, reason, nil
	}
	if touch {
		s := p.session
		idle, _ := Timeouts(s.Kind, p.ActiveRoles)
		idleExpires := now.Add(idle)
		if idleExpires.After(s.AbsoluteExpiresAt) {
			idleExpires = s.AbsoluteExpiresAt
		}
		err := a.DB.InTenant(ctx, tid, func(tx *store.TenantTx) error { return tx.TouchSession(sid, now, idleExpires) })
		if errors.Is(err, store.ErrSessionInactive) {
			return nil, FailRevoked, nil // revoked between the read and the touch
		}
		if err != nil {
			return nil, "", err
		}
		s.LastActivityAt, s.IdleExpiresAt = now, idleExpires
	}
	return p, "", nil
}

// authenticateToken resolves an Authorization: DPoP request to a Principal
// (design §10.4 step 6): the token and proof were verified by a.Tokens; the
// session it names must be an active CLI session of the token's user, within
// its idle and absolute expiry, and the user must be active. Roles are read
// now, from the database, and activated by the session's authentication
// context; the effective permissions are further limited by the token's scopes
// (§12.3).
func (a *Authenticator) authenticateToken(r *http.Request) (*Principal, *Failure, error) {
	if a.Tokens == nil {
		return nil, &Failure{Reason: FailInvalidToken}, nil
	}
	vt, tf, err := a.Tokens.VerifyAccessToken(r)
	if err != nil {
		return nil, nil, err
	}
	if tf != nil {
		return nil, &Failure{Reason: tf.Reason, Challenge: tf.Challenge, Nonce: tf.Nonce}, nil
	}
	if vt.Tenant.Status != "active" || vt.Tenant.ID == tenancy.Platform {
		return nil, &Failure{Reason: FailTenantInactive, Challenge: `DPoP error="invalid_token"`}, nil
	}
	now := a.Clock().UTC()
	var p *Principal
	var reason string
	var expire bool
	err = a.DB.ReadTenant(r.Context(), vt.Tenant.ID, func(tx *store.TenantTx) error {
		s, err := tx.Session(vt.SessionID)
		if err != nil {
			return err
		}
		switch {
		case s.Kind != store.SessionCLI || s.UserID != vt.UserID || (s.ClientID != nil && *s.ClientID != vt.ClientID):
			reason = FailInvalidSession
			return nil
		case s.Status == store.SessionRevoked:
			reason = FailRevoked
			return nil
		case s.Status != store.SessionActive:
			reason = FailExpired
			return nil
		case !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt):
			reason, expire = FailExpired, true
			return nil
		}
		u, err := tx.PlatformUser(s.UserID)
		if err != nil {
			return err
		}
		if u.Status != "active" {
			reason = FailUserDisabled
			return nil
		}
		rec, err := tx.AuthnContext(s.CurrentAuthnContextID)
		if err != nil {
			return err
		}
		as, err := tx.RoleAssignments(u.ID)
		if err != nil {
			return err
		}
		authn := ContextFromRecord(rec)
		assigned := AssignedRoles(as, now)
		active, inactive := ActivateRoles(assigned, &authn, TenantSettings(vt.Tenant.Settings), now)
		uid, sessID := u.ID, s.ID
		display := u.DisplayName
		if u.Email != nil && *u.Email != "" {
			display = *u.Email
		}
		p = &Principal{Kind: KindUser, TenantID: vt.Tenant.ID, UserID: &uid, ClientID: vt.ClientID, Display: display,
			SessionID: &sessID, Authn: &authn, AssignedRoles: assigned, ActiveRoles: active, InactiveRoles: inactive,
			Scopes: ScopeSetOf(vt.Scopes), Via: ViaDPoP, session: s}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Failure{Reason: FailInvalidSession, Challenge: `DPoP error="invalid_token"`}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if expire {
		_ = a.DB.InTenant(context.WithoutCancel(r.Context()), vt.Tenant.ID, func(tx *store.TenantTx) error {
			return tx.ExpireSession(vt.SessionID)
		})
	}
	if p == nil {
		return nil, &Failure{Reason: reason, Challenge: `DPoP error="invalid_token"`}, nil
	}
	return p, nil, nil
}

// Middleware is Authenticate as net/http middleware: it stores the principal
// in the context and refuses an unauthenticated request with 401
// login_required (500 when the session could not be checked).
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _, err := a.Authenticate(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if p == nil {
			WriteDenial(w, &Denial{Status: http.StatusUnauthorized, Error: "login_required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}
