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
	FailTenantInactive = "tenant_inactive"
)

// Authenticator resolves the session cookie of a request to a Principal
// (design §12.4, cookie path; the DPoP token path arrives in PR10).
type Authenticator struct {
	DB      *store.DB
	Clock   func() time.Time
	Cookies Cookies
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
	if tenant.Status != "active" || tid == tenancy.Platform {
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
		settings := TenantSettings(tenant.Settings)
		active, inactive := ActivateRoles(assigned, &authn, settings, now)
		uid, sessID := u.ID, s.ID
		display := u.DisplayName
		if u.Email != nil && *u.Email != "" {
			display = *u.Email
		}
		p = &Principal{Kind: KindUser, TenantID: tid, UserID: &uid, Display: display, SessionID: &sessID,
			Authn: &authn, AssignedRoles: assigned, ActiveRoles: active, InactiveRoles: inactive, Via: ViaCookie,
			IdentityID: u.IdentityID, GroupsViewerView: settings.GroupsViewerCanView, session: s}
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
