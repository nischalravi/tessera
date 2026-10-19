package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The test sign-in of a pending IdP connection (design §15.2): the admin who
// requested the connection signs in once through it, GET
// /api/auth/login?connection=<id>&test=1, before activating it. It proves the
// IdP works; it never creates a session, never creates a user and never
// grants a role. The callback only records the test login on the admin's
// own, still-live session.

// startTestLogin begins the test sign-in of pending connection want for the
// signed-in admin. Anything else is refused and audited.
func (s *Server) startTestLogin(w http.ResponseWriter, r *http.Request, t store.Tenant, want, returnTo string) (any, error) {
	now := s.clock().UTC()
	p, _, err := s.authn.Authenticate(r)
	if err != nil {
		return nil, err
	}
	if p == nil || p.Kind != auth.KindUser || p.TenantID != t.ID || p.UserID == nil || p.SessionID == nil ||
		auth.Check(p, auth.PermAdminChangeReq, nil, now) != nil {
		return s.loginFailure(w, r, t.ID, "test_login_admin_required", nil)
	}
	id, err := uuid.Parse(want)
	if err != nil {
		return s.loginFailure(w, r, t.ID, "unknown_connection", nil)
	}
	var conn *store.IdPConnection
	reason := ""
	if err := s.store.ReadTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(id)
		if errors.Is(err, store.ErrNotFound) {
			reason = "unknown_connection"
			return nil
		}
		if err != nil {
			return err
		}
		ch, err := tx.AppliedConnectionCreate(id)
		switch {
		case c.Status != "pending" || (c.Protocol != "oidc" && c.Protocol != "saml"):
			reason = "test_login_not_pending"
		case errors.Is(err, store.ErrNotFound):
			reason = "test_login_not_requested"
		case err != nil:
			return err
		case ch.RequestedBy != *p.UserID:
			reason = "test_login_not_requester"
		case ch.TestLoginAt != nil:
			reason = "test_login_done"
		default:
			conn = c
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if reason != "" {
		return s.loginFailure(w, r, t.ID, reason, ojson.Object{{Key: "connection_id", Value: truncate(want, 64)}})
	}
	sid := *p.SessionID
	return s.startLogin(w, r, t, conn, loginStart{purpose: "test", returnTo: returnTo, acr: LoginACR(t.Settings), session: &sid})
}

// finishTestLogin ends a test sign-in (the ID token or assertion is valid
// and normalized; the transaction is consumed): the browser must still hold
// the admin's session, and the admin's test login is recorded.
func (s *Server) finishTestLogin(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction) (any, error) {
	ctx := r.Context()
	now := s.clock().UTC()
	fail := func(reason string) (any, error) {
		return s.loginFailure(w, r, tenant.ID, reason, ojson.Object{{Key: "login_transaction_id", Value: txn.ID.String()},
			{Key: "connection_id", Value: conn.ID.String()}})
	}
	if txn.SessionID == nil {
		return fail("test_login_transaction_invalid")
	}
	pt, psid, ok, err := s.authn.RequestSession(r)
	if err != nil {
		return nil, err
	}
	if !ok || pt != tenant.ID || psid != *txn.SessionID {
		return fail("test_login_session_mismatch")
	}
	var user *store.PlatformUser
	reason := ""
	if err := s.store.ReadTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		sess, err := tx.Session(*txn.SessionID)
		if err != nil {
			return err
		}
		if sess.Status != store.SessionActive || !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt) {
			reason = "session_inactive"
			return nil
		}
		if user, err = tx.PlatformUser(sess.UserID); err != nil {
			return err
		}
		if user.Status != "active" {
			reason = "user_disabled"
		} else if off, err := auth.IdentityDisabled(tx, user); err != nil {
			return err
		} else if off {
			reason = auth.FailIdentityDisabled
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if reason != "" {
		return fail(reason)
	}
	uid, display := user.ID.String(), user.DisplayName
	if user.Email != nil && *user.Email != "" {
		display = *user.Email
	}
	sid := txn.SessionID.String()
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: tenant.ID, SessionID: &sid,
		Actor: store.AuditActor{Type: store.ActorUser, ID: &uid, Display: &display}})
	err = s.store.InTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(conn.ID)
		if err != nil {
			return err
		}
		if c.Status != "pending" {
			reason = "test_login_not_pending"
			return nil
		}
		return admin.RecordTestLogin(tx, conn.ID, user.ID, now)
	})
	var ae *admin.Error
	switch {
	case errors.As(err, &ae):
		return fail("test_login_not_recorded")
	case err != nil:
		return nil, err
	case reason != "":
		return fail(reason)
	}
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(txn.ReturnTo, "test_login", "ok"), http.StatusFound)
	return nil, nil
}
