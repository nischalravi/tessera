package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RecordTestLogin records that user signed in successfully through the still
// pending connection (the test login of design §15.2, GET
// /api/auth/login?connection=…&test=1). It counts only for the admin who
// requested the connection's creation, and only once. The login flow calls it
// in the transaction of that sign-in.
func RecordTestLogin(tx *store.TenantTx, connectionID, userID uuid.UUID, now time.Time) error {
	err := tx.RecordConnectionTestLogin(connectionID, userID, now)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("pending connection requested by this user")
	}
	if err != nil {
		return err
	}
	_, err = audit.Record(tx.Context(), tx, "idp_connection.test_login", ojson.Object{
		{Key: "connection_id", Value: connectionID.String()}, {Key: "user_id", Value: userID.String()}},
		audit.At(now), audit.Target("idp_connection", connectionID.String()))
	return err
}

// ActivateConnection makes a pending connection active (design §15.2): it
// was created by an applied idp_connection.create request (so it waited out
// the 24 h cooling-off) and the admin who requested it has since signed in
// through it once. Only that admin may activate it, with a fresh
// STEP_UP_ADMIN.
func (s *Service) ActivateConnection(ctx context.Context, p *auth.Principal, id uuid.UUID) (*store.IdPConnection, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminChangeReq, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	var conn *store.IdPConnection
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		c, err := e.connection(id)
		if err != nil {
			return err
		}
		if c.Status != "pending" {
			return conflict("invalid_state", "the connection is %s, not pending", c.Status)
		}
		ch, err := tx.AppliedConnectionCreate(id)
		if errors.Is(err, store.ErrNotFound) {
			return conflict("not_created_by_change", "this connection was not created by an admin change request; "+
				"an operator activates it")
		}
		if err != nil {
			return err
		}
		switch {
		case ch.RequestedBy != *p.UserID:
			return newErr(http.StatusForbidden, "not_requester", "only the admin who requested this connection can activate it")
		case ch.TestLoginAt == nil:
			return conflict("test_login_required", "sign in once through this connection (GET /api/auth/login?connection=%s&test=1) "+
				"before activating it", id)
		}
		cid := ch.ID.String()
		if err := tx.SetIdPConnectionStatus(id, "pending", "active", now, &cid); err != nil {
			return err
		}
		if _, err := audit.Record(tx.Context(), tx, "idp_connection.activated", ojson.Object{
			{Key: "connection_id", Value: id.String()}, {Key: "change_id", Value: cid},
			{Key: "by", Value: p.Display}}, audit.At(now), audit.Target("idp_connection", id.String())); err != nil {
			return err
		}
		if err := e.queueAll(&ch.ID, nil, "admin.idp_connection.activated", "[Tessera] IdP connection activated: "+c.Name,
			"The IdP connection "+c.Name+" was activated by "+p.Display+" after a successful test login. "+
				"People can now sign in through it.\n", "conn-activated:"+id.String()); err != nil {
			return err
		}
		conn, err = tx.IdPConnection(id)
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return conn, nil
}

// DisableUser disables a user and revokes their sessions at once (design
// §15.1: narrowing takes effect immediately but is audited and notified).
// It needs admin.users.disable and a fresh STEP_UP_ADMIN, and is refused for
// yourself and for the admin whose removal would leave fewer than min_admins.
func (s *Service) DisableUser(ctx context.Context, p *auth.Principal, id uuid.UUID, reason string) (*store.PlatformUser, error) {
	now := s.now()
	if d := auth.Check(p, auth.PermAdminUsersDisable, &auth.StepUpAdmin, now); d != nil {
		return nil, denied(d)
	}
	if n := len(reason); n < 3 || n > 500 {
		return nil, invalid("reason is required: 3 to 500 characters")
	}
	var out *store.PlatformUser
	err := s.DB.InTenant(ctx, p.TenantID, func(tx *store.TenantTx) error {
		e := s.env(tx, now, *p.UserID)
		u, err := e.user(id)
		if err != nil {
			return err
		}
		switch {
		case u.Status != "active":
			return conflict("already_disabled", "the user is already disabled")
		case u.ID == *p.UserID:
			return conflict("self_disable", "you cannot disable yourself")
		}
		isAdmin, err := e.isActiveAdmin(u.ID)
		if err != nil {
			return err
		}
		if isAdmin {
			t, err := e.tenantRecord()
			if err != nil {
				return err
			}
			admins, err := e.activeAdmins()
			if err != nil {
				return err
			}
			if len(admins)-1 < t.MinAdmins {
				return conflict("min_admins", "this would leave %d active admins; the tenant needs at least %d", len(admins)-1, t.MinAdmins)
			}
		}
		if err := tx.DisableUser(id, reason, now); err != nil {
			return err
		}
		n, err := tx.RevokeUserSessions(id, auth.RevokedUserDisabled, now)
		if err != nil {
			return err
		}
		if _, err := tx.RevokeMCPTokensOfUser(id, auth.RevokedUserDisabled, now); err != nil {
			return err
		}
		if _, err := audit.Record(tx.Context(), tx, "admin.user.disabled", ojson.Object{{Key: "user_id", Value: id.String()},
			{Key: "reason", Value: reason}, {Key: "sessions_revoked", Value: n}, {Key: "by", Value: p.Display}},
			audit.At(now), audit.Target("platform_user", id.String())); err != nil {
			return err
		}
		if err := e.queueAll(nil, nil, "admin.user.disabled", "[Tessera] User disabled: "+u.DisplayName,
			u.DisplayName+" was disabled by "+p.Display+" and their sessions were revoked.\nReason: "+reason+"\n",
			"user-disabled:"+id.String()+":"+now.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		out, err = tx.PlatformUser(id)
		return err
	})
	if err != nil {
		return nil, mapStore(err)
	}
	return out, nil
}
