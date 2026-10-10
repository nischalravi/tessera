package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// loginOptions describe how a sign-in ends (completeLogin).
type loginOptions struct {
	via, protocol, purpose string
	// user is the platform user. When insert is set, the user does not exist
	// yet: insert creates it (with user.ID) in the session's transaction.
	user   *store.PlatformUser
	insert func(tx *store.TenantTx) error
	// extra runs in the session's transaction after the user exists (role
	// sync, invitation consumption).
	extra func(tx *store.TenantTx) error
	// detail is added to auth.login.success.
	detail ojson.Object
}

// completeLogin ends every successful sign-in the same way: the browser's
// previous session is revoked (in its own tenant), the normalized
// authentication is recorded, a session is created under the tenant's
// settings, the user's last login is stamped, auth.login.success is written
// with the authentication summary, and the session cookie is set. Events of
// the sign-in are attributed to the user.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	res authnorm.Result, o loginOptions) (auth.Issued, error) {
	ctx := r.Context()
	now := s.clock().UTC()
	user := o.user
	actor := store.AuditActor{Type: store.ActorUser}
	uid := user.ID.String()
	display := user.DisplayName
	if user.Email != nil && *user.Email != "" {
		display = *user.Email
	}
	actor.ID, actor.Display = &uid, &display
	rec := &store.AuthnContextRecord{ID: uuid.New()}
	summary := (&auth.Principal{Authn: &auth.AuthnContext{ID: rec.ID, AAL: res.AAL, PhishingResistant: res.PhishingResistant,
		TesseraACR: auth.ACR(res.TesseraACR), AuthTime: res.AuthTime}}).AuditAuthn(now)

	// Signing in again replaces the browser's previous session (§11): it is
	// revoked with the new session's creation when it is the same tenant,
	// and on the system's behalf before it otherwise.
	prevTenant, prevSID, hadSession, err := s.authn.RequestSession(r)
	if err != nil {
		return auth.Issued{}, err
	}
	if hadSession && prevTenant != tenant.ID {
		sys := audit.AsSystem(ctx, "auth.login")
		if err := s.store.InTenant(sys, prevTenant, func(tx *store.TenantTx) error {
			_, err := auth.RevokeReplaced(sys, tx, prevSID, now)
			return err
		}); err != nil {
			return auth.Issued{}, err
		}
	}
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: tenant.ID, Actor: actor, Authn: summary})
	var issued auth.Issued
	err = s.store.InTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		if hadSession && prevTenant == tenant.ID {
			if _, err := auth.RevokeReplaced(ctx, tx, prevSID, now); err != nil {
				return err
			}
		}
		if o.insert != nil {
			if err := o.insert(tx); err != nil {
				return err
			}
		}
		if o.extra != nil {
			if err := o.extra(tx); err != nil {
				return err
			}
		}
		ip, ua := clientAddr(r), userAgent(r)
		var connID *uuid.UUID
		if conn != nil {
			connID = &conn.ID
		}
		*rec = store.AuthnContextRecord{ID: rec.ID, UserID: user.ID, IdPConnectionID: connID, Protocol: o.protocol,
			Purpose: authnPurpose(o.purpose), ACR: res.ACR, AMR: res.AMR, Methods: res.Methods, AAL: res.AAL,
			PhishingResistant: res.PhishingResistant, PhrBasis: res.PhrBasis, TesseraACR: res.TesseraACR,
			AuthTime: res.AuthTime, IP: ip, UserAgent: ua, MappingProfile: res.MappingProfile,
			MappingVersion: res.MappingVersion, ClaimsSHA256: res.ClaimsSHA256, CreatedAt: now}
		if err := tx.InsertAuthnContext(rec); err != nil {
			return err
		}
		var err error
		issued, err = auth.CreateSession(tx, auth.SessionInput{User: user, Authn: rec, Now: now, IP: ip, UA: ua,
			Settings: auth.TenantSettings(tenant.Settings)})
		if err != nil {
			return err
		}
		if err := tx.SetUserLastLogin(user.ID, now); err != nil {
			return err
		}
		sid := issued.Session.ID.String()
		detail := ojson.Object{{Key: "via", Value: o.via}, {Key: "purpose", Value: o.purpose},
			{Key: "session_id", Value: sid}, {Key: "authn_context_id", Value: rec.ID.String()},
			{Key: "aal", Value: rec.AAL}, {Key: "phishing_resistant", Value: rec.PhishingResistant},
			{Key: "phr_basis", Value: rec.PhrBasis}, {Key: "acr", Value: rec.TesseraACR}}
		if conn != nil {
			detail = append(detail, ojson.KV{Key: "connection_id", Value: conn.ID.String()})
		}
		_, err = audit.Record(ctx, tx, "auth.login.success", append(detail, o.detail...), audit.At(now),
			audit.Target("session", sid))
		return err
	})
	if err != nil {
		return auth.Issued{}, err
	}
	sid := issued.Session.ID.String()
	audit.SetPrincipal(ctx, audit.Principal{Tenant: tenant.ID, Actor: actor, SessionID: &sid, Authn: summary})
	http.SetCookie(w, s.authn.Cookies.Session(issued.Secret))
	return issued, nil
}

// authnPurpose is the authn_contexts purpose of a sign-in purpose.
func authnPurpose(p string) string {
	switch p {
	case "step_up", "bootstrap", "device_approval", "break_glass":
		return p
	}
	return "login"
}
