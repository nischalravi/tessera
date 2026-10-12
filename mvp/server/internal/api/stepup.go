package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Step-up (design §9.4, §19 PR8). A route that needs a fresher or stronger
// authentication answers 401 step_up_required with the RFC 9470 challenge and
// a step_up_url. GET /api/auth/step-up starts a re-authentication through the
// IdP the session signed in with: a login transaction with purpose step_up,
// bound to the session and to the external login that must sign in again,
// sending prompt=login and max_age=0. The callback then requires the same
// subject (else auth.step_up.subject_mismatch), an auth_time not older than
// the transaction (the IdP really re-authenticated) and an ACR that meets the
// requirement (else auth.step_up.insufficient); on success the session's
// current authentication becomes the new context, the session secret and
// CSRF token rotate, auth.step_up.success records required vs presented, and
// the browser returns to return_to with ?stepup=ok.

// MaxStepUpAge is the largest max_age a step-up may ask for (§10.2).
const MaxStepUpAge = 900

func (s *Server) registerStepUpRoutes() {
	// noTenant: the handler opens its own transactions (it creates a login
	// transaction and redirects); a GET only starts a re-authentication.
	s.handle(http.MethodGet, "/api/auth/step-up", noTenant, need(auth.PermAuthenticated), s.authStepUp)
}

// withQuery adds k=v to a same-site path's query.
func withQuery(path string, kv ...string) string {
	u, err := url.Parse(path)
	if err != nil {
		return "/"
	}
	q, _ := url.ParseQuery(u.RawQuery)
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// stepUpFailure audits a refused step-up and sends the browser back to the
// page it came from with ?stepup=failed and the request id. The session is
// unchanged.
func (s *Server) stepUpFailure(w http.ResponseWriter, r *http.Request, t tenancy.ID, txn *store.LoginTransaction,
	action, reason string, extra ojson.Object) (any, error) {
	detail := append(ojson.Object{{Key: "reason", Value: reason}, {Key: "login_transaction_id", Value: txn.ID.String()},
		{Key: "required_acr", Value: deref(txn.RequiredTesseraACR)}}, extra...)
	if txn.SessionID != nil {
		detail = append(detail, ojson.KV{Key: "session_id", Value: txn.SessionID.String()})
	}
	if err := s.store.InTenant(r.Context(), t, func(tx *store.TenantTx) error {
		_, err := audit.Record(r.Context(), tx, action, detail, audit.At(s.clock()), audit.Outcome(store.OutcomeFailure))
		return err
	}); err != nil {
		return nil, err
	}
	rid := audit.RequestID(r.Context())
	s.log.Info("step-up refused", "reason", reason, "request_id", rid)
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(txn.ReturnTo, "stepup", "failed", "request_id", rid), http.StatusFound)
	return nil, nil
}

// authStepUp is GET /api/auth/step-up?acr=&max_age=&return_to=.
func (s *Server) authStepUp(w http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	p := principal(r)
	if p.Kind != auth.KindUser || p.SessionID == nil || p.UserID == nil {
		auth.WriteDenial(w, &auth.Denial{Status: http.StatusForbidden, Error: "interactive_authentication_required"})
		return nil, nil
	}
	q := r.URL.Query()
	acr := q.Get("acr")
	if acr == "" {
		acr = authnorm.ACRPhr
	}
	switch acr {
	case authnorm.ACRAAL2, authnorm.ACRPhr, authnorm.ACRPhrh:
	default:
		return nil, errStatus(http.StatusUnprocessableEntity, "acr must be one of urn:tessera:acr:aal2, :phr, :phrh")
	}
	if v := q.Get("max_age"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > MaxStepUpAge {
			return nil, errStatus(http.StatusUnprocessableEntity, "max_age must be from 0 to 900")
		}
	}
	returnTo := q.Get("return_to")
	if returnTo == "" || !store.ValidReturnTo(returnTo) || strings.HasPrefix(returnTo, "/api/") {
		returnTo = "/"
	}
	var tenant store.Tenant
	if err := s.store.ReadSystem(r.Context(), "step-up tenant", func(st *store.SystemTx) error {
		var err error
		tenant, err = st.TenantByID(p.TenantID)
		return err
	}); err != nil {
		return nil, err
	}
	// The IdP to re-authenticate at is the one the session's current
	// authentication came from; the same external login must sign in.
	var conn *store.IdPConnection
	var login *store.ExternalLogin
	if err := s.store.ReadTenant(r.Context(), p.TenantID, func(tx *store.TenantTx) error {
		sess, err := tx.Session(*p.SessionID)
		if err != nil {
			return err
		}
		rec, err := tx.AuthnContext(sess.CurrentAuthnContextID)
		if err != nil || rec.IdPConnectionID == nil {
			return err
		}
		c, err := tx.IdPConnection(*rec.IdPConnectionID)
		if err != nil {
			return err
		}
		if c.Status != "active" || (c.Protocol != "oidc" && c.Protocol != "saml") {
			return nil
		}
		ls, err := tx.ExternalLoginsForUser(*p.UserID)
		if err != nil {
			return err
		}
		for _, l := range ls {
			if l.IdPConnectionID == c.ID {
				conn, login = c, l
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if conn == nil {
		return statusBody{http.StatusConflict, ojson.Object{{Key: "error", Value: "step_up_unavailable"},
			{Key: "detail", Value: "This session did not sign in through an identity provider that can re-authenticate you. Sign out and sign in again."}}}, nil
	}
	sid, lid := *p.SessionID, login.ID
	return s.startLogin(w, r, tenant, conn, loginStart{purpose: "step_up", returnTo: returnTo, acr: acr,
		session: &sid, expectedLogin: &lid, maxAge: 0, prompt: "login"})
}

// finishStepUp completes a step-up callback (the ID token is valid and
// normalized; the transaction is consumed).
func (s *Server) finishStepUp(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction, res authnorm.Result) (any, error) {
	ctx := r.Context()
	now := s.clock().UTC()
	if txn.SessionID == nil || txn.ExpectedExternalLoginID == nil {
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.failure", "step_up_transaction_invalid", nil)
	}
	// the browser finishing the step-up must hold the session it started for
	pt, psid, ok, err := s.authn.RequestSession(r)
	if err != nil {
		return nil, err
	}
	if !ok || pt != tenant.ID || psid != *txn.SessionID {
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.failure", "step_up_session_mismatch", nil)
	}
	var user *store.PlatformUser
	var sess *store.Session
	reason := ""
	if err := s.store.ReadTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		var err error
		if sess, err = tx.Session(*txn.SessionID); err != nil {
			return err
		}
		if sess.Status != store.SessionActive || !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt) {
			reason = "session_inactive"
			return nil
		}
		l, err := tx.ExternalLoginBySubject(conn.ID, res.Subject)
		if errors.Is(err, store.ErrNotFound) || (err == nil && l.ID != *txn.ExpectedExternalLoginID) {
			reason = "subject_mismatch"
			return nil
		}
		if err != nil {
			return err
		}
		if user, err = tx.PlatformUser(sess.UserID); err != nil {
			return err
		}
		if l.UserID != user.ID {
			reason = "subject_mismatch"
		} else if user.Status != "active" {
			reason = "user_disabled"
		}
		return nil
	}); err != nil {
		return nil, err
	}
	switch reason {
	case "":
	case "subject_mismatch":
		// someone else signed in at the IdP: never upgrade this session
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.subject_mismatch", reason,
			ojson.Object{{Key: "presented_subject", Value: truncate(res.Subject, 128)}})
	default:
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.failure", reason, nil)
	}
	required := auth.AuthnRequirement{ACR: auth.ACR(deref(txn.RequiredTesseraACR))}
	presented := auth.AuthnContext{AAL: res.AAL, PhishingResistant: res.PhishingResistant, TesseraACR: auth.ACR(res.TesseraACR),
		AuthTime: res.AuthTime}
	presentedDetail := ojson.Object{{Key: "acr", Value: res.TesseraACR}, {Key: "aal", Value: res.AAL},
		{Key: "phishing_resistant", Value: res.PhishingResistant}, {Key: "phr_basis", Value: res.PhrBasis}}
	if !presented.Satisfies(required, now) {
		// the IdP did not confirm what was asked (for example acr=urn:okta:loa:2fa:any)
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.insufficient", "insufficient_authentication",
			ojson.Object{{Key: "presented", Value: presentedDetail}, {Key: "idp_acr", Value: res.ACR}})
	}

	actor := store.AuditActor{Type: store.ActorUser}
	uid, display := user.ID.String(), user.DisplayName
	if user.Email != nil && *user.Email != "" {
		display = *user.Email
	}
	actor.ID, actor.Display = &uid, &display
	rec := &store.AuthnContextRecord{ID: uuid.New()}
	summary := (&auth.Principal{Authn: &auth.AuthnContext{ID: rec.ID, AAL: res.AAL, PhishingResistant: res.PhishingResistant,
		TesseraACR: auth.ACR(res.TesseraACR), AuthTime: res.AuthTime}}).AuditAuthn(now)
	sidStr := sess.ID.String()
	ctx = audit.SetPrincipal(ctx, audit.Principal{Tenant: tenant.ID, Actor: actor, SessionID: &sidStr, Authn: summary})
	var issued auth.Issued
	err = s.store.InTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		ip, ua := clientAddr(r), userAgent(r)
		*rec = store.AuthnContextRecord{ID: rec.ID, UserID: user.ID, IdPConnectionID: &conn.ID, Protocol: conn.Protocol,
			Purpose: "step_up", ACR: res.ACR, AMR: res.AMR, Methods: res.Methods, AAL: res.AAL,
			PhishingResistant: res.PhishingResistant, PhrBasis: res.PhrBasis, TesseraACR: res.TesseraACR,
			AuthTime: res.AuthTime, IP: ip, UserAgent: ua, MappingProfile: res.MappingProfile,
			MappingVersion: res.MappingVersion, ClaimsSHA256: res.ClaimsSHA256, CreatedAt: now,
			Device: res.Device.JSON()}
		if err := tx.InsertAuthnContext(rec); err != nil {
			return err
		}
		var err error
		if issued, err = auth.RotateSession(tx, sess.ID, rec.ID, auth.TenantSettings(tenant.Settings), now); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, "auth.step_up.success", ojson.Object{{Key: "session_id", Value: sidStr},
			{Key: "authn_context_id", Value: rec.ID.String()}, {Key: "required", Value: ojson.Object{
				{Key: "acr", Value: deref(txn.RequiredTesseraACR)}}}, {Key: "presented", Value: presentedDetail}},
			audit.At(now), audit.Target("session", sidStr))
		return err
	})
	if errors.Is(err, store.ErrSessionInactive) {
		return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.failure", "session_inactive", nil)
	}
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, s.authn.Cookies.Session(issued.Secret))
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, withQuery(txn.ReturnTo, "stepup", "ok"), http.StatusFound)
	return nil, nil
}
