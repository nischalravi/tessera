package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// WS-Federation passive sign-in (issue #153, legacy ADFS):
//
//	GET  /api/auth/login?tenant=&connection=<wsfed>  302 to the passive endpoint (wsignin1.0, wctx = state)
//	POST /api/auth/wsfed/{connection_id}/callback    wa, wresult, wctx (the wreply URL)
//
// The realm (wtrealm, the token's audience) is /api/auth/wsfed/{connection_id}.
// WS-Federation has no request ID: the transaction is found by the login
// cookie and bound by wctx (its state, compared as a hash); the token is
// validated by samlsp.ValidateWSFed and finished like a SAML assertion
// (freshness, replay_cache, subject, normalization). The cross-site POST is
// re-posted from Tessera's origin as for SAML. Step-up sends wfresh=0 and
// wauth (the requested class ref).

// maxWSFedBody caps the callback POST: a 256 KiB token, form-encoded.
const maxWSFedBody = 3 * samlsp.MaxResponseBytes

func (s *Server) registerWSFedRoutes() {
	s.handle(http.MethodPost, "/api/auth/wsfed/{connection_id}/callback", noTenant, publicRoute, s.wsfedCallback)
}

// WSFedRealm is a WS-Federation connection's realm (wtrealm and audience).
func WSFedRealm(publicURL string, conn uuid.UUID) string {
	return strings.TrimRight(publicURL, "/") + "/api/auth/wsfed/" + conn.String()
}

// WSFedReply is its wreply URL.
func WSFedReply(publicURL string, conn uuid.UUID) string {
	return WSFedRealm(publicURL, conn) + "/callback"
}

func (s *Server) startWSFedLogin(w http.ResponseWriter, r *http.Request, t store.Tenant, c *store.IdPConnection, ls loginStart) (any, error) {
	now := s.clock().UTC()
	cookie, state := seal.RandomSecret(32), seal.RandomSecret(32)
	stateHash := seal.SHA256Hex([]byte(state))
	maxAge := loginMaxAge
	if ls.purpose == "step_up" {
		maxAge = ls.maxAge
	}
	acr := ls.acr
	req, _ := requestedAuthn(c, acr)
	wauth := ""
	if len(req.ClassRefs) > 0 {
		wauth = req.ClassRefs[0] // WS-Federation names one method
	}
	signin, err := samlsp.WSFedLoginURL(deref(c.IdPSSOURL), WSFedRealm(s.cfg.PublicURL, c.ID), WSFedReply(s.cfg.PublicURL, c.ID),
		state, ls.purpose == "step_up", wauth)
	if err != nil {
		s.log.Warn("WS-Federation connection unusable", "connection_id", c.ID, "err", err)
		return s.loginFailure(w, r, t.ID, samlsp.ReasonOf(err), ojson.Object{{Key: "connection_id", Value: c.ID.String()}})
	}
	txn := &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: c.ID,
		Purpose: ls.purpose, StateHash: &stateHash, RequiredTesseraACR: &acr, MaxAge: &maxAge,
		BootstrapInvitationID: ls.invitation, SessionID: ls.session, ExpectedExternalLoginID: ls.expectedLogin,
		ReturnTo: ls.returnTo, CreatedAt: now, ExpiresAt: now.Add(loginTxnTTL)}
	if err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		_, err := audit.Record(r.Context(), tx, "auth.login.start", ojson.Object{{Key: "via", Value: "wsfed"},
			{Key: "purpose", Value: ls.purpose}, {Key: "connection_id", Value: c.ID.String()},
			{Key: "login_transaction_id", Value: txn.ID.String()}, {Key: "required_acr", Value: acr}},
			audit.At(now), audit.Target("login_transaction", txn.ID.String()))
		return err
	}); err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, signin, http.StatusFound)
	return nil, nil
}

// wsfedCallback is POST /api/auth/wsfed/{connection_id}/callback.
func (s *Server) wsfedCallback(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxWSFedBody)
	if err := r.ParseForm(); err != nil {
		reason := samlsp.ReasonMalformed
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			reason = samlsp.ReasonTooLarge
		}
		return s.loginFailure(w, r, tenancy.ID{}, reason, nil)
	}
	f := r.PostForm
	wresult, wctx := f.Get("wresult"), f.Get("wctx")
	tenant, txnID, reason, err := s.loginTxnFromCookie(r)
	if err != nil {
		return nil, err
	}
	if reason == "login_cookie_missing" && f.Get("bounce") == "" && wresult != "" {
		id, err := uuid.Parse(p.path["connection_id"])
		if err != nil {
			return nil, errStatus(http.StatusNotFound, "Not Found")
		}
		return s.formBounce(w, WSFedReply(s.cfg.PublicURL, id), [][2]string{{"wa", f.Get("wa")}, {"wresult", wresult}, {"wctx", wctx}})
	}
	if reason != "" {
		return s.loginFailure(w, r, tenancy.ID{}, reason, nil)
	}
	tid := tenant.ID
	var txn *store.LoginTransaction
	var conn *store.IdPConnection
	now := s.clock().UTC()
	if err := s.store.InTenant(ctx, tid, func(tx *store.TenantTx) error {
		var err error
		if txn, err = tx.LoginTransaction(txnID); err != nil {
			return err
		}
		switch {
		case txn.IdPConnectionID.String() != p.path["connection_id"]:
			reason = "connection_mismatch"
		case txn.StateHash == nil || subtle.ConstantTimeCompare([]byte(*txn.StateHash), []byte(seal.SHA256Hex([]byte(wctx)))) != 1:
			reason = "wctx_mismatch"
		case f.Get("wa") != "wsignin1.0":
			reason = "wsfed_action_unsupported"
		}
		if reason != "" {
			return nil
		}
		if err := tx.ConsumeLoginTransaction(txn.ID, now); errors.Is(err, store.ErrNotFound) {
			reason = "login_transaction_expired_or_used"
			return nil
		} else if err != nil {
			return err
		}
		conn, err = tx.IdPConnection(txn.IdPConnectionID)
		if err == nil && (conn.Status != "active" || conn.Protocol != "wsfed") {
			reason = "connection_disabled"
		}
		return err
	}); err != nil {
		return nil, err
	}
	stepUp := txn != nil && txn.Purpose == "step_up"
	fail := func(reason string, extra ojson.Object) (any, error) {
		if stepUp && reason != "connection_mismatch" && reason != "wctx_mismatch" && reason != "wsfed_action_unsupported" {
			return s.stepUpFailure(w, r, tid, txn, "auth.step_up.failure", reason, extra)
		}
		return s.loginFailure(w, r, tid, reason, append(ojson.Object{{Key: "login_transaction_id", Value: txnID.String()}}, extra...))
	}
	if reason != "" {
		return fail(reason, nil)
	}
	sc, err := s.samlConnection(tid, conn, false)
	if err != nil {
		s.log.Warn("WS-Federation connection unusable", "connection_id", conn.ID, "err", err)
		return fail(samlsp.ReasonConfig, nil)
	}
	a, err := samlsp.ValidateWSFed(sc, wresult, samlsp.WSFedExpect{Realm: WSFedRealm(s.cfg.PublicURL, conn.ID),
		Reply: WSFedReply(s.cfg.PublicURL, conn.ID), Now: now})
	if err != nil {
		s.log.Info("WS-Federation token refused", "err", err, "request_id", audit.RequestID(ctx))
		return fail(samlsp.ReasonOf(err), nil)
	}
	return s.finishAssertion(w, r, tenant, conn, txn, sc.IdPEntityID, a, fail)
}
