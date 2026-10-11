package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/casclient"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// CAS 3.0 sign-in (issue #152):
//
//	GET /api/auth/login?tenant=&connection=<cas>  302 to {cas}/login?service=<callback?state=>
//	GET /api/auth/cas/{connection_id}/callback?state=&ticket=
//
// CAS round-trips only the service URL, so the transaction's state rides
// inside it and the service is rebuilt exactly from the callback's state
// for validation. The callback shares the OIDC callback's transaction checks,
// then validates the ticket (casclient), uses each ticket once
// (replay_cache), and requires authenticationDate (auth_time; max_age at
// sign-in). A step-up asks CAS for renew=true, validates with renew=true and
// requires a new login after the step-up started.

// casTicketTTL is how long a validated ticket is remembered (CAS tickets
// live seconds; this outlasts any server's setting).
const casTicketTTL = 10 * time.Minute

func (s *Server) registerCASRoutes() {
	s.handle(http.MethodGet, "/api/auth/cas/{connection_id}/callback", noTenant, publicRoute, s.oidcCallback)
}

// casService is the service URL for a transaction's state.
func (s *Server) casService(conn uuid.UUID, state string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/api/auth/cas/" + conn.String() + "/callback?" +
		url.Values{"state": {state}}.Encode()
}

// startCASLogin creates the transaction and redirects to the CAS server.
func (s *Server) startCASLogin(w http.ResponseWriter, r *http.Request, t store.Tenant, c *store.IdPConnection, ls loginStart) (any, error) {
	if s.cas == nil {
		return nil, errors.New("api: CAS sign-in is not configured (no outbound HTTP client)")
	}
	now := s.clock().UTC()
	cookie, state := seal.RandomSecret(32), seal.RandomSecret(32)
	stateHash := seal.SHA256Hex([]byte(state))
	maxAge := loginMaxAge
	if ls.purpose == "step_up" {
		maxAge = ls.maxAge
	}
	acr := ls.acr
	txn := &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: c.ID,
		Purpose: ls.purpose, StateHash: &stateHash, RequiredTesseraACR: &acr, MaxAge: &maxAge,
		BootstrapInvitationID: ls.invitation, SessionID: ls.session, ExpectedExternalLoginID: ls.expectedLogin,
		ReturnTo: ls.returnTo, CreatedAt: now, ExpiresAt: now.Add(loginTxnTTL)}
	loginURL, err := casclient.LoginURL(deref(c.Issuer), s.casService(c.ID, state), ls.purpose == "step_up")
	if err != nil {
		s.log.Warn("CAS connection unusable", "connection_id", c.ID, "err", err)
		return s.loginFailure(w, r, t.ID, casclient.ReasonOf(err), ojson.Object{{Key: "connection_id", Value: c.ID.String()}})
	}
	if err := s.store.InTenant(r.Context(), t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		_, err := audit.Record(r.Context(), tx, "auth.login.start", ojson.Object{{Key: "via", Value: "cas"},
			{Key: "purpose", Value: ls.purpose}, {Key: "connection_id", Value: c.ID.String()},
			{Key: "login_transaction_id", Value: txn.ID.String()}, {Key: "required_acr", Value: acr}},
			audit.At(now), audit.Target("login_transaction", txn.ID.String()))
		return err
	}); err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil, nil
}

// finishCASCallback runs after the shared transaction checks.
func (s *Server) finishCASCallback(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction) (any, error) {
	ctx := r.Context()
	q := r.URL.Query()
	now := s.clock().UTC()
	stepUp := txn.Purpose == "step_up"
	fail := func(reason string) (any, error) {
		if stepUp {
			return s.stepUpFailure(w, r, tenant.ID, txn, "auth.step_up.failure", reason, nil)
		}
		return s.loginFailure(w, r, tenant.ID, reason, ojson.Object{{Key: "login_transaction_id", Value: txn.ID.String()}})
	}
	server := deref(conn.Issuer)
	ticket := q.Get("ticket")
	t, err := s.cas.Validate(ctx, server, s.casService(conn.ID, q.Get("state")), ticket, stepUp)
	if err != nil {
		s.log.Info("CAS ticket refused", "err", err, "request_id", audit.RequestID(ctx))
		return fail(casclient.ReasonOf(err))
	}
	// a ticket is single use at the CAS server; also here, in case the
	// server is wrong about it
	if err := s.store.InSystem(ctx, "cas replay cache", func(st *store.SystemTx) error {
		return st.UseOnce(store.ReplayCASTicket, seal.SHA256Hex([]byte(server+"\x00"+ticket)), now, now.Add(casTicketTTL))
	}); errors.Is(err, store.ErrDuplicate) {
		return fail("cas_ticket_replay")
	} else if err != nil {
		return nil, err
	}
	at := t.AuthenticationDate
	switch {
	case at.IsZero():
		return fail(oidcrp.ReasonAuthTimeMissing) // the server must release authenticationDate
	case at.After(now.Add(oidcrp.IatSkew)):
		return fail(oidcrp.ReasonAuthTimeStale)
	case stepUp && (at.Before(txn.CreatedAt.Add(-oidcrp.StepUpSkew)) || (t.NewLogin != nil && !*t.NewLogin)):
		return fail(oidcrp.ReasonAuthTimeStale) // renew=true is only a request: the login must be new
	case !stepUp && txn.MaxAge != nil && now.Sub(at) > time.Duration(*txn.MaxAge)*time.Second+oidcrp.AuthTimeSkew:
		return fail(oidcrp.ReasonAuthTimeStale)
	}
	subject := t.User
	if name, ok := strings.CutPrefix(conn.SubjectSource, "attribute:"); ok {
		v := t.Attributes[name]
		if len(v) != 1 || v[0] == "" || len(v[0]) > 255 {
			return fail(casclient.ReasonUser)
		}
		subject = v[0]
	} else if conn.SubjectSource != "" && conn.SubjectSource != "cas_user" && conn.SubjectSource != "nameid_persistent" {
		return fail(casclient.ReasonUser)
	}
	mapping, err := authnorm.ParseMapping(conn.AuthnMapping)
	if err != nil {
		return nil, err
	}
	res, err := authnorm.Normalize(authnorm.Connection{Profile: conn.Profile, Mapping: mapping,
		AssumePhishingResistant: conn.AssumePhishingResistant}, authnorm.Requested{},
		authnorm.Claims{Subject: subject, Attributes: t.Attributes, AuthTime: &at, Raw: t.Raw})
	if err != nil {
		return fail("normalization_failed")
	}
	if stepUp {
		return s.finishStepUp(w, r, tenant, conn, txn, res)
	}
	return s.finishLogin(w, r, tenant, conn, txn, attributeProfile(conn, t.Attributes, "memberOf"), res)
}
