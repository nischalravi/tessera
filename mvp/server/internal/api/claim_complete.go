package api

import (
	"errors"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The OIDC callback's claim purpose (issue #69): the guest's sign-in at the
// credential authority comes back to the same callback as every other sign-in
// (login.go), with the login transaction's purpose "claim". Instead of creating
// a Tessera session it completes the claim: a new platform user with no roles,
// linked to the guest's identity, whose external login is the sign-in's
// (issuer, subject), and only if the sign-in is the one the authority was told
// to expect and meets the sponsorship's authenticator assurance level.

// callbackFailure refuses a callback: a claim's guest is sent back to the claim
// page, everyone else gets the sign-in error page.
func (s *Server) callbackFailure(w http.ResponseWriter, r *http.Request, txn *store.LoginTransaction, t tenancy.ID, reason string, extra ojson.Object) (any, error) {
	if txn != nil && txn.Purpose == "claim" {
		return s.claimFailure(w, r, t, txn, reason, extra)
	}
	return s.loginFailure(w, r, t, reason, extra)
}

// claimFailure audits the refused claim sign-in (never with a secret), clears
// the login cookie and sends the browser back to the claim page, which asks the
// session for its status. The claim stays at the credential step.
func (s *Server) claimFailure(w http.ResponseWriter, r *http.Request, t tenancy.ID, txn *store.LoginTransaction, reason string, extra ojson.Object) (any, error) {
	ctx := audit.SetPrincipal(r.Context(), audit.Principal{Tenant: t, Actor: store.AuditActor{Type: store.ActorAnonymous}})
	detail := append(ojson.Object{{Key: "reason", Value: reason}, {Key: "login_transaction_id", Value: txn.ID.String()}}, extra...)
	if err := s.store.InTenant(ctx, t, func(tx *store.TenantTx) error {
		return claim.Audit(tx, s.clock().UTC(), "claim.credential.failed", detail, store.OutcomeFailure)
	}); err != nil {
		return nil, err
	}
	return s.claimRedirect(w, r, "failed")
}

func (s *Server) claimRedirect(w http.ResponseWriter, r *http.Request, result string) (any, error) {
	http.SetCookie(w, s.loginCookie("", -1))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/claim?result="+result, http.StatusSeeOther)
	return nil, nil
}

// finishClaim completes the claim of the transaction's claim session.
func (s *Server) finishClaim(w http.ResponseWriter, r *http.Request, tenant store.Tenant, conn *store.IdPConnection,
	txn *store.LoginTransaction, tok *oidcrp.IDToken, res authnorm.Result) (any, error) {
	if !s.claimReady() {
		return s.claimFailure(w, r, tenant.ID, txn, "claim_unavailable", nil)
	}
	ctx := audit.SetPrincipal(r.Context(), audit.Principal{Tenant: tenant.ID, Actor: store.AuditActor{Type: store.ActorAnonymous}})
	now := s.clock().UTC()
	reason := ""
	err := s.store.InTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		sess, err := tx.ClaimSessionByLoginTxn(txn.ID.String())
		if errors.Is(err, store.ErrNotFound) {
			reason = "claim_session_unknown"
			return nil
		}
		if err != nil {
			return err
		}
		if sess.RevokedAt != nil || !now.Before(sess.ExpiresAt) {
			reason = "claim_session_expired"
			return nil
		}
		authority := ""
		if s.cfg.Credential != nil {
			authority = s.cfg.Credential.Kind()
		}
		_, err = s.claimSvc.Complete(tx, sess, claim.Binding{ConnectionID: conn.ID, Issuer: deref(conn.Issuer), Subject: res.Subject,
			Email: tok.Email, Name: tok.Name, AAL: res.AAL, ACR: res.TesseraACR, Authority: authority}, now)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, claim.ErrAAL):
			reason = "aal_not_met"
		case errors.Is(err, claim.ErrSubject):
			reason = "subject_mismatch"
		case errors.Is(err, claim.ErrSubjectBound):
			reason = "subject_already_bound"
		case errors.Is(err, claim.ErrNotReady):
			reason = "claim_not_ready"
		default:
			return err
		}
		// the refusal is recorded and committed (Complete wrote nothing before it refused)
		return claim.Audit(tx, now, "claim.credential.failed", ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
			{Key: "reason", Value: reason}, {Key: "aal", Value: res.AAL}, {Key: "acr", Value: res.TesseraACR}}, store.OutcomeFailure)
	})
	if err != nil {
		return nil, err
	}
	if reason != "" {
		s.log.Info("claim sign-in refused", "reason", reason, "request_id", audit.RequestID(r.Context()))
		return s.claimRedirect(w, r, "failed")
	}
	return s.claimRedirect(w, r, "complete")
}
