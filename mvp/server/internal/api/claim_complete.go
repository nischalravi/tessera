package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/merge"
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
	reason, result := "", "complete"
	err := s.store.InTenant(ctx, tenant.ID, func(tx *store.TenantTx) error {
		// a sign-in started by "yes, I already have an account" links; it sets up no credential
		if l, err := tx.ClaimLinkByTxn(txn.ID.String()); err == nil {
			result, reason, err = s.completeClaimLink(tx, l, conn, tok, res, now)
			return err
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
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
			// a renewal held for a step-up continues once the assurance is reached (GU-11)
			_, err = s.guests.ApplyStepups(tx, 0, now)
			return err
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
	return s.claimRedirect(w, r, result)
}

// completeClaimLink finishes a claim's sign-in as an existing person (design
// §6.5, §5.3 Tier A "link by sign-in"). When the person who signed in is one of
// the candidates the matcher found for this intake, the intake is linked to
// them: the sponsorship, affiliations and access bundle become theirs, they get
// no new credential, and the claim is complete. When they are not (or the sign-in
// does not reach the sponsorship's assurance level, or is nobody we know) nothing
// is linked and the claim goes on at the credential step as a new identity, with
// the suspicion left in the review queue. Both look the same to the claimant
// ("continue" is not an error). It returns the redirect result and, for a claim
// that cannot go on at all, the reason.
func (s *Server) completeClaimLink(tx *store.TenantTx, l *store.ClaimLink, conn *store.IdPConnection, tok *oidcrp.IDToken,
	res authnorm.Result, now time.Time) (result, reason string, err error) {
	fail := func(why string) (string, string, error) {
		if err := tx.FinishClaimLink(l.ID, store.ClaimLinkFailed, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", "", err
		}
		return "failed", why, claim.Audit(tx, now, "claim.link.failed", ojson.Object{{Key: "intake_id", Value: l.IntakeID},
			{Key: "reason", Value: why}}, store.OutcomeFailure)
	}
	sess, err := tx.ClaimSession(l.SessionIDHash)
	switch {
	case err != nil:
		return "", "", err
	case l.Status != store.ClaimLinkStarted:
		return fail("claim_link_used")
	case sess.RevokedAt != nil || sess.CompletedAt != nil || !now.Before(sess.ExpiresAt):
		return fail("claim_session_expired")
	}
	var person *store.PlatformUser
	if ext, err := tx.ExternalLoginBySubject(conn.ID, res.Subject); err == nil {
		if u, err := tx.PlatformUser(ext.UserID); err != nil {
			return "", "", err
		} else if u.Status == "active" && u.IdentityID != nil {
			person = u
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}
	linked := false
	if person != nil {
		_, aal, rerr := s.claimSvc.Requirements(tx, sess)
		if rerr != nil {
			var ce *claim.Error
			if !errors.As(rerr, &ce) {
				return "", "", rerr
			}
			return fail("claim_not_ready")
		}
		if claim.MeetsAAL(aal, res.AAL, res.TesseraACR) {
			ok, _, err := merge.LinkBySignIn(tx, sess.IntakeID, *person.IdentityID,
				merge.Actor{UserID: person.ID.String(), Display: person.DisplayName}, now)
			if err != nil {
				return "", "", err
			}
			if ok {
				if err := s.claimSvc.CompleteLinked(tx, sess, *person.IdentityID, claim.Binding{ConnectionID: conn.ID, Issuer: deref(conn.Issuer),
					Subject: res.Subject, Email: tok.Email, Name: tok.Name, AAL: res.AAL, ACR: res.TesseraACR, Authority: "existing_account"}, now); err != nil {
					return "", "", err
				}
				linked = true
			}
		}
	}
	status, outcome := store.ClaimLinkContinued, "not_a_candidate"
	if linked {
		status, outcome = store.ClaimLinkLinked, "linked"
	}
	if err := tx.FinishClaimLink(l.ID, status, now); err != nil {
		return "", "", err
	}
	result = "continue"
	if linked {
		result = "complete"
	}
	return result, "", claim.Audit(tx, now, "claim.link", ojson.Object{{Key: "intake_id", Value: l.IntakeID}, {Key: "outcome", Value: outcome},
		{Key: "aal", Value: res.AAL}, {Key: "acr", Value: res.TesseraACR}}, store.OutcomeSuccess)
}
