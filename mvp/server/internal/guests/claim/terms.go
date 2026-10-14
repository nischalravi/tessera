package claim

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Step 5 of the claim: terms and consent (guest accounts design §6.1, §7.4,
// issue #73). It is a gate on the credential step, not a step of its own: the
// session stays at "credential", the status says pending "terms" (or "consent")
// and the credential is not started, and Complete refuses to bind one, until
// everything that applies has been accepted.

// OutstandingTerms lists the documents the claimant must still accept, at the
// version in force.
func (s *Service) OutstandingTerms(tx *store.TenantTx, sess *store.ClaimSession, now time.Time) ([]terms.Requirement, error) {
	reqs, err := terms.Required(tx, sess.IdentityID, now)
	return terms.Outstanding(reqs), err
}

// ConsentPending reports whether the attribute-release consent screen applies
// to a claim through this authority and has not been answered.
func (s *Service) ConsentPending(tx *store.TenantTx, sess *store.ClaimSession, authority string) (bool, error) {
	if !terms.ConsentApplies(authority) {
		return false, nil
	}
	given, err := terms.ConsentGiven(tx, sess.IDHash)
	return !given, err
}

// AcceptTerms records the claimant's acceptance of the documents they were
// shown (id and text hash), before any credential is bound. ipHash and uaHash
// are keyed hashes (ClientHash) of the client address and user agent.
func (s *Service) AcceptTerms(tx *store.TenantTx, sess *store.ClaimSession, shown []terms.Shown, ipHash, uaHash string, now time.Time) ([]*store.TermsAcceptance, error) {
	if sess.Step != StepCredential || sess.CompletedAt != nil {
		return nil, refuse(409, "wrong_step", "this step is not open")
	}
	ctx := store.TermsContextClaim
	if IsRecovery(sess) {
		ctx = store.TermsContextRecovery
	}
	h := sess.IDHash
	return terms.Accept(tx, terms.Accepting{IdentityID: sess.IdentityID, Context: ctx, SessionHash: &h, IPHash: ipHash, UAHash: uaHash}, shown, now)
}

// RecordConsent records the attributes the claimant agreed to release.
func (s *Service) RecordConsent(tx *store.TenantTx, sess *store.ClaimSession, authority string, consented []string, now time.Time) error {
	if sess.Step != StepCredential || sess.CompletedAt != nil {
		return refuse(409, "wrong_step", "this step is not open")
	}
	if !terms.ConsentApplies(authority) {
		return refuse(409, "not_applicable", "this sign-in releases no attributes to ask about")
	}
	return terms.RecordConsent(tx, sess.IdentityID, sess.IDHash, authority, consented, now)
}

// ClientHash is a tenant-keyed hash of a client value (address, user agent) for
// the acceptance record; the value itself is never stored. "" when unkeyed.
func (s *Service) ClientHash(t tenancy.ID, kind, value string) string {
	if s == nil || s.Keyer == nil || value == "" {
		return ""
	}
	h, err := s.Keyer.MAC(t, "terms-"+kind, value)
	if err != nil {
		return ""
	}
	return h
}
