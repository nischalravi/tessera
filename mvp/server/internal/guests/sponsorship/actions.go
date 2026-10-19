package sponsorship

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Load returns a sponsorship, or the 404 every unknown id gets.
func Load(tx *store.TenantTx, id string) (*store.Sponsorship, error) {
	ss, err := tx.Sponsorship(strings.TrimSpace(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "sponsorship_not_found", "sponsorship not found")
	}
	return ss, err
}

func reasonOf(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" || utf8.RuneCountInString(r) > MaxReason || hasControl(r) {
		return "", refuse(422, "reason_required", "a reason of 1 to %d characters is required", MaxReason)
	}
	return r, nil
}

// reevaluate runs the sponsor policy again for a live sponsorship: as the
// sponsor-to-be (who must be eligible and within their limits, not counting
// this sponsorship), from the later of the start and now, to ends.
func (s *Service) reevaluate(tx *store.TenantTx, ss *store.Sponsorship, sponsor *store.Identity, ends, now time.Time) (Decision, error) {
	pop, ok := PopulationOf(ss.Population)
	if !ok {
		return Decision{}, refuse(500, "unknown_population", "the sponsorship has an unknown population")
	}
	gp, err := tx.GuestPopulation(pop.Group)
	if err != nil {
		return Decision{}, err
	}
	worker, ended, err := workerOf(tx, sponsor.ID)
	if err != nil {
		return Decision{}, err
	}
	live, err := tx.CountLiveSponsorships(sponsor.ID, ss.Population, ss.ID)
	if err != nil {
		return Decision{}, err
	}
	start := ss.StartsAt
	if start.Before(now) {
		start = now
	}
	return s.Policy.Evaluate(Request{Sponsor: sponsor, SponsorWorkerType: worker, SponsorEnded: ended, GuestIdentityID: ss.GuestIdentityID,
		Population: ss.Population, Starts: start, Ends: ends, Now: now, MaxDays: affiliations.MaxDurationDays(pop.AffType, gp.MaxDurationDays),
		LiveCount: live, SensitiveBundle: slices.ContainsFunc(ParseBundle(ss.AccessBundle), BundleItem.Sensitive),
		RequiredIAL: ss.RequiredIAL}), nil
}

func (s *Service) save(tx *store.TenantTx, ss *store.Sponsorship, from string, now time.Time) error {
	ss.UpdatedAt = now
	if err := tx.SaveSponsorship(ss, from); errors.Is(err, store.ErrNotFound) {
		return refuse(409, "changed", "the sponsorship changed while you were working on it; reload and try again")
	} else if err != nil {
		return err
	}
	return nil
}

// fourEyes refuses a decision by someone the sponsorship is about or whose
// request it is.
func fourEyes(ss *store.Sponsorship, by Actor) error {
	if by.Is(ss.SponsorIdentityID) || by.Is(ss.GuestIdentityID) || (ss.CreatedBy != nil && by.uid() != nil && *ss.CreatedBy == *by.uid()) {
		return refuse(403, "self_approval", "a second person approves: not the sponsor, the guest or whoever made the request")
	}
	return nil
}

// Approve approves a sponsorship waiting for a second person. The policy is
// run again (the sponsor must still be eligible and within limits); the
// sponsorship becomes active and writes the guest's affiliation and lifecycle.
func (s *Service) Approve(tx *store.TenantTx, by Actor, id string, now time.Time) (*store.Sponsorship, error) {
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case !by.Approver:
		return nil, refuse(403, "approver_required", "approving sponsorships needs the sponsorships.approve permission")
	case ss.Status != store.SponsorPendingApproval:
		return nil, refuse(409, "not_pending", "this sponsorship is not waiting for approval")
	}
	if err := fourEyes(ss, by); err != nil {
		return nil, err
	}
	sponsor, err := tx.Identity(ss.SponsorIdentityID)
	if err != nil {
		return nil, err
	}
	d, err := s.reevaluate(tx, ss, sponsor, ss.EndsAt, now)
	if err != nil {
		return nil, err
	}
	if !d.Allowed {
		return nil, refusal(d)
	}
	ss.Status, ss.PolicyVersion, ss.ApprovedBy, ss.ApprovedAt = store.SponsorActive, d.Version, by.uid(), &now
	if err := s.save(tx, ss, store.SponsorPendingApproval, now); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "approved", store.SponsorPendingApproval, by, "", now); err != nil {
		return nil, err
	}
	if err := s.activate(tx, ss, by, now); err != nil {
		return nil, err
	}
	if err := notify.SponsorshipDecided(tx, now, ss, true, derefOr(by.uid()), ""); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.approve", detail(ss, rulesKV(d)))
}

func derefOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Reject rejects a sponsorship waiting for a second person. The invited
// identity is retired unless another sponsorship still stands behind it.
func (s *Service) Reject(tx *store.TenantTx, by Actor, id, reason string, now time.Time) (*store.Sponsorship, error) {
	why, err := reasonOf(reason)
	if err != nil {
		return nil, err
	}
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case !by.Approver:
		return nil, refuse(403, "approver_required", "rejecting sponsorships needs the sponsorships.approve permission")
	case ss.Status != store.SponsorPendingApproval:
		return nil, refuse(409, "not_pending", "this sponsorship is not waiting for approval")
	}
	if err := fourEyes(ss, by); err != nil {
		return nil, err
	}
	ss.PolicyVersion = s.Policy.Version
	if err := s.finalize(tx, ss, store.SponsorRejected, "rejected", why, by, now); err != nil {
		return nil, err
	}
	if err := notify.SponsorshipDecided(tx, now, ss, false, derefOr(by.uid()), why); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.reject", detail(ss, ojson.KV{Key: "reason", Value: why}))
}

// finalize moves a sponsorship to a final status, ends its affiliation if it
// had begun and lets the guest's lifecycle follow (the last one ends the term).
func (s *Service) finalize(tx *store.TenantTx, ss *store.Sponsorship, status, ev, reason string, by Actor, now time.Time) error {
	from, wasLive := ss.Status, ss.Live()
	ss.Status, ss.EndedAt, ss.EndReason = status, &now, &reason
	ss.TransferToIdentityID, ss.TransferDeadline = nil, nil
	if err := s.save(tx, ss, from, now); err != nil {
		return err
	}
	if err := s.event(tx, ss, ev, from, by, reason, now); err != nil {
		return err
	}
	if wasLive {
		if err := affiliations.EndSponsored(tx, ss.GuestIdentityID, ss.ID, reason, derefOr(by.uid()), now); err != nil {
			return err
		}
	}
	if s.Claim != nil {
		if err := s.Claim.RevokeIfIssued(tx, ss, reason, now); err != nil {
			return err
		}
	}
	return s.syncPerson(tx, ss.GuestIdentityID, by, now, reason)
}

// Renew extends an active sponsorship to a new end date (a new term, at most
// the population's maximum from now) with a fresh justification. The policy
// is run again. Where it asks for a second approver, the sponsor cannot renew
// alone: a holder of sponsorships.approve who is not the sponsor renews it.
func (s *Service) Renew(tx *store.TenantTx, by Actor, id string, to time.Time, justification string, now time.Time) (*store.Sponsorship, error) {
	why, err := reasonOf(justification)
	if err != nil {
		return nil, refuse(422, "justification_required", "a fresh justification of 1 to %d characters is required", MaxReason)
	}
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	sponsor := by.Is(ss.SponsorIdentityID)
	switch {
	case !sponsor && !by.Approver:
		return nil, refuse(403, "not_sponsor", "only the sponsor can renew a sponsorship")
	case ss.Status != store.SponsorActive:
		return nil, refuse(409, "not_active", "only an active sponsorship can be renewed")
	case !to.After(ss.EndsAt):
		return nil, refuse(422, "not_later", "a renewal moves the end date later")
	}
	owner, err := tx.Identity(ss.SponsorIdentityID)
	if err != nil {
		return nil, err
	}
	d, err := s.reevaluate(tx, ss, owner, to.UTC(), now)
	if err != nil {
		return nil, err
	}
	switch {
	case !d.Allowed:
		return nil, refusal(d)
	case d.NeedsApproval && (sponsor || by.Is(ss.GuestIdentityID)):
		return nil, refuse(422, "renewal_needs_approval", "this sponsorship needs a second approver to renew: ask someone with sponsorships.approve")
	}
	from := ss.EndsAt
	ss.EndsAt, ss.PolicyVersion = to.UTC(), d.Version
	if err := s.save(tx, ss, store.SponsorActive, now); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "renewed", store.SponsorActive, by, why, now); err != nil {
		return nil, err
	}
	if err := affiliations.MoveSponsoredEnd(tx, ss.GuestIdentityID, ss.ID, ss.EndsAt); err != nil {
		return nil, err
	}
	if err := s.syncPerson(tx, ss.GuestIdentityID, by, now, "renewed: "+why); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.renew", detail(ss, rulesKV(d),
		ojson.KV{Key: "from_ends_at", Value: timeNote(from)}, ojson.KV{Key: "justification", Value: why}))
}

// End ends a sponsorship now. The sponsor ends it (status ended); a holder of
// sponsorships.approve who is not the sponsor revokes it; one that never
// began is revoked. A person stays active until their last sponsorship ends.
func (s *Service) End(tx *store.TenantTx, by Actor, id, reason string, now time.Time) (*store.Sponsorship, error) {
	why, err := reasonOf(reason)
	if err != nil {
		return nil, err
	}
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	sponsor := by.Is(ss.SponsorIdentityID)
	switch {
	case !sponsor && !by.Approver:
		return nil, refuse(403, "not_sponsor", "only the sponsor can end a sponsorship")
	case ss.Status != store.SponsorActive && ss.Status != store.SponsorTransferPending && ss.Status != store.SponsorPendingApproval:
		return nil, refuse(409, "already_ended", "this sponsorship is not running")
	}
	status, ev := store.SponsorEnded, "ended"
	if !sponsor || ss.Status == store.SponsorPendingApproval {
		status, ev = store.SponsorRevoked, "revoked"
	}
	ss.PolicyVersion = s.Policy.Version
	if err := s.finalize(tx, ss, status, ev, why, by, now); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.end", detail(ss, ojson.KV{Key: "reason", Value: why}))
}

// Transfer asks another eligible person to take over a sponsorship. The
// sponsorship stays with its sponsor until the target accepts, for at most the
// policy's deadline (14 days); then it ends. The target's eligibility and
// limits are checked now and again on acceptance.
func (s *Service) Transfer(tx *store.TenantTx, by Actor, id string, to int64, reason string, now time.Time) (*store.Sponsorship, error) {
	why, err := reasonOf(reason)
	if err != nil {
		return nil, err
	}
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case !by.Is(ss.SponsorIdentityID) && !by.Approver:
		return nil, refuse(403, "not_sponsor", "only the sponsor can transfer a sponsorship")
	case ss.Status != store.SponsorActive && ss.Status != store.SponsorTransferPending:
		return nil, refuse(409, "not_active", "only a running sponsorship can be transferred")
	case to == ss.SponsorIdentityID:
		return nil, refuse(422, "transfer_to_self", "the sponsorship is with this person already")
	}
	target, err := tx.Identity(to)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(422, "transfer_target_not_found", "person not found")
	} else if err != nil {
		return nil, err
	}
	d, err := s.reevaluate(tx, ss, target, ss.EndsAt, now)
	if err != nil {
		return nil, err
	}
	if !d.Allowed {
		return nil, refusal(d)
	}
	from := ss.Status
	deadline := now.AddDate(0, 0, s.Policy.TransferDeadlineDays)
	ss.Status, ss.TransferToIdentityID, ss.TransferDeadline, ss.PolicyVersion = store.SponsorTransferPending, &target.ID, &deadline, d.Version
	if err := s.save(tx, ss, from, now); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "transfer_requested", from, by, why, now); err != nil {
		return nil, err
	}
	if err := notify.SponsorshipTransferRequested(tx, now, ss); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.transfer", detail(ss, rulesKV(d),
		ojson.KV{Key: "transfer_to_identity_id", Value: target.ID}, ojson.KV{Key: "transfer_deadline", Value: timeNote(deadline)}))
}

// AcceptTransfer is the target taking over: the sponsor becomes the target
// (after a new policy check as them) and the guest's lifecycle follows.
func (s *Service) AcceptTransfer(tx *store.TenantTx, by Actor, id string, now time.Time) (*store.Sponsorship, error) {
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case ss.Status != store.SponsorTransferPending || ss.TransferToIdentityID == nil || ss.TransferDeadline == nil:
		return nil, refuse(409, "not_pending", "this sponsorship is not waiting for a new sponsor")
	case !by.Is(*ss.TransferToIdentityID):
		return nil, refuse(403, "not_transfer_target", "only the person asked to take over can accept")
	case !ss.TransferDeadline.After(now):
		return nil, refuse(409, "transfer_expired", "the deadline to accept has passed")
	}
	target, err := tx.Identity(*ss.TransferToIdentityID)
	if err != nil {
		return nil, err
	}
	d, err := s.reevaluate(tx, ss, target, ss.EndsAt, now)
	if err != nil {
		return nil, err
	}
	if !d.Allowed {
		return nil, refusal(d)
	}
	previous := ss.SponsorIdentityID
	ss.Status, ss.SponsorIdentityID, ss.PolicyVersion = store.SponsorActive, target.ID, d.Version
	ss.TransferToIdentityID, ss.TransferDeadline = nil, nil
	if err := s.save(tx, ss, store.SponsorTransferPending, now); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "transfer_accepted", store.SponsorTransferPending, by, "", now); err != nil {
		return nil, err
	}
	if err := s.syncPerson(tx, ss.GuestIdentityID, by, now, "transferred"); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.accept_transfer", detail(ss, rulesKV(d),
		ojson.KV{Key: "previous_sponsor_identity_id", Value: previous}))
}
