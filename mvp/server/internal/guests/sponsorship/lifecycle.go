package sponsorship

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The sponsorship side of the guest lifecycle (design §8, issue #74): a renewal
// that waits for a step-up, a sponsor's departure, and a person's return. The
// package internal/guests/lifecycle decides when; these functions change the
// sponsorship, in the caller's transaction.

// StepUpSweeper is the actor of an applied step-up renewal.
const StepUpSweeper = "guest.stepup"

// hold records a renewal that waits for the guest's identity assurance to reach
// ial. Nothing about the access changes. A newer request replaces an older one.
func (s *Service) hold(tx *store.TenantTx, ss *store.Sponsorship, by Actor, to time.Time, why string, ial int, now time.Time) (*store.Stepup, error) {
	older, err := tx.Stepups(store.StepupPending, ss.ID)
	if err != nil {
		return nil, err
	}
	for _, o := range older {
		if err := tx.ResolveStepup(o.ID, store.StepupCancelled, now); err != nil {
			return nil, err
		}
	}
	up := &store.Stepup{ID: uuid.NewString(), SponsorshipID: ss.ID, RequestedEndsAt: to, Justification: why, RequiredIAL: ial, Status: store.StepupPending,
		RequestedBy: by.uid(), CreatedAt: now}
	if err := tx.InsertStepup(up); err != nil {
		return nil, err
	}
	ss.UpdatedAt = now
	if err := s.event(tx, ss, "stepup_required", ss.Status, by, why, now); err != nil {
		return nil, err
	}
	if err := notify.GuestStepUp(tx, now, ss, ial); err != nil {
		return nil, err
	}
	return up, tx.Audit(now, by.Display, "sponsorship.renew_stepup_required", detail(ss,
		ojson.KV{Key: "requested_ends_at", Value: timeNote(to)}, ojson.KV{Key: "required_ial", Value: ial}))
}

// ApplyStepups applies the held renewals of a guest (0: everyone) whose
// identity assurance has reached what the bundle needs. A renewal that can no
// longer stand (the sponsorship ended, the requested end passed, the sponsor
// is not eligible any more) is cancelled instead. It returns how many it applied.
func (s *Service) ApplyStepups(tx *store.TenantTx, guestID int64, now time.Time) (int, error) {
	ups, err := tx.Stepups(store.StepupPending, "")
	if err != nil {
		return 0, err
	}
	by, applied := Actor{Display: StepUpSweeper}, 0
	for _, up := range ups {
		ss, err := tx.Sponsorship(up.SponsorshipID)
		if err != nil {
			return applied, err
		}
		if guestID != 0 && ss.GuestIdentityID != guestID {
			continue
		}
		cancel := func(reason string) error {
			if err := tx.ResolveStepup(up.ID, store.StepupCancelled, now); err != nil {
				return err
			}
			return tx.Audit(now, by.Display, "sponsorship.stepup_cancel", detail(ss, ojson.KV{Key: "reason", Value: reason}))
		}
		if ss.Status != store.SponsorActive || !up.RequestedEndsAt.After(ss.EndsAt) || !up.RequestedEndsAt.After(now) {
			if err := cancel("the sponsorship changed or the requested end passed"); err != nil {
				return applied, err
			}
			continue
		}
		need, have, err := s.assurance(tx, ss)
		if err != nil {
			return applied, err
		}
		if have < max(need, up.RequiredIAL) {
			continue
		}
		owner, err := tx.Identity(ss.SponsorIdentityID)
		if err != nil {
			return applied, err
		}
		d, err := s.reevaluate(tx, ss, owner, up.RequestedEndsAt, now)
		if err != nil {
			return applied, err
		}
		if !d.Allowed {
			if err := cancel("the sponsor policy no longer allows it: " + d.Code); err != nil {
				return applied, err
			}
			continue
		}
		if err := tx.ResolveStepup(up.ID, store.StepupApplied, now); err != nil {
			return applied, err
		}
		if err := s.event(tx, ss, "stepup_met", ss.Status, by, "identity assurance reached", now); err != nil {
			return applied, err
		}
		if err := s.applyRenewal(tx, ss, up.RequestedEndsAt, up.Justification, d, by, need, now); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}

// closeTasks closes a sponsorship's open lifecycle tasks of one kind.
func (s *Service) closeTasks(tx *store.TenantTx, sponsorshipID, kind, status, outcome string, by Actor, now time.Time) error {
	open, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Sponsorship: sponsorshipID, Kind: kind, Status: store.TaskOpen})
	if err != nil {
		return err
	}
	for _, t := range open {
		if err := tx.ResolveLifecycleTask(t.ID, status, outcome, "", by.uid(), now); err != nil {
			return err
		}
	}
	if kind == store.TaskRenewalRequest {
		_, err = tx.RevokeRenewalTokens(sponsorshipID)
	}
	return err
}

// TakeOver makes the signed-in person the sponsor of a running sponsorship
// whose sponsor has left (the transfer task, design §8.3). The sponsor policy
// is run again as them: they must be eligible and within their limits. The
// guest's lifecycle follows.
func (s *Service) TakeOver(tx *store.TenantTx, by Actor, id string, now time.Time) (*store.Sponsorship, error) {
	ss, err := Load(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case ss.Status != store.SponsorActive && ss.Status != store.SponsorTransferPending:
		return nil, refuse(409, "not_active", "only a running sponsorship can be taken over")
	case by.IdentityID == nil:
		return nil, refuse(422, "sponsor_identity_required", "your sign-in is not linked to a person, so you cannot sponsor guests")
	case by.Is(ss.SponsorIdentityID):
		return nil, refuse(422, "transfer_to_self", "the sponsorship is with this person already")
	}
	target, err := tx.Identity(*by.IdentityID)
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
	previous, from := ss.SponsorIdentityID, ss.Status
	ss.Status, ss.SponsorIdentityID, ss.PolicyVersion = store.SponsorActive, target.ID, d.Version
	ss.TransferToIdentityID, ss.TransferDeadline = nil, nil
	if err := s.save(tx, ss, from, now); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "transfer_accepted", from, by, "took over from the departed sponsor", now); err != nil {
		return nil, err
	}
	if err := s.syncPerson(tx, ss.GuestIdentityID, by, now, "transferred"); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.accept_transfer", detail(ss, rulesKV(d),
		ojson.KV{Key: "previous_sponsor_identity_id", Value: previous}, ojson.KV{Key: "via", Value: "sponsor_departure"}))
}

// EndForDeparture ends or suspends a sponsorship whose sponsor left and found no
// successor: the access of this sponsorship ends either way, so a sponsorship is
// never left running without a living sponsor. Suspended is kept (not final).
func (s *Service) EndForDeparture(tx *store.TenantTx, ss *store.Sponsorship, suspend bool, reason string, by Actor, now time.Time) error {
	ss.PolicyVersion = s.Policy.Version
	if !suspend {
		return s.finalize(tx, ss, store.SponsorEnded, "ended", reason, by, now)
	}
	from, wasLive := ss.Status, ss.Live()
	ss.Status, ss.TransferToIdentityID, ss.TransferDeadline = store.SponsorSuspended, nil, nil
	if err := s.save(tx, ss, from, now); err != nil {
		return err
	}
	if err := s.event(tx, ss, "suspended", from, by, reason, now); err != nil {
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
	if err := access.End(tx, ss, by.Display, now); err != nil {
		return err
	}
	return s.syncPerson(tx, ss.GuestIdentityID, by, now, reason)
}

// Return revives a person who comes back within the retention period: they were
// terminated or deprovisioned, nothing was purged. They become active again on
// the same identity (the caller then adds the new sponsorship), their stage row
// reads "returned" and the event is audited. A purged person is not revived.
func Return(tx *store.TenantTx, guest *store.Identity, by Actor, now time.Time) error {
	if guest.Status != "terminated" && guest.Status != store.StageDeprovisioned {
		return nil
	}
	if err := tx.ReviveIdentity(guest.ID); err != nil {
		return err
	}
	for _, from := range []string{store.StageGrace, store.StageDeprovisioned} {
		if err := tx.AdvanceDeprovisioning(guest.ID, from, store.StageReturned, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return tx.Audit(now, by.Display, "guest.return", ojson.Object{{Key: "identity_id", Value: guest.ID},
		{Key: "from_status", Value: guest.Status}})
}
