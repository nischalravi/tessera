package guestlife

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Task actions.
const (
	ActionAccept  = "accept"  // sponsor_transfer: take the sponsorship over
	ActionDecline = "decline" // sponsor_transfer, dual_status: end (or suspend) the sponsorship
	ActionKeep    = "keep"    // sponsor_transfer after a move: the sponsor stays the sponsor
	ActionConfirm = "confirm" // dual_status: the contractor stays on next to the employment
	ActionDismiss = "dismiss" // renewal_request: leave it to end
)

// Departed opens a transfer task for each running sponsorship of a sponsor who
// left, moved or stopped being eligible (design §8.3): the sponsor's manager
// and the sponsor admins (holders of sponsorships.approve) are asked to take it
// over before the deadline (14 days by default, never later than the
// sponsorship's own end). It returns how many tasks it opened; a sponsorship
// with an open task is left as it is.
func (s *Service) Departed(tx *store.TenantTx, sponsorID int64, trigger string, now time.Time) (int, error) {
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return 0, err
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Sponsor: sponsorID, Status: store.SponsorActive})
	if err != nil || len(sps) == 0 {
		return 0, err
	}
	sponsor, err := tx.Identity(sponsorID)
	if err != nil {
		return 0, err
	}
	to, err := notify.GuestTaskRecipients(tx, now, sponsor.ManagerID)
	if err != nil {
		return 0, err
	}
	opened := 0
	for _, ss := range sps {
		if open, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Sponsorship: ss.ID, Kind: store.TaskSponsorTransfer, Status: store.TaskOpen}); err != nil {
			return opened, err
		} else if len(open) > 0 {
			continue
		}
		deadline := now.AddDate(0, 0, set.TransferDeadlineDays)
		if ss.EndsAt.Before(deadline) {
			deadline = ss.EndsAt
		}
		t := &store.LifecycleTask{ID: uuid.NewString(), Kind: store.TaskSponsorTransfer, SponsorshipID: ss.ID, SubjectIdentityID: sponsorID,
			Trigger: trigger, Deadline: &deadline, CreatedAt: now}
		if err := tx.InsertLifecycleTask(t); err != nil {
			return opened, err
		}
		guest, err := tx.Identity(ss.GuestIdentityID)
		if err != nil {
			return opened, err
		}
		if err := notify.GuestTaskOpened(tx, now, t.ID, "Take over sponsoring "+guest.Name+"?",
			sponsor.Name+" ("+trigger+") sponsors "+guest.Name+" as a "+ss.Population+" until "+iso(ss.EndsAt)+". Someone eligible must take over, or the sponsorship "+
				map[string]string{"end": "ends", "suspend": "is suspended"}[set.OnSponsorDeparture]+" at the deadline.", &deadline, to...); err != nil {
			return opened, err
		}
		if err := tx.Audit(now, Sweeper, "guestlife.transfer_task.open", ojson.Object{kv("task_id", t.ID), kv("sponsorship_id", ss.ID),
			kv("sponsor_identity_id", sponsorID), kv("trigger", trigger), kv("deadline", iso(deadline))}); err != nil {
			return opened, err
		}
		opened++
	}
	return opened, nil
}

// OnEvent is what a JML event for a person sets in motion: a leaver or a mover
// who sponsors guests puts each of their sponsorships up for transfer. The
// caller runs it in the transaction that executed the event.
func (s *Service) OnEvent(tx *store.TenantTx, eventType string, identityID int64, now time.Time) (int, error) {
	switch eventType {
	case "leaver":
		return s.Departed(tx, identityID, store.TaskTriggerLeaver, now)
	case "mover":
		return s.Departed(tx, identityID, store.TaskTriggerMover, now)
	}
	return 0, nil
}

// ScanDepartures finds sponsors who no longer qualify (their term ended, they
// were terminated, or they lost eligibility under the sponsor policy) and opens
// the transfer tasks the event hook may have missed.
func (s *Service) ScanDepartures(tx *store.TenantTx, now time.Time) (int, error) {
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorActive})
	if err != nil {
		return 0, err
	}
	seen, opened := map[int64]bool{}, 0
	for _, ss := range sps {
		if seen[ss.SponsorIdentityID] {
			continue
		}
		seen[ss.SponsorIdentityID] = true
		ok, err := s.Sponsors.CanSponsor(tx, ss.SponsorIdentityID)
		if err != nil {
			return opened, err
		}
		if ok {
			continue
		}
		sponsor, err := tx.Identity(ss.SponsorIdentityID)
		if err != nil {
			return opened, err
		}
		trigger := store.TaskTriggerIneligible
		if sponsor.Status != "active" {
			trigger = store.TaskTriggerLeaver
		}
		n, err := s.Departed(tx, ss.SponsorIdentityID, trigger, now)
		if err != nil {
			return opened, err
		}
		opened += n
	}
	return opened, nil
}

// mayAct reports whether the actor may decide a task: sponsor admins, the
// manager of the person who left (transfer), the sponsor (renewals, dual status).
func mayAct(tx *store.TenantTx, by Actor, t *store.LifecycleTask, ss *store.Sponsorship) (bool, error) {
	if by.IdentityID != nil && *by.IdentityID == t.SubjectIdentityID {
		return false, nil // nobody, an approver included, decides a task about themselves (#446)
	}
	if by.Approver && by.UserID != uuid.Nil && by.IdentityID == nil {
		return false, nil // an unlinked approver is refused with actor_unlinked (#449)
	}
	if by.Approver {
		return true, nil
	}
	if by.IdentityID == nil {
		return false, nil
	}
	switch t.Kind {
	case store.TaskSponsorTransfer:
		subject, err := tx.Identity(t.SubjectIdentityID)
		if err != nil {
			return false, err
		}
		return subject.ManagerID != nil && *subject.ManagerID == *by.IdentityID, nil
	default:
		return *by.IdentityID == ss.SponsorIdentityID, nil
	}
}

// MayAct is mayAct for the API's views.
func MayAct(tx *store.TenantTx, by Actor, t *store.LifecycleTask) (bool, error) {
	ss, err := tx.Sponsorship(t.SponsorshipID)
	if err != nil {
		return false, err
	}
	return mayAct(tx, by, t, ss)
}

// Resolve applies a decision on an open task, with the authorization checked
// here (the server decides, the page only offers): accept takes the
// sponsorship over under a fresh policy check; decline ends or suspends it
// (the tenant's setting) or, for a dual-status task, ends the contractor
// sponsorship; keep leaves a moved sponsor in place; confirm keeps a
// converted contractor's sponsorship; dismiss drops a renewal request.
func (s *Service) Resolve(tx *store.TenantTx, by Actor, taskID, action string, now time.Time) (*store.LifecycleTask, error) {
	t, err := tx.LifecycleTask(taskID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "task_not_found", "task not found")
	} else if err != nil {
		return nil, err
	}
	ss, err := tx.Sponsorship(t.SponsorshipID)
	if err != nil {
		return nil, err
	}
	if by.IdentityID != nil && *by.IdentityID == t.SubjectIdentityID {
		return nil, refuse(403, "self_decision", "you cannot decide a task about yourself")
	}
	if by.Approver && by.UserID != uuid.Nil && by.IdentityID == nil {
		return nil, refuse(403, "actor_unlinked", "your account is not linked to an identity, so it cannot decide tasks; ask an administrator to link it")
	}
	if ok, err := mayAct(tx, by, t, ss); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(404, "task_not_found", "task not found") // one that is not yours looks missing
	}
	if t.Status != store.TaskOpen {
		return nil, refuse(409, "not_open", "this task is already closed")
	}
	allowed := map[string][]string{store.TaskSponsorTransfer: {ActionAccept, ActionDecline, ActionKeep},
		store.TaskDualStatus: {ActionConfirm, ActionDecline}, store.TaskRenewalRequest: {ActionDismiss}}
	if !contains(allowed[t.Kind], action) {
		return nil, refuse(422, "invalid_action", "a %s task takes %v", t.Kind, allowed[t.Kind])
	}
	if !ss.Live() {
		if err := tx.ResolveLifecycleTask(t.ID, store.TaskCancelled, store.OutcomeDismissed, "the sponsorship is over", by.UserPtr(), now); err != nil {
			return nil, err
		}
		return nil, refuse(409, "not_open", "the sponsorship is over; the task is closed")
	}
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return nil, err
	}
	status, outcome := store.TaskDone, ""
	switch {
	case t.Kind == store.TaskSponsorTransfer && action == ActionAccept:
		if _, err := s.Sponsors.TakeOver(tx, by, ss.ID, now); err != nil {
			return nil, err
		}
		outcome = store.OutcomeTransferred
	case t.Kind == store.TaskSponsorTransfer && action == ActionKeep:
		if t.Trigger != store.TaskTriggerMover {
			return nil, refuse(422, "invalid_action", "only a sponsor who moved can stay the sponsor")
		}
		if ok, err := s.Sponsors.CanSponsor(tx, ss.SponsorIdentityID); err != nil {
			return nil, err
		} else if !ok {
			return nil, refuse(422, "sponsor_not_eligible", "the sponsor is not eligible any more; someone else must take over")
		}
		outcome = store.OutcomeConfirmed
	case t.Kind == store.TaskSponsorTransfer: // decline
		status, outcome = store.TaskDeclined, outcomeFor(set)
		if err := s.Sponsors.EndForDeparture(tx, ss, set.OnSponsorDeparture == "suspend", "sponsor left and the transfer was declined", by, now); err != nil {
			return nil, err
		}
	case action == ActionConfirm:
		outcome = store.OutcomeConfirmed
		if err := conversionEvent(tx, ss, "dual status confirmed by the sponsor", by.Display, now); err != nil {
			return nil, err
		}
	case t.Kind == store.TaskDualStatus: // decline
		status, outcome = store.TaskDeclined, store.OutcomeEnded
		if err := s.Sponsors.EndForDeparture(tx, ss, false, "converted to employee: the contractor sponsorship ends", by, now); err != nil {
			return nil, err
		}
	default: // dismiss a renewal request
		status, outcome = store.TaskDeclined, store.OutcomeDismissed
	}
	if err := tx.ResolveLifecycleTask(t.ID, status, outcome, "", by.UserPtr(), now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by.Display, "guestlife.task."+action, ojson.Object{kv("task_id", t.ID), kv("kind", t.Kind),
		kv("sponsorship_id", ss.ID), kv("outcome", outcome)}); err != nil {
		return nil, err
	}
	return tx.LifecycleTask(t.ID)
}

func outcomeFor(set store.GuestLifecycleSettings) string {
	if set.OnSponsorDeparture == "suspend" {
		return store.OutcomeSuspended
	}
	return store.OutcomeEnded
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ExpireTasks closes the tasks that can no longer be decided: one whose
// sponsorship is over is cancelled; a transfer task past its deadline ends (or
// suspends) the sponsorship, so it never runs on without a living sponsor; a
// dual-status task past its deadline ends the contractor sponsorship. It returns
// how many sponsorships it ended or suspended.
func (s *Service) ExpireTasks(tx *store.TenantTx, now time.Time) (ended int, err error) {
	open, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Status: store.TaskOpen})
	if err != nil {
		return 0, err
	}
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return 0, err
	}
	by := sweeper()
	for _, t := range open {
		ss, err := tx.Sponsorship(t.SponsorshipID)
		if err != nil {
			return ended, err
		}
		switch {
		case !ss.Live():
			if err := tx.ResolveLifecycleTask(t.ID, store.TaskCancelled, store.OutcomeDismissed, "the sponsorship is over", nil, now); err != nil {
				return ended, err
			}
		case t.Deadline == nil || t.Deadline.After(now):
		case t.Kind == store.TaskSponsorTransfer:
			if err := s.Sponsors.EndForDeparture(tx, ss, set.OnSponsorDeparture == "suspend", "sponsor left and the transfer deadline passed", by, now); err != nil {
				return ended, err
			}
			if err := tx.ResolveLifecycleTask(t.ID, store.TaskExpired, outcomeFor(set), "", nil, now); err != nil {
				return ended, err
			}
			if err := tx.Audit(now, Sweeper, "guestlife.transfer_task.expire", ojson.Object{kv("task_id", t.ID), kv("sponsorship_id", ss.ID),
				kv("outcome", outcomeFor(set))}); err != nil {
				return ended, err
			}
			ended++
		case t.Kind == store.TaskDualStatus:
			if err := s.Sponsors.EndForDeparture(tx, ss, false, "converted to employee: dual status was not confirmed", by, now); err != nil {
				return ended, err
			}
			if err := tx.ResolveLifecycleTask(t.ID, store.TaskExpired, store.OutcomeEnded, "", nil, now); err != nil {
				return ended, err
			}
			if err := tx.Audit(now, Sweeper, "guestlife.dual_status.expire", ojson.Object{kv("task_id", t.ID), kv("sponsorship_id", ss.ID)}); err != nil {
				return ended, err
			}
			ended++
		}
	}
	return ended, nil
}
