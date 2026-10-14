package guestlife

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RenewalLinkPath is the page of the guest's "request renewal" link; the token
// follows in the fragment, so it is never sent to a server in a URL.
const RenewalLinkPath = "/renew#t="

// bucket is the reminder threshold a sponsorship with left days to go is in:
// the smallest threshold not yet passed (0 when it is beyond all of them).
func bucket(thresholds []int, left int) int {
	best := 0
	for _, t := range thresholds {
		if left <= t && (best == 0 || t < best) {
			best = t
		}
	}
	return best
}

// RemindResult counts the reminders sent.
type RemindResult struct{ Sponsor, Guest int }

// Remind sends the reminders due now: to the sponsor at each threshold before a
// sponsorship ends (30, 14 and 3 days by default) and to the guest at the guest
// threshold (14) with a one-time "request renewal" link. Each (sponsorship, end
// date, audience, threshold) is sent once, however often this runs and across
// restarts: the record is written before the message, in the same transaction.
// A renewal moves the end date and so arms the reminders again.
func (s *Service) Remind(tx *store.TenantTx, now time.Time) (RemindResult, error) {
	var res RemindResult
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return res, err
	}
	window := set.GuestReminderDays
	for _, d := range set.SponsorReminderDays {
		window = max(window, d)
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorActive})
	if err != nil {
		return res, err
	}
	for _, ss := range sps {
		if ss.StartsAt.After(now) || !ss.EndsAt.After(now) {
			continue
		}
		left := daysLeft(ss.EndsAt, now)
		if left > window {
			continue
		}
		if t := bucket(set.SponsorReminderDays, left); t > 0 {
			sent, err := tx.MarkReminder(ss.ID, ss.EndsAt, store.AudienceSponsor, t, now)
			if err != nil {
				return res, err
			}
			if sent {
				if err := notify.SponsorshipEndingSponsor(tx, now, ss, t); err != nil {
					return res, err
				}
				if err := tx.Audit(now, Sweeper, "guestlife.reminder", reminderDetail(ss, store.AudienceSponsor, t, left)); err != nil {
					return res, err
				}
				res.Sponsor++
			}
		}
		if set.GuestReminderDays > 0 && left <= set.GuestReminderDays {
			sent, err := s.remindGuest(tx, ss, set.GuestReminderDays, left, now)
			if err != nil {
				return res, err
			}
			if sent {
				res.Guest++
			}
		}
	}
	return res, nil
}

func reminderDetail(ss *store.Sponsorship, audience string, threshold, left int) ojson.Object {
	return ojson.Object{kv("sponsorship_id", ss.ID), kv("guest_identity_id", ss.GuestIdentityID), kv("audience", audience),
		kv("threshold_days", threshold), kv("days_left", left), kv("ends_at", iso(ss.EndsAt))}
}

// remindGuest sends the guest's reminder with a fresh renewal link. The guest
// must have claimed their account (be active) and have an address, and the
// service must be able to hand the link over; otherwise nothing is recorded and
// a later run tries again.
func (s *Service) remindGuest(tx *store.TenantTx, ss *store.Sponsorship, threshold, left int, now time.Time) (bool, error) {
	if s.Secrets == nil || s.BaseURL == "" {
		return false, nil
	}
	guest, err := tx.Identity(ss.GuestIdentityID)
	if err != nil {
		return false, err
	}
	email := ""
	if guest.Email != nil {
		email = strings.TrimSpace(*guest.Email)
	}
	if guest.Status != "active" || email == "" {
		return false, nil
	}
	fresh, err := tx.MarkReminder(ss.ID, ss.EndsAt, store.AudienceGuest, threshold, now)
	if err != nil || !fresh {
		return false, err
	}
	token := claim.NewToken()
	if err := tx.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: ss.ID, GuestIdentityID: guest.ID,
		TokenHash: claim.HashToken(tx.Tenant(), token), ExpiresAt: ss.EndsAt, CreatedAt: now}); err != nil {
		return false, err
	}
	nid, err := notify.GuestRenewalReminder(tx, now, ss, guest.Name, email, s.tenantName(tx), threshold)
	if err != nil {
		return false, err
	}
	if nid != "" {
		// the link goes to the dispatcher through memory only
		s.Secrets.Put(nid, "Ask for a renewal (works once):\n"+strings.TrimRight(s.BaseURL, "/")+RenewalLinkPath+token, ss.EndsAt)
	}
	return true, tx.Audit(now, Sweeper, "guestlife.reminder", reminderDetail(ss, store.AudienceGuest, threshold, left))
}

// RequestRenewal is the guest's "request renewal" link: the token is spent once
// and an Inbox task opens for the sponsor. It says nothing about why a token
// did nothing (unknown, spent, expired, a sponsorship that is over): the
// caller's answer is the same.
func (s *Service) RequestRenewal(tx *store.TenantTx, token string, now time.Time) error {
	if !claim.WellFormed(token) {
		return nil
	}
	rt, err := tx.ConsumeRenewalToken(claim.HashToken(tx.Tenant(), token), now)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	ss, err := tx.Sponsorship(rt.SponsorshipID)
	if err != nil {
		return err
	}
	if ss.Status != store.SponsorActive || !ss.EndsAt.After(now) {
		return nil
	}
	if open, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Sponsorship: ss.ID, Kind: store.TaskRenewalRequest, Status: store.TaskOpen}); err != nil || len(open) > 0 {
		return err
	}
	t := &store.LifecycleTask{ID: uuid.NewString(), Kind: store.TaskRenewalRequest, SponsorshipID: ss.ID, SubjectIdentityID: ss.GuestIdentityID,
		Trigger: store.TaskTriggerGuest, CreatedAt: now}
	if err := tx.InsertLifecycleTask(t); err != nil {
		return err
	}
	sponsor, err := tx.Identity(ss.SponsorIdentityID)
	if err != nil {
		return err
	}
	to, err := notify.Identity(tx, ss.SponsorIdentityID)
	if err != nil {
		return err
	}
	if sponsor.Status != "active" { // nobody to ask: the sponsor admins decide
		if to, err = notify.GuestTaskRecipients(tx, now, sponsor.ManagerID); err != nil {
			return err
		}
	}
	guest, err := tx.Identity(ss.GuestIdentityID)
	if err != nil {
		return err
	}
	if err := notify.GuestTaskOpened(tx, now, t.ID, "Renewal requested by "+guest.Name,
		guest.Name+" asked for their "+ss.Population+" access to be renewed; it ends on "+iso(ss.EndsAt)+". Renew the sponsorship or leave it to end.", nil, to...); err != nil {
		return err
	}
	return tx.Audit(now, "guest", "guestlife.renewal_requested", ojson.Object{kv("task_id", t.ID), kv("sponsorship_id", ss.ID),
		kv("guest_identity_id", ss.GuestIdentityID)})
}
