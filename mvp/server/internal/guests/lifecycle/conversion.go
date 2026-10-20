package guestlife

import (
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Conversion without losing history (design §8.4): when the HR system gives a
// person an employee affiliation, their guest or contractor sponsorships stop
// being the basis of their standing. Everything stays on the one identity; the
// employee affiliation is already what the HR record started. By default the
// sponsorship ends at the hire date; with conversion_dual_status =
// sponsor_confirms the sponsor is asked first, and the sponsorship ends at the
// deadline unless they confirm. The applicant, admit and pre-hire conversions
// need the SIS and HRIS intake (GU-4) and are not built.

// hiredFrom is the running affiliation from the HR or student system that makes
// the person an employee or student, nil when there is none.
func hiredFrom(tx *store.TenantTx, guestID int64, now time.Time) (*store.Affiliation, error) {
	affs, err := tx.AffiliationsFor(guestID)
	if err != nil {
		return nil, err
	}
	for _, a := range affs {
		if (a.Source == store.AffSourceHRIS || a.Source == store.AffSourceSIS) && affiliations.Effective(a, now) == store.AffActive {
			return a, nil
		}
	}
	return nil, nil
}

func conversionEvent(tx *store.TenantTx, ss *store.Sponsorship, note, actor string, now time.Time) error {
	n := note
	return tx.AddSponsorshipEvent(&store.SponsorshipEvent{SponsorshipID: ss.ID, Event: "conversion", ToStatus: ss.Status, Note: &n,
		PolicyVersion: ss.PolicyVersion, Actor: actor, At: now})
}

// ConvertResult counts what a conversion pass did.
type ConvertResult struct{ Ended, Asked int }

// Convert finds people with a running guest or contractor sponsorship who now
// have an employee (or student) affiliation from the HR or student system and
// converts them: the sponsorship ends at the hire date, or the sponsor is asked
// to confirm dual status. Each conversion is a "jml.conversion" audit event and
// a "conversion" entry in the sponsorship's history.
func (s *Service) Convert(tx *store.TenantTx, now time.Time) (ConvertResult, error) {
	var res ConvertResult
	set, err := tx.GuestLifecycleSettings()
	if err != nil {
		return res, err
	}
	sps, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorActive})
	if err != nil {
		return res, err
	}
	by := sweeper()
	for _, ss := range sps {
		guest, err := tx.Identity(ss.GuestIdentityID)
		if err != nil {
			return res, err
		}
		if guest.Status != "active" {
			continue
		}
		emp, err := hiredFrom(tx, ss.GuestIdentityID, now)
		if err != nil {
			return res, err
		}
		if emp == nil {
			continue
		}
		detail := ojson.Object{kv("identity_id", guest.ID), kv("sponsorship_id", ss.ID), kv("from", ss.Population),
			kv("to", emp.Type), kv("hire_date", iso(emp.StartsAt)), kv("affiliation_id", emp.ID)}
		if set.ConversionDualStatus == "sponsor_confirms" {
			prior, err := tx.LifecycleTasks(store.LifecycleTaskFilter{Sponsorship: ss.ID, Kind: store.TaskDualStatus})
			if err != nil {
				return res, err
			}
			if len(prior) > 0 {
				continue // asked before; the task decides
			}
			deadline := now.AddDate(0, 0, set.TransferDeadlineDays)
			if ss.EndsAt.Before(deadline) {
				deadline = ss.EndsAt
			}
			t := &store.LifecycleTask{ID: uuid.NewString(), Kind: store.TaskDualStatus, SponsorshipID: ss.ID, SubjectIdentityID: guest.ID,
				Trigger: store.TaskTriggerConversion, Deadline: &deadline, CreatedAt: now}
			if err := tx.InsertLifecycleTask(t); err != nil {
				return res, err
			}
			sponsor, err := tx.Identity(ss.SponsorIdentityID)
			if err != nil {
				return res, err
			}
			to, err := notify.Identity(tx, ss.SponsorIdentityID)
			if err != nil {
				return res, err
			}
			if sponsor.Status != "active" {
				if to, err = notify.GuestTaskRecipients(tx, now, sponsor.ManagerID); err != nil {
					return res, err
				}
			}
			if err := notify.GuestTaskOpened(tx, now, t.ID, guest.Name+" was hired: keep the "+ss.Population+" sponsorship?",
				guest.Name+" is now an employee. The "+ss.Population+" sponsorship ends at the deadline unless you confirm that they keep both roles.", &deadline, to...); err != nil {
				return res, err
			}
			if err := conversionEvent(tx, ss, "an employee affiliation started; the sponsor was asked about dual status", Sweeper, now); err != nil {
				return res, err
			}
			if err := tx.Audit(now, Sweeper, "jml.conversion", append(detail, kv("outcome", "asked"), kv("task_id", t.ID))); err != nil {
				return res, err
			}
			res.Asked++
			continue
		}
		if err := conversionEvent(tx, ss, "an employee affiliation started; the sponsorship ends at the hire date", Sweeper, now); err != nil {
			return res, err
		}
		if err := s.Sponsors.EndForDeparture(tx, ss, false, "converted to employee: the sponsorship ends at the hire date", by, now); err != nil {
			return res, err
		}
		if err := tx.Audit(now, Sweeper, "jml.conversion", append(detail, kv("outcome", "ended"))); err != nil {
			return res, err
		}
		res.Ended++
	}
	return res, nil
}
