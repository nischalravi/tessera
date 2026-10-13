// Package lifecycle is the identity lifecycle (issue #159): each person's
// worker type (employee, contractor, intern, partner, vendor, guest), their
// sponsor, and their start and end dates.
//
// Every worker type but employee has an end date and a sponsor: the active
// person accountable for them, who is warned before the end (14, 7 and 1
// days) and may extend it. A term is at most MaxTermDays from now; longer
// engagements are extended, each extension audited. On the end date the
// sweep runs the identity's leaver plan (disable accounts, remove grants,
// cancel JIT, reassign ownership, as jml.LeaverPlan lists them) and
// terminates the identity, in one transaction with its audit event.
//
// An identity with no lifecycle row is an employee with no end date. The
// lifecycle is set by hand (lifecycle.manage) or from the HRIS joiner
// event. Every change is a history event and an audit event in the
// caller's transaction.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Limits and thresholds.
const (
	MaxTermDays = 366 // a term (or extension) ends at most this far from now
	MaxReason   = requests.MaxReason
	MaxOrg      = 200
	// Sweeper is the actor of sweep events.
	Sweeper = "lifecycle.sweeper"
)

// WarnDays are the warning thresholds before an end date, largest first.
var WarnDays = []int{14, 7, 1}

// WorkerTypes lists every worker type.
var WorkerTypes = []string{store.WorkerEmployee, store.WorkerContractor, store.WorkerIntern, store.WorkerPartner,
	store.WorkerVendor, store.WorkerGuest}

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

// Actor is the signed-in user acting.
type Actor = requests.Actor

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Notifier is told when a warning goes out or a term ends (the
// notifications outbox, #189, implements it; nil sends nothing beyond the
// audit event).
type Notifier interface {
	Expiring(tx *store.TenantTx, l *store.Lifecycle, person *store.Identity, daysLeft int) error
	Ended(tx *store.TenantTx, l *store.Lifecycle, person *store.Identity) error
}

// Notify is the notifier the sweep uses.
var Notify Notifier

// ---------------------------------------------------------------- state

// States of a lifecycle at a moment.
const (
	StateUpcoming = "upcoming" // starts in the future
	StateActive   = "active"
	StateEnding   = "ending" // ends within the first warning threshold
	StateEnded    = "ended"
)

// State is a lifecycle's state at now.
func State(l *store.Lifecycle, now time.Time) string {
	switch {
	case l.EndedAt != nil:
		return StateEnded
	case l.StartsAt != nil && l.StartsAt.After(now):
		return StateUpcoming
	case l.EndsAt != nil && !l.EndsAt.After(now.Add(days(WarnDays[0]))):
		return StateEnding
	}
	return StateActive
}

// DaysLeft is the whole days until the end date (rounded up; 0 when due).
func DaysLeft(l *store.Lifecycle, now time.Time) *int {
	if l.EndsAt == nil {
		return nil
	}
	d := int(math.Ceil(l.EndsAt.Sub(now).Hours() / 24))
	if d < 0 {
		d = 0
	}
	return &d
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// ---------------------------------------------------------------- changes

// Spec is the lifecycle an admin sets.
type Spec struct {
	WorkerType   string
	SponsorID    *int64
	Organization *string
	StartsAt     *time.Time
	EndsAt       *time.Time
	Reason       string
}

func reasonPtr(reason string) (*string, error) {
	r := strings.TrimSpace(reason)
	if r == "" || len(r) > MaxReason {
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", MaxReason)
	}
	return &r, nil
}

func person(tx *store.TenantTx, id int64) (*store.Identity, error) {
	p, err := tx.Identity(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "identity_not_found", "person not found")
	}
	return p, err
}

func (s *Spec) validate(tx *store.TenantTx, p *store.Identity, now time.Time) error {
	if !slices.Contains(WorkerTypes, s.WorkerType) {
		return refuse(422, "invalid_worker_type", "worker type is one of %s", strings.Join(WorkerTypes, ", "))
	}
	if s.Organization != nil {
		o := strings.TrimSpace(*s.Organization)
		if len(o) > MaxOrg {
			return refuse(422, "invalid_organization", "the organization is at most %d characters", MaxOrg)
		}
		if o == "" {
			s.Organization = nil
		} else {
			s.Organization = &o
		}
	}
	if s.WorkerType == store.WorkerEmployee {
		if s.EndsAt != nil && !s.EndsAt.After(now) {
			return refuse(422, "invalid_end", "the end date is in the past")
		}
	} else {
		switch {
		case s.EndsAt == nil:
			return refuse(422, "end_required", "a %s needs an end date", s.WorkerType)
		case !s.EndsAt.After(now):
			return refuse(422, "invalid_end", "the end date is in the past")
		case s.EndsAt.After(now.Add(days(MaxTermDays))):
			return refuse(422, "term_too_long", "an end date is at most %d days away; extend it later", MaxTermDays)
		case s.SponsorID == nil:
			return refuse(422, "sponsor_required", "a %s needs a sponsor", s.WorkerType)
		}
	}
	if s.StartsAt != nil && s.EndsAt != nil && !s.EndsAt.After(*s.StartsAt) {
		return refuse(422, "invalid_end", "the end date is before the start date")
	}
	if s.SponsorID != nil {
		sp, err := tx.Identity(*s.SponsorID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return refuse(422, "sponsor_not_found", "sponsor not found")
		case err != nil:
			return err
		case sp.ID == p.ID:
			return refuse(422, "sponsor_is_self", "nobody sponsors themselves")
		case sp.Type != "human" || sp.Status != "active":
			return refuse(422, "sponsor_not_active", "%s cannot sponsor: the sponsor is an active person", sp.Name)
		}
		if spl, err := tx.LifecycleFor(sp.ID); err == nil && spl.WorkerType != store.WorkerEmployee {
			return refuse(422, "sponsor_not_employee", "%s is a %s; sponsors are employees", sp.Name, spl.WorkerType)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func uidp(by Actor) *string {
	if by.UserID == uuid.Nil {
		return nil
	}
	s := by.UserID.String()
	return &s
}

func event(tx *store.TenantTx, l *store.Lifecycle, ev string, note *string, by Actor, now time.Time) error {
	wt := l.WorkerType
	return tx.AddLifecycleEvent(&store.LifecycleEvent{IdentityID: l.IdentityID, Event: ev, WorkerType: &wt, EndsAt: l.EndsAt,
		Note: note, ActorUserID: uidp(by), Actor: by.Display, At: now})
}

func detail(l *store.Lifecycle, reason *string) ojson.Object {
	d := ojson.Object{{Key: "identity_id", Value: l.IdentityID}, {Key: "worker_type", Value: l.WorkerType}}
	if l.SponsorID != nil {
		d = append(d, ojson.KV{Key: "sponsor_id", Value: *l.SponsorID})
	}
	if l.EndsAt != nil {
		d = append(d, ojson.KV{Key: "ends_at", Value: timeutil.ISO(*l.EndsAt)})
	}
	if reason != nil {
		d = append(d, ojson.KV{Key: "reason", Value: *reason})
	}
	return d
}

// Set sets (or converts) a person's lifecycle. A change of worker type is a
// conversion (for example contractor to employee, which drops the end date
// unless one is given).
func Set(tx *store.TenantTx, identityID int64, s Spec, by Actor, now time.Time) (*store.Lifecycle, error) {
	r, err := reasonPtr(s.Reason)
	if err != nil {
		return nil, err
	}
	p, err := person(tx, identityID)
	if err != nil {
		return nil, err
	}
	switch {
	case p.Type != "human":
		return nil, refuse(422, "not_a_person", "machine identities have owners, not a lifecycle")
	case p.Status != "active":
		return nil, refuse(409, "identity_not_active", "%s is %s", p.Name, p.Status)
	}
	old, err := tx.LifecycleFor(identityID)
	if errors.Is(err, store.ErrNotFound) {
		old = nil
	} else if err != nil {
		return nil, err
	}
	if old != nil && old.EndedAt != nil {
		return nil, refuse(409, "ended", "this term has ended")
	}
	if err := s.validate(tx, p, now); err != nil {
		return nil, err
	}
	l := &store.Lifecycle{IdentityID: identityID, WorkerType: s.WorkerType, SponsorID: s.SponsorID, Organization: s.Organization,
		StartsAt: s.StartsAt, EndsAt: s.EndsAt, Source: "manual", UpdatedBy: uidp(by), UpdatedAt: now}
	if old != nil && sameTime(old.EndsAt, l.EndsAt) {
		l.WarnedDays = old.WarnedDays // the warnings already sent still hold
	}
	if err := tx.PutLifecycle(l); err != nil {
		return nil, err
	}
	ev, action := "set", "lifecycle.set"
	if old != nil && old.WorkerType != l.WorkerType {
		ev, action = "converted", "lifecycle.convert"
	}
	if err := event(tx, l, ev, r, by, now); err != nil {
		return nil, err
	}
	d := detail(l, r)
	if old != nil && ev == "converted" {
		d = append(d, ojson.KV{Key: "from_worker_type", Value: old.WorkerType})
	}
	return l, tx.Audit(now, by.Display, action, d)
}

func sameTime(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}

// Extend moves an end date later. The sponsor may extend their own
// people; manager is true for holders of lifecycle.manage.
func Extend(tx *store.TenantTx, identityID int64, to time.Time, reason string, by Actor, manager bool, now time.Time) (*store.Lifecycle, error) {
	r, err := reasonPtr(reason)
	if err != nil {
		return nil, err
	}
	l, err := tx.LifecycleFor(identityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "no_end_date", "this person has no end date to extend")
	} else if err != nil {
		return nil, err
	}
	sponsor := by.IdentityID != nil && l.SponsorID != nil && *by.IdentityID == *l.SponsorID
	switch {
	case !manager && !sponsor:
		return nil, refuse(403, "not_sponsor", "only the sponsor or a lifecycle admin can extend")
	case by.IdentityID != nil && *by.IdentityID == identityID:
		return nil, refuse(403, "self_extension", "nobody extends their own term")
	case l.EndedAt != nil:
		return nil, refuse(409, "ended", "this term has ended")
	case l.EndsAt == nil:
		return nil, refuse(409, "no_end_date", "this person has no end date to extend")
	case !to.After(*l.EndsAt):
		return nil, refuse(422, "not_later", "an extension moves the end date later")
	case to.After(now.Add(days(MaxTermDays))):
		return nil, refuse(422, "term_too_long", "an end date is at most %d days away", MaxTermDays)
	}
	if sp := l.SponsorID; sp != nil {
		if s, err := tx.Identity(*sp); err != nil {
			return nil, err
		} else if s.Status != "active" && !manager {
			return nil, refuse(409, "sponsor_not_active", "the sponsor is no longer active; a lifecycle admin assigns a new one")
		}
	}
	l.EndsAt, l.WarnedDays, l.UpdatedBy, l.UpdatedAt = &to, nil, uidp(by), now
	if err := tx.PutLifecycle(l); err != nil {
		return nil, err
	}
	if err := event(tx, l, "extended", r, by, now); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "lifecycle.extend", detail(l, r))
}

// ---------------------------------------------------------------- sweep

// threshold is the warning due for daysLeft (0: none).
func threshold(daysLeft int) int {
	t := 0
	for _, w := range WarnDays {
		if daysLeft <= w {
			t = w
		}
	}
	return t
}

func due(l *store.Lifecycle, now time.Time) (end bool, warn int) {
	if l.EndedAt != nil || l.EndsAt == nil {
		return false, 0
	}
	if !l.EndsAt.After(now) {
		return true, 0
	}
	t := threshold(*DaysLeft(l, now))
	if t > 0 && (l.WarnedDays == nil || t < *l.WarnedDays) {
		return false, t
	}
	return false, 0
}

// NeedsSweep reports whether Sweep would change anything at now.
func NeedsSweep(tx *store.TenantTx, now time.Time) (bool, error) {
	ls, err := tx.LifecyclesEndingBy(now.Add(days(WarnDays[0])))
	if err != nil {
		return false, err
	}
	for _, l := range ls {
		if end, warn := due(l, now); end || warn > 0 {
			return true, nil
		}
	}
	return false, nil
}

// SweepResult counts what a sweep did.
type SweepResult struct{ Warned, Ended int }

// Sweep sends due warnings and ends due terms: the leaver plan runs and the
// identity is terminated (an identity terminated already, by the HRIS, is
// only marked ended).
func Sweep(tx *store.TenantTx, now time.Time) (SweepResult, error) {
	var res SweepResult
	ls, err := tx.LifecyclesEndingBy(now.Add(days(WarnDays[0])))
	if err != nil {
		return res, err
	}
	by := Actor{Display: Sweeper}
	for _, l := range ls {
		end, warn := due(l, now)
		if !end && warn == 0 {
			continue
		}
		p, err := tx.Identity(l.IdentityID)
		if err != nil {
			return res, err
		}
		if end {
			steps := 0
			if p.Status == "active" {
				plan, err := jml.ExecuteLeaver(tx, now, l.IdentityID)
				if err != nil {
					return res, err
				}
				if s, ok := plan.Get("steps"); ok {
					if ss, ok := s.([]jml.Step); ok {
						steps = len(ss)
					}
				}
			}
			if err := tx.MarkLifecycleEnded(l.IdentityID, now); err != nil {
				return res, err
			}
			l.EndedAt = &now
			if err := event(tx, l, "ended", nil, by, now); err != nil {
				return res, err
			}
			if Notify != nil {
				if err := Notify.Ended(tx, l, p); err != nil {
					return res, err
				}
			}
			d := append(detail(l, nil), ojson.KV{Key: "leaver_steps", Value: steps}, ojson.KV{Key: "was_active", Value: p.Status == "active"})
			if err := tx.Audit(now, Sweeper, "lifecycle.end", d); err != nil {
				return res, err
			}
			res.Ended++
			continue
		}
		if err := tx.MarkLifecycleWarned(l.IdentityID, warn); err != nil {
			return res, err
		}
		left := *DaysLeft(l, now)
		note := fmt.Sprintf("ends in %d day(s)", left)
		l.WarnedDays = &warn
		if err := event(tx, l, "warned", &note, by, now); err != nil {
			return res, err
		}
		if Notify != nil {
			if err := Notify.Expiring(tx, l, p, left); err != nil {
				return res, err
			}
		}
		if err := tx.Audit(now, Sweeper, "lifecycle.warn", append(detail(l, nil), ojson.KV{Key: "days_left", Value: left})); err != nil {
			return res, err
		}
		res.Warned++
	}
	return res, nil
}

// SweepAll runs Sweep for every active tenant in its own transaction (the
// background sweeper); a tenant with nothing due is left untouched. It is
// not run on the read path: ending a term runs a leaver plan, which a read
// should not set off.
func SweepAll(ctx context.Context, db *store.DB, now time.Time) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		need, err := NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = Sweep(tx, now)
		return err
	})
}
