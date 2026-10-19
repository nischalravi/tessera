package reviews

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Scheduled and recurring reviews (issue #166).
//
// A template launches a scoped campaign at next_run_at and moves next_run_at
// on by its recurrence (from the scheduled time, so runs do not drift). Each
// run is recorded once per period ("2026-Q4", "2026-H2", "2026"); a period
// that already ran is never launched again, and periods missed while the
// server was down collapse into one launch for the latest. Reminders are
// written reminder_days before the due time. At the due time, items nobody
// decided are revoked, or (close_out "escalate") reassigned to the
// escalation reviewer for escalation_days and revoked after that.
//
// Reminders and escalations are audit events for now; delivery to email or
// chat is the alerting issue (#168).

// Scheduler is the actor of scheduled launches, reminders and close-outs.
const Scheduler = "reviews.scheduler"

// Recurrences.
var Recurrences = []string{"once", "quarterly", "semiannual", "annual"}

// SpecError is a template the caller can fix.
type SpecError struct{ Code, Msg string }

func (e *SpecError) Error() string { return e.Code + ": " + e.Msg }

func specErr(code, format string, args ...any) error {
	return &SpecError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Next returns the run after t for a recurrence (nil: no further run).
func Next(recurrence string, t time.Time) *time.Time {
	months := map[string]int{"quarterly": 3, "semiannual": 6, "annual": 12}[recurrence]
	if months == 0 {
		return nil
	}
	n := t.AddDate(0, months, 0)
	return &n
}

// PeriodKey names the period a run at t belongs to.
func PeriodKey(recurrence string, t time.Time) string {
	t = t.UTC()
	switch recurrence {
	case "quarterly":
		return fmt.Sprintf("%d-Q%d", t.Year(), (int(t.Month())-1)/3+1)
	case "semiannual":
		return fmt.Sprintf("%d-H%d", t.Year(), (int(t.Month())-1)/6+1)
	case "annual":
		return strconv.Itoa(t.Year())
	}
	return "once"
}

// ValidateTemplate checks a template's settings.
func ValidateTemplate(tx *store.TenantTx, t *store.ReviewTemplate) error {
	t.Name = strings.TrimSpace(t.Name)
	switch {
	case t.Name == "" || len(t.Name) > 200:
		return specErr("invalid_name", "a name of 1 to 200 characters is required")
	case !slices.Contains(Recurrences, t.Recurrence):
		return specErr("invalid_recurrence", "recurrence is once, quarterly, semiannual or annual")
	case t.UnusedDays < 1 || t.UnusedDays > 365:
		return specErr("invalid_unused_days", "unused days is 1 to 365")
	case t.DurationDays < 1 || t.DurationDays > 90:
		return specErr("invalid_duration", "reviewers get 1 to 90 days")
	case t.ReminderDays < 0 || t.ReminderDays >= t.DurationDays:
		return specErr("invalid_reminder", "reminders go out 0 to %d days before the due date", t.DurationDays-1)
	case t.CloseOut != "revoke" && t.CloseOut != "escalate":
		return specErr("invalid_close_out", "close-out is revoke or escalate")
	case t.EscalationDays < 1 || t.EscalationDays > 30:
		return specErr("invalid_escalation_days", "escalation lasts 1 to 30 days")
	case t.Enabled && t.NextRunAt == nil:
		return specErr("first_run_required", "an enabled schedule needs a first run time")
	}
	if t.System != nil {
		if s := strings.TrimSpace(*t.System); s == "" {
			t.System = nil
		} else {
			t.System = &s
		}
	}
	if t.System != nil { // a typo would certify nothing, silently
		n, err := tx.CountSystem(*t.System)
		if err != nil {
			return err
		}
		if n.Accounts+n.Groups+n.Resources+n.Permissions == 0 {
			return specErr("invalid_system", "%q is not one of this organization's systems", *t.System)
		}
	}
	if t.CloseOut == "escalate" {
		if t.EscalationIdentityID == nil {
			return specErr("escalation_reviewer_required", "escalation needs a reviewer")
		}
		i, err := tx.Identity(*t.EscalationIdentityID)
		if errors.Is(err, store.ErrNotFound) {
			return specErr("escalation_reviewer_not_found", "escalation reviewer not found")
		} else if err != nil {
			return err
		}
		if i.Type != "human" || i.Status != "active" {
			return specErr("escalation_reviewer_not_active", "the escalation reviewer is an active person")
		}
	} else {
		t.EscalationIdentityID = nil
	}
	return nil
}

// ErrAlreadyLaunched is a run of a period that already launched.
var ErrAlreadyLaunched = errors.New("this period already launched")

// Launch starts a template's campaign for period, due after its duration.
// When nothing is in scope it creates no campaign: it audits
// review.schedule.skipped with the reason and returns a nil launch.
func Launch(tx *store.TenantTx, t *store.ReviewTemplate, period string, now time.Time, policies []*policy.Policy, actor string) (*store.ReviewLaunch, error) {
	name := t.Name + " · " + period
	sys := ""
	if t.System != nil {
		sys = *t.System
	}
	campID, err := GenerateScopedCampaign(tx, now, name, t.UnusedDays, policies, Scope{System: sys, PrivilegedOnly: t.PrivilegedOnly, SkipEmpty: true})
	if err != nil {
		return nil, err
	}
	if campID == 0 {
		return nil, tx.Audit(now, actor, "review.schedule.skipped", ojson.Object{{Key: "template_id", Value: t.ID},
			{Key: "period", Value: period}, {Key: "reason", Value: "no grants in scope"}})
	}
	l := &store.ReviewLaunch{ID: uuid.NewString(), TemplateID: t.ID, PeriodKey: period, CampaignID: campID, LaunchedAt: now,
		DueAt: now.Add(time.Duration(t.DurationDays) * 24 * time.Hour)}
	if err := tx.InsertReviewLaunch(l); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, actor, "review.schedule.launch", ojson.Object{{Key: "template_id", Value: t.ID},
		{Key: "period", Value: period}, {Key: "campaign_id", Value: campID}, {Key: "due_at", Value: timeutil.ISO(l.DueAt)}})
}

// RunNow launches a template outside its schedule (period "manual-<time>"). A
// nil launch with a nil error means nothing was in scope and no campaign was made.
func RunNow(tx *store.TenantTx, id string, now time.Time, policies []*policy.Policy, actor string) (*store.ReviewLaunch, error) {
	t, err := tx.ReviewTemplate(id)
	if err != nil {
		return nil, err
	}
	period := "manual-" + now.UTC().Format("20060102T150405Z")
	if done, err := tx.ReviewPeriodLaunched(t.ID, period); err != nil {
		return nil, err
	} else if done { // a double click in the same second
		return nil, ErrAlreadyLaunched
	}
	return Launch(tx, t, period, now, policies, actor)
}

// TickResult counts what one tick did.
type TickResult struct{ Launched, Reminded, Escalated, Closed, Revoked, Skipped int }

// Tick launches due templates and progresses open runs, in one tenant.
func Tick(tx *store.TenantTx, now time.Time, policies []*policy.Policy) (TickResult, error) {
	var res TickResult
	due, err := tx.DueReviewTemplates(now)
	if err != nil {
		return res, err
	}
	for _, t := range due {
		scheduled := *t.NextRunAt
		// collapse missed periods into the latest one at or before now
		run, next := scheduled, Next(t.Recurrence, scheduled)
		for next != nil && !next.After(now) {
			run, next = *next, Next(t.Recurrence, *next)
		}
		period := PeriodKey(t.Recurrence, run)
		if done, err := tx.ReviewPeriodLaunched(t.ID, period); err != nil {
			return res, err
		} else if !done {
			l, err := Launch(tx, t, period, now, policies, Scheduler)
			if err != nil {
				return res, err
			}
			if l == nil {
				res.Skipped++
			} else {
				res.Launched++
			}
		}
		if err := tx.AdvanceReviewTemplate(t.ID, scheduled, next); err != nil {
			return res, err
		}
	}
	open, err := tx.OpenReviewLaunches()
	if err != nil {
		return res, err
	}
	for _, l := range open {
		if err := progress(tx, l, now, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func undecided(tx *store.TenantTx, campaignID int64) ([]*store.ReviewItem, error) {
	items, err := tx.CampaignItems(campaignID)
	if err != nil {
		return nil, err
	}
	var out []*store.ReviewItem
	for _, it := range items {
		if it.Decision == nil {
			out = append(out, it)
		}
	}
	return out, nil
}

func progress(tx *store.TenantTx, l *store.ReviewLaunch, now time.Time, res *TickResult) error {
	t, err := tx.ReviewTemplate(l.TemplateID)
	if err != nil {
		return err
	}
	open, err := undecided(tx, l.CampaignID)
	if err != nil {
		return err
	}
	if len(open) == 0 {
		l.ClosedAt = &now
		return tx.SaveReviewLaunch(l)
	}
	remindAt := l.DueAt.Add(-time.Duration(t.ReminderDays) * 24 * time.Hour)
	if l.RemindedAt == nil && t.ReminderDays > 0 && !now.Before(remindAt) && now.Before(l.DueAt) {
		byReviewer := map[string]int{}
		for _, it := range open {
			k := "unassigned"
			if it.ReviewerID != nil {
				k = strconv.FormatInt(*it.ReviewerID, 10)
			}
			byReviewer[k]++
		}
		l.RemindedAt = &now
		if err := tx.SaveReviewLaunch(l); err != nil {
			return err
		}
		res.Reminded++
		return tx.Audit(now, Scheduler, "review.reminder", ojson.Object{{Key: "campaign_id", Value: l.CampaignID},
			{Key: "open_items", Value: len(open)}, {Key: "by_reviewer", Value: sortedCounts(byReviewer)},
			{Key: "due_at", Value: timeutil.ISO(l.DueAt)}})
	}
	if now.Before(l.DueAt) {
		return nil
	}
	if t.CloseOut == "escalate" && l.EscalatedAt == nil && t.EscalationIdentityID != nil {
		for _, it := range open {
			if err := tx.SetItemReviewer(it.ID, *t.EscalationIdentityID); err != nil {
				return err
			}
		}
		l.EscalatedAt = &now
		l.DueAt = now.Add(time.Duration(t.EscalationDays) * 24 * time.Hour)
		if err := tx.SaveReviewLaunch(l); err != nil {
			return err
		}
		res.Escalated++
		return tx.Audit(now, Scheduler, "review.escalate", ojson.Object{{Key: "campaign_id", Value: l.CampaignID},
			{Key: "items", Value: len(open)}, {Key: "reviewer_id", Value: *t.EscalationIdentityID},
			{Key: "due_at", Value: timeutil.ISO(l.DueAt)}})
	}
	note := "not reviewed by the deadline"
	for _, it := range open {
		if _, err := Decide(tx, now, it.ID, "revoke", store.UserRef{Display: Scheduler}, &note); err != nil {
			return err
		}
	}
	l.ClosedAt, l.Revoked = &now, len(open)
	if err := tx.SaveReviewLaunch(l); err != nil {
		return err
	}
	res.Closed++
	res.Revoked += len(open)
	return tx.Audit(now, Scheduler, "review.close", ojson.Object{{Key: "campaign_id", Value: l.CampaignID},
		{Key: "revoked", Value: len(open)}})
}

// sortedCounts renders per-reviewer counts as an ordered object.
func sortedCounts(m map[string]int) ojson.Object {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(ojson.Object, 0, len(keys))
	for _, k := range keys {
		out = append(out, ojson.KV{Key: k, Value: m[k]})
	}
	return out
}

// TickAll runs Tick for every active tenant, each in its own transaction.
func TickAll(ctx context.Context, db *store.DB, now time.Time, policies []*policy.Policy) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		_, err := Tick(tx, now, policies)
		return err
	})
}
