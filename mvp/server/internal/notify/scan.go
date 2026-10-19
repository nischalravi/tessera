package notify

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Scan windows: how far ahead access endings are announced, and how old an
// open review campaign is before its reviewers are reminded (and then every
// further ReviewReminderEvery).
const (
	JITWarnWindow      = time.Hour
	RequestWarnWindow  = 24 * time.Hour
	ReviewReminderAge  = 7 * 24 * time.Hour
	ReviewReminderStep = 7 * 24 * time.Hour
)

// Scan finds the time-driven notifications due at now and returns them as
// rows to Write; it reads only. The events that cause them have no domain
// transaction of their own: just-in-time and requested access nearing its
// end, an approval stage that passed its due time (escalation), and review
// campaigns that have waited a week or more. Planning skips what was already
// written, so a scan that finds nothing new returns nothing.
func Scan(tx *store.TenantTx, now time.Time) ([]*store.Notification, error) {
	var out []*store.Notification
	add := func(rows []*store.Notification, err error) error {
		out = append(out, rows...)
		return err
	}
	jits, err := tx.JITExpiringBetween(now, now.Add(JITWarnWindow))
	if err != nil {
		return nil, err
	}
	for _, r := range jits {
		if err := add(PlanJITExpiring(tx, now, r)); err != nil {
			return nil, err
		}
	}
	lines, err := tx.RequestLinesExpiringBetween(now, now.Add(RequestWarnWindow))
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if err := add(PlanRequestExpiring(tx, now, l)); err != nil {
			return nil, err
		}
	}
	stages, err := tx.WaitingStages()
	if err != nil {
		return nil, err
	}
	for _, st := range stages {
		// a stage that was due the moment it started (nobody could act as its
		// assignee) went to the deciders at once: nothing escalated
		if st.Kind == store.StageDecider || st.DueAt == nil || now.Before(*st.DueAt) ||
			st.StartedAt != nil && !st.DueAt.After(*st.StartedAt) {
			continue
		}
		l, err := tx.RequestLine(st.LineID)
		if err != nil {
			return nil, err
		}
		if l.Status != store.RequestPending {
			continue
		}
		if err := add(PlanApprovalEscalated(tx, now, l, st)); err != nil {
			return nil, err
		}
	}
	camps, err := tx.CampaignsNewestFirst()
	if err != nil {
		return nil, err
	}
	for _, c := range camps {
		age := now.Sub(c.CreatedAt)
		if c.Status != "open" || age < ReviewReminderAge {
			continue
		}
		week := int(age / ReviewReminderStep)
		if err := add(PlanReviewReminder(tx, now, c, week)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
