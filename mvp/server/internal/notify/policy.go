package notify

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Policy is a tenant's reminder cadence and escalation timings (Admin > Notifications, schema/0763_notification_policy.sql).
// The defaults are the timings that were fixed before: reminders to the reviewers of an open campaign after 7 days and every 7
// days, access ending announced 24 hours ahead (requested access) and 60 minutes ahead (just-in-time access), and an approval
// stage escalated to the deciders after 48 hours.
type Policy struct {
	ReviewRemindAfterDays int `json:"review_remind_after_days"`
	ReviewRemindEveryDays int `json:"review_remind_every_days"`
	RequestWarnHours      int `json:"request_warn_hours"`
	JITWarnMinutes        int `json:"jit_warn_minutes"`
	// EscalateAfterHours is how long an approval stage waits before the deciders may act, for a catalog item with no approval
	// policy of its own (an item's own policy, an organization's default stages and a workflow keep theirs).
	EscalateAfterHours int `json:"escalate_after_hours"`
}

// Limits of the policy fields, mirrored by the table's checks.
const (
	MaxRemindDays    = 90
	MaxWarnHours     = 720
	MinJITWarnMin    = 5
	MaxJITWarnMin    = 1440
	MaxEscalateHours = 720
)

// DefaultPolicy is the policy of a tenant that saved none.
func DefaultPolicy() Policy {
	return Policy{ReviewRemindAfterDays: 7, ReviewRemindEveryDays: 7, RequestWarnHours: 24, JITWarnMinutes: 60, EscalateAfterHours: 48}
}

// Check refuses values outside the limits.
func (p Policy) Check() error {
	in := func(v, lo, hi int) bool { return v >= lo && v <= hi }
	switch {
	case !in(p.ReviewRemindAfterDays, 1, MaxRemindDays):
		return cfgerr.Refuse(422, "invalid_reminder", "the first review reminder is after 1 to %d days", MaxRemindDays)
	case !in(p.ReviewRemindEveryDays, 1, MaxRemindDays):
		return cfgerr.Refuse(422, "invalid_reminder", "review reminders repeat every 1 to %d days", MaxRemindDays)
	case !in(p.RequestWarnHours, 1, MaxWarnHours):
		return cfgerr.Refuse(422, "invalid_warning", "the end of requested access is announced 1 to %d hours ahead", MaxWarnHours)
	case !in(p.JITWarnMinutes, MinJITWarnMin, MaxJITWarnMin):
		return cfgerr.Refuse(422, "invalid_warning", "the end of just-in-time access is announced %d to %d minutes ahead", MinJITWarnMin, MaxJITWarnMin)
	case !in(p.EscalateAfterHours, 1, MaxEscalateHours):
		return cfgerr.Refuse(422, "invalid_escalation", "approvals escalate after 1 to %d hours", MaxEscalateHours)
	}
	return nil
}

// LoadPolicy returns the tenant's policy and its version (0 for the defaults).
func LoadPolicy(tx *store.TenantTx) (Policy, int, error) {
	r, err := tx.NotificationPolicy()
	if errors.Is(err, store.ErrNotFound) {
		return DefaultPolicy(), 0, nil
	} else if err != nil {
		return Policy{}, 0, err
	}
	return Policy{ReviewRemindAfterDays: r.ReviewRemindAfterDays, ReviewRemindEveryDays: r.ReviewRemindEveryDays,
		RequestWarnHours: r.RequestWarnHours, JITWarnMinutes: r.JITWarnMinutes, EscalateAfterHours: r.EscalateAfterHours}, r.Version, nil
}

func policyDetail(p Policy) ojson.Object {
	return ojson.Object{{Key: "review_remind_after_days", Value: p.ReviewRemindAfterDays}, {Key: "review_remind_every_days", Value: p.ReviewRemindEveryDays},
		{Key: "request_warn_hours", Value: p.RequestWarnHours}, {Key: "jit_warn_minutes", Value: p.JITWarnMinutes},
		{Key: "escalate_after_hours", Value: p.EscalateAfterHours}}
}

// SavePolicy replaces the tenant's policy. ver is the version the caller read (0 for the defaults); a different current
// version is a conflict. It is audited in the same transaction, with the old values.
func SavePolicy(tx *store.TenantTx, p Policy, ver int, by string, now time.Time) (Policy, int, error) {
	if err := p.Check(); err != nil {
		return Policy{}, 0, err
	}
	old, cur, err := LoadPolicy(tx)
	if err != nil {
		return Policy{}, 0, err
	}
	if ver != cur {
		return Policy{}, 0, cfgerr.Conflict(ver, cur)
	}
	row := &store.NotificationPolicyRow{ReviewRemindAfterDays: p.ReviewRemindAfterDays, ReviewRemindEveryDays: p.ReviewRemindEveryDays,
		RequestWarnHours: p.RequestWarnHours, JITWarnMinutes: p.JITWarnMinutes, EscalateAfterHours: p.EscalateAfterHours, UpdatedBy: by}
	if err := tx.PutNotificationPolicy(row, now); err != nil {
		return Policy{}, 0, err
	}
	d := append(policyDetail(p), ojson.KV{Key: "previous", Value: policyDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	return p, cur + 1, tx.Audit(now, by, "notification.policy.update", d)
}
