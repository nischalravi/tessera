package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Engine is the system actor of everything the engine audits.
const Engine = "alerts.engine"

// batch caps the audit events read per tenant per evaluation.
const batch = 1000

// Error is a refused change; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Result counts what one evaluation did.
type Result struct {
	Events   int // audit events read
	Raised   int
	Bumped   int
	Resolved int // detections that cleared
}

// Evaluate reads the tenant's audit events after the cursor, matches them
// against the event rules and, when detect is set, re-runs the detection
// rules. The first evaluation of a tenant starts at the current head: past
// events do not alert.
func Evaluate(tx *store.TenantTx, now time.Time, detect bool) (Result, error) {
	var res Result
	rules, err := EffectiveRules(tx)
	if err != nil {
		return res, err
	}
	cursor, ok, err := tx.AlertCursor()
	if err != nil {
		return res, err
	}
	if !ok {
		head, err := tx.AuditHead()
		if err != nil {
			return res, err
		}
		cursor = head.LastSeq
	}
	events, err := tx.AuditEventsRange(cursor+1, 0, batch)
	if err != nil {
		return res, err
	}
	res.Events = len(events)
	for _, e := range events {
		cursor = e.Seq
		if e.Action == "http.request" || strings.HasPrefix(e.Action, "alert.") {
			continue
		}
		for _, r := range rules {
			if !r.Enabled || r.Kind != "event" {
				continue
			}
			hit, ok := r.Match(e)
			if !ok {
				continue
			}
			raised, err := onHit(tx, now, r, hit, e)
			if err != nil {
				return res, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			switch raised {
			case 1:
				res.Raised++
			case 2:
				res.Bumped++
			}
		}
	}
	if err := tx.SetAlertCursor(cursor, now); err != nil {
		return res, err
	}
	if detect {
		for _, r := range rules {
			if r.Kind != "detection" {
				continue
			}
			raised, resolved, err := runDetection(tx, now, r)
			if err != nil {
				return res, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			res.Raised += raised
			res.Resolved += resolved
		}
	}
	return res, nil
}

func eventDetail(e *store.AuditEvent) json.RawMessage {
	d := map[string]any{"event_id": e.ID.String(), "seq": e.Seq, "action": e.Action, "outcome": e.Outcome,
		"actor": actorOf(e), "occurred_at": e.OccurredAt.UTC().Format(time.RFC3339)}
	if e.IP != nil {
		d["ip"] = *e.IP
	}
	if e.TargetType != nil {
		d["target_type"] = *e.TargetType
	}
	if e.TargetID != nil {
		d["target_id"] = *e.TargetID
	}
	b, _ := json.Marshal(d)
	return b
}

// onHit handles one matching event: 2 when it bumped a live alert, 1 when it
// raised one, 0 when the threshold is not reached yet.
func onHit(tx *store.TenantTx, now time.Time, r Effective, hit Hit, e *store.AuditEvent) (int, error) {
	seq := e.Seq
	live, err := tx.LiveAlert(r.ID, hit.Key)
	if err == nil {
		return 2, tx.BumpAlert(live.ID, 1, e.OccurredAt, &seq, live.Severity, live.Title, live.Detail)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	n := 1
	if r.Threshold > 1 {
		if n, err = countHits(tx, r, hit.Key, e); err != nil {
			return 0, err
		}
		if n < r.Threshold {
			return 0, nil
		}
	}
	title := hit.Title
	if n > 1 {
		title = fmt.Sprintf("%s (%d in %d min)", hit.Title, n, int(r.Window.Minutes()))
	}
	a := &store.Alert{ID: uuid.NewString(), RuleID: r.ID, DedupKey: hit.Key, Severity: r.Severity, Title: title,
		Detail: eventDetail(e), Count: n, FirstSeenAt: e.OccurredAt, LastSeenAt: e.OccurredAt, LastEventSeq: &seq}
	return 1, raise(tx, now, a)
}

// countHits counts the events with the same rule and key in the window that
// ends at e, e included.
func countHits(tx *store.TenantTx, r Effective, key string, e *store.AuditEvent) (int, error) {
	from := e.OccurredAt.Add(-r.Window)
	evs, err := tx.AuditEvents(store.AuditFilter{From: from, To: e.OccurredAt.Add(time.Second), Limit: 5000})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range evs {
		if x.Seq > e.Seq || x.OccurredAt.Before(from) {
			continue
		}
		if h, ok := r.Match(x); ok && h.Key == key {
			n++
		}
	}
	return n, nil
}

func runDetection(tx *store.TenantTx, now time.Time, r Effective) (raised, resolved int, err error) {
	var found []Finding
	if r.Enabled {
		if found, err = r.Detect(tx, now); err != nil {
			return 0, 0, err
		}
	}
	keep := map[string]bool{}
	for _, f := range found {
		if max(f.Count, 1) < r.Threshold {
			continue
		}
		keep[f.Key] = true
		detail, _ := json.Marshal(f.Detail)
		live, err := tx.LiveAlert(r.ID, f.Key)
		if err == nil {
			if err := tx.BumpAlert(live.ID, 0, now, nil, live.Severity, f.Title, detail); err != nil {
				return raised, resolved, err
			}
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return raised, resolved, err
		}
		a := &store.Alert{ID: uuid.NewString(), RuleID: r.ID, DedupKey: f.Key, Severity: r.Severity, Title: f.Title,
			Detail: detail, Count: 1, FirstSeenAt: now, LastSeenAt: now}
		if err := raise(tx, now, a); err != nil {
			return raised, resolved, err
		}
		raised++
	}
	live, err := tx.LiveAlertsOfRule(r.ID)
	if err != nil {
		return raised, resolved, err
	}
	for _, a := range live {
		if keep[a.DedupKey] {
			continue
		}
		note := "condition cleared"
		if !r.Enabled {
			note = "rule switched off"
		}
		a.Status, a.ResolvedAt, a.Resolution = "resolved", &now, &note
		if err := tx.SaveAlertState(a); err != nil {
			return raised, resolved, err
		}
		if err := tx.Audit(now, Engine, "alert.resolved", ojson.Object{{Key: "alert_id", Value: a.ID},
			{Key: "rule", Value: a.RuleID}, {Key: "title", Value: a.Title}, {Key: "resolution", Value: note}}); err != nil {
			return raised, resolved, err
		}
		resolved++
	}
	return raised, resolved, nil
}

// RunScheduled runs one "scheduled" rule for the tenant (the daily certificate
// expiry check, from the durable queue): it raises an alert for each finding at
// the rule's threshold and resolves the ones whose condition cleared.
func RunScheduled(tx *store.TenantTx, now time.Time, ruleID string) (raised, resolved int, err error) {
	rules, err := EffectiveRules(tx)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range rules {
		if r.ID == ruleID && r.Kind == "scheduled" {
			return runDetection(tx, now, r)
		}
	}
	return 0, 0, fmt.Errorf("alerts: no scheduled rule %q", ruleID)
}

// raise inserts a new alert, audits it and queues its deliveries.
func raise(tx *store.TenantTx, now time.Time, a *store.Alert) error {
	if err := tx.InsertAlert(a); err != nil {
		return err
	}
	chans, err := tx.AlertChannels()
	if err != nil {
		return err
	}
	queued := 0
	for _, c := range chans {
		if !c.Enabled || SeverityRank(a.Severity) < SeverityRank(c.MinSeverity) {
			continue
		}
		if err := tx.InsertAlertDelivery(&store.AlertDelivery{ID: uuid.NewString(), AlertID: a.ID, ChannelID: c.ID,
			Reason: "raised", NextAttemptAt: now, CreatedAt: now}); err != nil {
			return err
		}
		queued++
	}
	return tx.Audit(now, Engine, "alert.raised", ojson.Object{{Key: "alert_id", Value: a.ID}, {Key: "rule", Value: a.RuleID},
		{Key: "severity", Value: a.Severity}, {Key: "key", Value: a.DedupKey}, {Key: "title", Value: a.Title},
		{Key: "deliveries", Value: queued}})
}

// ----------------------------------------------------------------- triage

// Actor is the person changing an alert.
type Actor struct {
	UserID  string
	Display string
}

func liveAlert(tx *store.TenantTx, id string) (*store.Alert, error) {
	a, err := tx.Alert(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "alert_not_found", "alert not found")
	}
	return a, err
}

// Acknowledge marks an open alert as being handled, and assigns it to the
// actor when nobody has it.
func Acknowledge(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.Alert, error) {
	a, err := liveAlert(tx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != "open" {
		return nil, refuse(409, "not_open", "the alert is %s", a.Status)
	}
	a.Status, a.AcknowledgedBy, a.AcknowledgedAt = "acknowledged", &by.UserID, &now
	if a.AssigneeUserID == nil {
		a.AssigneeUserID = &by.UserID
	}
	if err := tx.SaveAlertState(a); err != nil {
		return nil, err
	}
	return a, tx.Audit(now, by.Display, "alert.acknowledged", ojson.Object{{Key: "alert_id", Value: a.ID},
		{Key: "rule", Value: a.RuleID}, {Key: "title", Value: a.Title}})
}

// Resolve closes an alert with a note.
func Resolve(tx *store.TenantTx, id string, note string, by Actor, now time.Time) (*store.Alert, error) {
	note = strings.TrimSpace(note)
	if len(note) > 1000 {
		return nil, refuse(422, "invalid_note", "the note is at most 1000 characters")
	}
	a, err := liveAlert(tx, id)
	if err != nil {
		return nil, err
	}
	if a.Status == "resolved" {
		return nil, refuse(409, "already_resolved", "the alert is already resolved")
	}
	a.Status, a.ResolvedBy, a.ResolvedAt = "resolved", &by.UserID, &now
	if note != "" {
		a.Resolution = &note
	}
	if err := tx.SaveAlertState(a); err != nil {
		return nil, err
	}
	return a, tx.Audit(now, by.Display, "alert.resolved", ojson.Object{{Key: "alert_id", Value: a.ID},
		{Key: "rule", Value: a.RuleID}, {Key: "title", Value: a.Title}, {Key: "resolution", Value: note}})
}

// Assign gives a live alert to a user of the tenant (nil: nobody).
func Assign(tx *store.TenantTx, id string, assignee *string, by Actor, now time.Time) (*store.Alert, error) {
	a, err := liveAlert(tx, id)
	if err != nil {
		return nil, err
	}
	if a.Status == "resolved" {
		return nil, refuse(409, "already_resolved", "the alert is resolved")
	}
	if assignee != nil {
		uid, err := uuid.Parse(*assignee)
		if err != nil {
			return nil, refuse(404, "user_not_found", "the assignee was not found")
		}
		u, err := tx.PlatformUser(uid)
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(404, "user_not_found", "the assignee was not found")
		} else if err != nil {
			return nil, err
		}
		if u.Status != "active" {
			return nil, refuse(409, "user_not_active", "the assignee is disabled")
		}
	}
	a.AssigneeUserID = assignee
	if err := tx.SaveAlertState(a); err != nil {
		return nil, err
	}
	return a, tx.Audit(now, by.Display, "alert.assigned", ojson.Object{{Key: "alert_id", Value: a.ID},
		{Key: "rule", Value: a.RuleID}, {Key: "assignee_user_id", Value: assignee}})
}

// RuleSpec is a tenant's settings for a rule.
type RuleSpec struct {
	Enabled       bool
	Severity      string
	Threshold     int
	WindowMinutes int
}

// CheckRule validates a tenant's settings for the built-in rule id (404
// rule_not_found, 422 for a bad value). SetRule and the configuration import
// (internal/transport) both apply it.
func CheckRule(id string, s RuleSpec) error {
	r := RuleByID(id)
	if r == nil {
		return refuse(404, "rule_not_found", "no rule %q", id)
	}
	if !slices.Contains(Severities, s.Severity) {
		return refuse(422, "invalid_severity", "severity is low, medium, high or critical")
	}
	if s.Threshold < 1 || s.Threshold > 10000 {
		return refuse(422, "invalid_threshold", "the threshold is 1 to 10000")
	}
	if s.WindowMinutes < 1 || s.WindowMinutes > 10080 {
		return refuse(422, "invalid_window", "the window is 1 minute to 7 days")
	}
	return nil
}

// SetRule stores a tenant's settings for a built-in rule.
func SetRule(tx *store.TenantTx, id string, s RuleSpec, by Actor, now time.Time) error {
	if err := CheckRule(id, s); err != nil {
		return err
	}
	if err := tx.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: id, Enabled: s.Enabled, Severity: s.Severity,
		Threshold: s.Threshold, WindowMinutes: s.WindowMinutes, UpdatedBy: &by.UserID, UpdatedAt: now}); err != nil {
		return err
	}
	return tx.Audit(now, by.Display, "alert.rule.updated", ojson.Object{{Key: "rule", Value: id},
		{Key: "enabled", Value: s.Enabled}, {Key: "severity", Value: s.Severity}, {Key: "threshold", Value: s.Threshold},
		{Key: "window_minutes", Value: s.WindowMinutes}})
}
