package readiness

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Drift, Degraded and template upgrades (design §7.4, §7.5, DR-9).
//
// On activation Tessera stores a baseline of the live revision (score, item
// states, finding counts, object counts, config hash). Every scheduled
// re-run is then compared with it. Drift is information; Degraded is the
// consequence: a live revision moves to degraded when a Required live check
// fails on two consecutive scheduled runs, its credential is within 7 days of
// expiry, sync has failed for over 24 hours, the change cursor was lost three
// times in 7 days, or a new Required template item passes its grace period.
// While degraded, reads continue and write-back stops (CanWrite, RequireWrite).

// Tolerances and thresholds.
const (
	FindingTolerancePct   = 10 // finding counts: beyond ±10% or ±FindingToleranceMin objects, whichever is larger
	FindingToleranceMin   = 25
	ObjectTolerancePct    = 5 // object counts between consecutive runs: beyond ±5%
	CredentialDriftDays   = 30
	CredentialDegradeDays = 7
	DegradeAfterRuns      = 2 // consecutive scheduled runs with a failing Required live check
	CursorLossLimit       = 3 // change-cursor losses within 7 days
	SyncFailureLimit      = 24 * time.Hour
	UpgradeGrace          = 30 * 24 * time.Hour // new Required template items: drift, then Degraded
)

// SchedulerActor is the actor of scheduled re-runs. Only its runs count
// towards the consecutive-failure rule: an administrator's on-demand re-run
// is evidence but cannot degrade a connection by itself.
const SchedulerActor = "readiness.scheduler"

// Drift kinds.
const (
	DriftNewFailing = "new_failing_check"
	DriftFindings   = "finding_count"
	DriftObjects    = "object_count"
	DriftExpiring   = "credential_expiry"
	DriftTemplate   = "template_update"
	DriftExternal   = "external_change"
)

// externalChecks read the service account's effective rights: a newly
// failing one means someone changed the account outside Tessera (for example
// granted it a write permission).
var externalChecks = []string{"effective_rights", "ad_effective_rights", "ad_svc_groups", "ad_replication_rights",
	"app_admin_roles", "subject_roles", "write_scope"}

// FindingDrift reports whether a finding count moved beyond tolerance: more
// than 10% or 25 objects, whichever is larger.
func FindingDrift(was, now int) bool {
	d := absInt(now - was)
	return d > FindingToleranceMin && d*100 > was*FindingTolerancePct
}

// ObjectDrift reports whether an object count moved by more than 5% between
// two consecutive runs. Without a previous count (zero) there is nothing to compare.
func ObjectDrift(prev, now int) bool {
	return prev > 0 && absInt(now-prev)*100 > prev*ObjectTolerancePct
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// DriftEvent is one deviation from the baseline.
type DriftEvent struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // high | medium | low
	Subject  string `json:"subject"`  // item id, finding code, object class or template pin
	Sentence string `json:"sentence"`
	Was      *int   `json:"was,omitempty"`
	Now      *int   `json:"now,omitempty"`
}

func ip(n int) *int { return &n }

// BaselineSnapshot is what a baseline remembers of a revision (stored as JSON).
type BaselineSnapshot struct {
	Score      int               `json:"score"`
	Template   string            `json:"template"`
	ConfigHash string            `json:"config_hash"`
	Items      map[string]string `json:"items"`    // applicable Required and Recommended item → status
	Findings   map[string]int    `json:"findings"` // finding code and variant → count (not resolved)
	Counts     DryRunCounts      `json:"counts"`
}

type itemObs struct {
	Status, Level string
	External      bool
}

// Observation is the revision as the latest evidence shows it.
type Observation struct {
	Items          map[string]itemObs
	Findings       map[string]int
	Counts         DryRunCounts
	CredentialDays *int // days left on the credential (the cred_expiry check), when known
}

// countsMark remembers the object counts of the latest reconciliation run and
// of the one before it, so drift between consecutive runs survives a restart.
type countsMark struct {
	RunID    string        `json:"run_id"`
	Counts   DryRunCounts  `json:"counts"`
	Previous *DryRunCounts `json:"previous,omitempty"`
}

func parseMark(s *string) *countsMark {
	if s == nil {
		return nil
	}
	var m countsMark
	if json.Unmarshal([]byte(*s), &m) != nil {
		return nil
	}
	return &m
}

// advance records a new reconciliation run's counts (nothing when runID is the one already recorded).
func (m *countsMark) advance(runID string, cur DryRunCounts) *countsMark {
	switch {
	case runID == "":
		return m
	case m == nil:
		return &countsMark{RunID: runID, Counts: cur}
	case m.RunID == runID:
		return m
	}
	prev := m.Counts
	return &countsMark{RunID: runID, Counts: cur, Previous: &prev}
}

// previous is the counts the run runID is compared with.
func (m *countsMark) previous(runID string) *DryRunCounts {
	switch {
	case m == nil:
		return nil
	case m.RunID == runID:
		return m.Previous
	}
	return &m.Counts
}

func (m *countsMark) String() *string {
	if m == nil {
		return nil
	}
	raw, _ := json.Marshal(m) // plain struct
	s := string(raw)
	return &s
}

var severityOrder = map[string]int{"high": 0, "medium": 1, "low": 2}

// Compare lists how an observation deviates from the baseline. prev holds
// the object counts of the run before the latest one (nil when unknown).
func Compare(base *BaselineSnapshot, prev *DryRunCounts, cur *Observation) []DriftEvent {
	var out []DriftEvent
	for id, o := range cur.Items {
		if o.Status != StatusFail || base.Items[id] == StatusFail {
			continue
		}
		kind, what := DriftNewFailing, "newly failing"
		if o.External {
			kind, what = DriftExternal, "changed outside Tessera"
		}
		sev := "medium"
		if o.Level == string(template.Required) {
			sev = "high"
		}
		out = append(out, DriftEvent{Kind: kind, Severity: sev, Subject: id,
			Sentence: fmt.Sprintf("%s is %s (it passed or was not failing at activation).", id, what)})
	}
	for key := range unionKeys(base.Findings, cur.Findings) {
		was, now := base.Findings[key], cur.Findings[key]
		if FindingDrift(was, now) {
			out = append(out, DriftEvent{Kind: DriftFindings, Severity: "medium", Subject: key, Was: ip(was), Now: ip(now),
				Sentence: fmt.Sprintf("Finding %s moved from %d to %d since activation, beyond the %d%% / %d object tolerance.",
					key, was, now, FindingTolerancePct, FindingToleranceMin)})
		}
	}
	if prev != nil {
		for _, c := range []struct {
			name      string
			was, then int
		}{{"accounts", prev.Accounts, cur.Counts.Accounts}, {"groups", prev.Groups, cur.Counts.Groups},
			{"memberships", prev.Memberships, cur.Counts.Memberships}} {
			if ObjectDrift(c.was, c.then) {
				out = append(out, DriftEvent{Kind: DriftObjects, Severity: "medium", Subject: c.name, Was: ip(c.was), Now: ip(c.then),
					Sentence: fmt.Sprintf("The %s count moved from %d to %d between consecutive runs (more than %d%%): a scope or permission change?",
						c.name, c.was, c.then, ObjectTolerancePct)})
			}
		}
	}
	if d := cur.CredentialDays; d != nil && *d <= CredentialDriftDays {
		sev := "medium"
		if *d <= CredentialDegradeDays {
			sev = "high"
		}
		out = append(out, DriftEvent{Kind: DriftExpiring, Severity: sev, Subject: "credential", Now: d,
			Sentence: fmt.Sprintf("The credential expires in %d days.", *d)})
	}
	sortEvents(out)
	return out
}

func unionKeys(a, b map[string]int) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func sortEvents(es []DriftEvent) {
	sort.SliceStable(es, func(i, j int) bool {
		if a, b := severityOrder[es[i].Severity], severityOrder[es[j].Severity]; a != b {
			return a < b
		}
		if es[i].Kind != es[j].Kind {
			return es[i].Kind < es[j].Kind
		}
		return es[i].Subject < es[j].Subject
	})
}

// ---------------------------------------------------------------- template upgrades

// TemplateUpgrade is a newer release of a live revision's template (§3.5):
// a minor release that adds Required items starts a 30-day grace period,
// after which the connection is degraded until a new revision (which pins the
// current template and passes its gates) replaces the live one. A major
// release always needs a new revision and has no grace clock.
type TemplateUpgrade struct {
	Pin         string   `json:"pin"`
	Available   string   `json:"available"`
	Major       bool     `json:"major"`
	NewRequired []string `json:"new_required"`
	NewOther    int      `json:"new_other"`
	FirstSeen   *string  `json:"first_seen_at,omitempty"`
	GraceEnds   *string  `json:"grace_ends_at,omitempty"`
	Overdue     bool     `json:"overdue"`
}

// upgradeOf compares a pinned template with the current release. seen is
// when the release was first noticed (nil: now). It returns nil when the
// pinned template is current.
func upgradeOf(pinned, latest *template.Resolved, seen *time.Time, now time.Time) *TemplateUpgrade {
	_, pmaj, pmin, err1 := template.ParsePin(pinned.Pin())
	_, lmaj, lmin, err2 := template.ParsePin(latest.Pin())
	if err1 != nil || err2 != nil || lmaj < pmaj || (lmaj == pmaj && lmin <= pmin) {
		return nil
	}
	up := &TemplateUpgrade{Pin: pinned.Pin(), Available: latest.Pin(), Major: lmaj > pmaj, NewRequired: []string{}}
	for _, it := range latest.Items {
		if _, ok := pinned.Item(it.ID); ok {
			continue
		}
		if it.Level == template.Required {
			up.NewRequired = append(up.NewRequired, it.ID)
		} else {
			up.NewOther++
		}
	}
	if up.Major || len(up.NewRequired) == 0 {
		return up
	}
	first := now
	if seen != nil {
		first = *seen
	}
	end := first.Add(UpgradeGrace)
	f, e := store.RT(first), store.RT(end)
	up.FirstSeen, up.GraceEnds, up.Overdue = &f, &e, !now.Before(end)
	return up
}

// templateUpgrade evaluates the upgrade of a live bundle and records when the
// release was first seen in bl (the caller persists it).
func (s *Service) templateUpgrade(b *Bundle, bl *store.Baseline, now time.Time) *TemplateUpgrade {
	latest, ok := s.Templates.Get(b.Template.ID)
	if !ok {
		return nil
	}
	var seen *time.Time
	if bl.UpgradePin != nil && *bl.UpgradePin == latest.Pin() {
		seen = bl.UpgradeSeenAt
	}
	up := upgradeOf(b.Template, latest, seen, now)
	switch {
	case up == nil:
		bl.UpgradePin, bl.UpgradeSeenAt = nil, nil
	case seen == nil && up.FirstSeen != nil:
		pin := latest.Pin()
		t := now
		bl.UpgradePin, bl.UpgradeSeenAt = &pin, &t
	}
	return up
}

func upgradeEvent(up *TemplateUpgrade) *DriftEvent {
	if up == nil || up.Major || len(up.NewRequired) == 0 {
		return nil
	}
	e := &DriftEvent{Kind: DriftTemplate, Severity: "medium", Subject: up.Available,
		Sentence: fmt.Sprintf("Template %s adds %d Required item(s): %s. Create a revision on the new template before %s.",
			up.Available, len(up.NewRequired), strings.Join(up.NewRequired, ", "), *up.GraceEnds)}
	if up.Overdue {
		e.Severity = "high"
		e.Sentence = fmt.Sprintf("Template %s added %d Required item(s) (%s) and the 30-day grace period ended on %s.",
			up.Available, len(up.NewRequired), strings.Join(up.NewRequired, ", "), *up.GraceEnds)
	}
	return e
}

// ---------------------------------------------------------------- degraded

// ExternalSignals are the Degraded triggers measured outside this package
// (the sync loop reports them; nothing records them yet, so the scheduler
// passes the zero value).
type ExternalSignals struct {
	SyncFailedSince *time.Time // sync has been failing since
	CursorLosses7d  int        // times the change cursor was lost in the last 7 days
}

// Signals is everything the Degraded rules read.
type Signals struct {
	ExternalSignals
	FailStreak     int      // consecutive scheduled runs with a failing Required live check
	FailingItems   []string // the Required live items failing now
	CredentialDays *int
	Upgrade        *TemplateUpgrade
}

// DegradeReasons lists why a live revision must be degraded (§7.5); empty
// means it may stay active (or recover).
func DegradeReasons(sig Signals, now time.Time) []string {
	var out []string
	if sig.FailStreak >= DegradeAfterRuns && len(sig.FailingItems) > 0 {
		out = append(out, fmt.Sprintf("Required live check failed on %d consecutive scheduled runs: %s",
			sig.FailStreak, strings.Join(sig.FailingItems, ", ")))
	}
	if d := sig.CredentialDays; d != nil && *d <= CredentialDegradeDays {
		out = append(out, fmt.Sprintf("the credential expires in %d days (within %d)", *d, CredentialDegradeDays))
	}
	if t := sig.SyncFailedSince; t != nil && now.Sub(*t) > SyncFailureLimit {
		out = append(out, "sync has failed for more than 24 hours")
	}
	if sig.CursorLosses7d >= CursorLossLimit {
		out = append(out, fmt.Sprintf("the change cursor was lost %d times in 7 days", sig.CursorLosses7d))
	}
	if up := sig.Upgrade; up != nil && up.Overdue {
		out = append(out, fmt.Sprintf("template %s adds Required items (%s) and its grace period ended",
			up.Available, strings.Join(up.NewRequired, ", ")))
	}
	return out
}

// RequireWrite is the server-side gate of write-back: nil only when CanWrite
// holds, otherwise a 409 that says why. Callers that apply changes through a
// connection must call it in the transaction that applies them.
func (s *Service) RequireWrite(c *store.TenantTx, connID string) error {
	ok, err := s.CanWrite(c, connID)
	if err != nil || ok {
		return err
	}
	conn, live, _, err := Revisions(c, connID)
	if err != nil {
		return err
	}
	switch {
	case conn.RetiredAt != nil:
		return conflict("connection_retired", "connection %s is retired", conn.Name)
	case live == nil:
		return conflict("not_live", "connection %s has no live revision", conn.Name)
	case live.State == store.StateDegraded:
		return conflict("connection_degraded", "write-back through %s is stopped while it is degraded; reads continue", conn.Name)
	}
	return conflict("write_not_enabled", "connection %s is not in scoped write mode", conn.Name)
}

// ---------------------------------------------------------------- baseline and monitoring

func failingRequiredLive(b *Bundle) []string {
	var out []string
	for _, it := range b.Eval.Items {
		if !it.Applicable || it.Level != template.Required || !it.HasKind(template.Live) || it.Status == StatusSkipped {
			continue
		}
		if st, _, _ := it.partsOf(template.Live); st == StatusFail {
			out = append(out, it.ID)
		}
	}
	return out
}

func intOf(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	}
	return 0, false
}

// observe summarises a revision's current evidence for drift.
func (s *Service) observe(c *store.TenantTx, b *Bundle) (*Observation, error) {
	o := &Observation{Items: map[string]itemObs{}, Findings: map[string]int{}}
	for _, it := range b.Eval.Items {
		if !it.Applicable || it.Level == template.Optional {
			continue
		}
		ob := itemObs{Status: it.Status, Level: string(it.Level)}
		for _, v := range it.Verify {
			if v.Kind == template.Live && slices.Contains(externalChecks, v.Check) {
				ob.External = true
			}
		}
		o.Items[it.ID] = ob
	}
	for _, f := range b.Evidence.Findings {
		if f.Status != "resolved" {
			o.Findings[f.Code+f.Variant] += f.Count
		}
	}
	var err error
	// No reconciliation row means no counts (simulated evidence in tests), not a failure.
	if o.Counts, err = dryRunCounts(c, b); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	for k, r := range b.Evidence.Live {
		if k.check != "cred_expiry" || (r.Status != "pass" && r.Status != "fail") {
			continue
		}
		if d, ok := intOf(r.Observed["expires_in_days"]); ok && (o.CredentialDays == nil || d < *o.CredentialDays) {
			o.CredentialDays = ip(d)
		}
	}
	return o, nil
}

func (s *Service) snapshotOf(c *store.TenantTx, b *Bundle) (*BaselineSnapshot, error) {
	o, err := s.observe(c, b)
	if err != nil {
		return nil, err
	}
	snap := &BaselineSnapshot{Score: s.ConnectionScore(b).Score, Template: b.Rev.TemplateID + "@" + b.Rev.TemplateVersion,
		ConfigHash: b.ConfigHash, Items: map[string]string{}, Findings: o.Findings, Counts: o.Counts}
	for id, it := range o.Items {
		snap.Items[id] = it.Status
	}
	return snap, nil
}

// captureBaseline stores the baseline of a revision that just became live.
// It is a no-op when the revision already has one.
func (s *Service) captureBaseline(c *store.TenantTx, b *Bundle, now time.Time) (*store.Baseline, error) {
	snap, err := s.snapshotOf(c, b)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	bl := &store.Baseline{RevisionID: b.Rev.ID, CapturedAt: now, Score: snap.Score, ConfigHash: b.ConfigHash, Snapshot: string(raw)}
	if b.Evidence.DataRun != nil {
		bl.LastCounts = (&countsMark{RunID: b.Evidence.DataRun.ID, Counts: snap.Counts}).String()
	}
	if err := c.InsertBaseline(bl); errors.Is(err, store.ErrDuplicate) {
		return c.Baseline(b.Rev.ID)
	} else if err != nil {
		return nil, err
	}
	return bl, c.Audit(now, "system", "readiness.baseline.captured", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "score", Value: snap.Score}, {Key: "config_hash", Value: b.ConfigHash}})
}

// baselineOf returns a live revision's baseline, capturing it first when the
// revision was activated before baselines existed. created reports a capture.
func (s *Service) baselineOf(c *store.TenantTx, b *Bundle, now time.Time) (bl *store.Baseline, created bool, err error) {
	bl, err = c.Baseline(b.Rev.ID)
	if errors.Is(err, store.ErrNotFound) {
		bl, err = s.captureBaseline(c, b, now)
		return bl, true, err
	}
	return bl, false, err
}

// MonitorResult is what one monitoring pass found.
type MonitorResult struct {
	ConnectionID string
	State        string
	Drift        []DriftEvent
	Reasons      []string // why the revision is (or must be) degraded
	Degraded     bool     // moved active → degraded in this pass
	Recovered    bool     // moved degraded → active in this pass
}

// Monitor evaluates a connection's live revision after a scheduled re-run:
// it counts the latest scheduled run towards the consecutive-failure rule
// (once), compares the evidence with the baseline, checks credential expiry
// and the template grace period, and degrades or recovers the revision. It
// writes only when something changed, and audits what it writes. A revision
// is recovered only if Monitor degraded it. Other revisions are untouched.
func (s *Service) Monitor(c *store.TenantTx, connID string, ext ExternalSignals, now time.Time) (*MonitorResult, error) {
	_, live, _, err := Revisions(c, connID)
	if err != nil || live == nil {
		return nil, err
	}
	b, err := s.Load(c, live, now)
	if err != nil {
		return nil, err
	}
	bl, created, err := s.baselineOf(c, b, now)
	if err != nil {
		return nil, err
	}
	before := *bl
	obs, err := s.observe(c, b)
	if err != nil {
		return nil, err
	}
	run, err := c.LatestLiveRun(live.ID)
	if err != nil {
		return nil, err
	}
	failing := failingRequiredLive(b)
	if run != nil && run.Status == "completed" && run.ActorID == SchedulerActor && (bl.LastRunID == nil || *bl.LastRunID != run.ID) {
		if len(failing) > 0 {
			bl.FailStreak++
		} else {
			bl.FailStreak = 0
		}
		id := run.ID
		bl.LastRunID, bl.LastRunAt = &id, run.FinishedAt
	}
	mark := parseMark(bl.LastCounts)
	var dataRun string
	if b.Evidence.DataRun != nil {
		dataRun = b.Evidence.DataRun.ID
	}
	events, up, err := s.driftOf(b, bl, obs, mark.previous(dataRun), now)
	if err != nil {
		return nil, err
	}
	bl.LastCounts = mark.advance(dataRun, obs.Counts).String()
	reasons := DegradeReasons(Signals{ExternalSignals: ext, FailStreak: bl.FailStreak, FailingItems: failing,
		CredentialDays: obs.CredentialDays, Upgrade: up}, now)
	res := &MonitorResult{ConnectionID: connID, State: live.State, Drift: events, Reasons: reasons}
	switch {
	case live.State == store.StateActive && len(reasons) > 0:
		reason := strings.Join(reasons, "; ")
		if err := s.Degrade(c, connID, reason, now); err != nil {
			return nil, err
		}
		t := now
		bl.DegradedReason, bl.DegradedAt = &reason, &t
		res.State, res.Degraded = store.StateDegraded, true
	case live.State == store.StateDegraded && len(reasons) == 0 && bl.DegradedReason != nil:
		if err := s.Recover(c, connID, "every degraded condition cleared", now); err != nil {
			return nil, err
		}
		bl.DegradedReason, bl.DegradedAt = nil, nil
		res.State, res.Recovered = store.StateActive, true
	}
	if !created && reflect.DeepEqual(before, *bl) {
		return res, nil
	}
	if err := c.UpdateBaselineMonitor(bl); err != nil {
		return nil, err
	}
	return res, c.Audit(now, "system", "readiness.drift.evaluated", ojson.Object{{Key: "connection_id", Value: connID},
		{Key: "revision_id", Value: live.ID}, {Key: "state", Value: res.State}, {Key: "drift_events", Value: len(events)},
		{Key: "fail_streak", Value: bl.FailStreak}})
}

// driftOf compares an observation with a baseline and adds the template
// upgrade. It records the upgrade's first-seen time in bl.
func (s *Service) driftOf(b *Bundle, bl *store.Baseline, obs *Observation, prev *DryRunCounts, now time.Time) ([]DriftEvent, *TemplateUpgrade, error) {
	var base BaselineSnapshot
	if err := json.Unmarshal([]byte(bl.Snapshot), &base); err != nil {
		return nil, nil, fmt.Errorf("readiness: baseline of revision %s: %w", bl.RevisionID, err)
	}
	events := Compare(&base, prev, obs)
	up := s.templateUpgrade(b, bl, now)
	if e := upgradeEvent(up); e != nil {
		events = append(events, *e)
		sortEvents(events)
	}
	if events == nil {
		events = []DriftEvent{}
	}
	return events, up, nil
}

// ---------------------------------------------------------------- views

// BaselineView is the activation baseline as the API returns it.
type BaselineView struct {
	CapturedAt string `json:"captured_at"`
	Score      int    `json:"score"`
	ConfigHash string `json:"config_hash"`
	Findings   int    `json:"findings"`
	Accounts   int    `json:"accounts"`
	Groups     int    `json:"groups"`
}

// ScorePoint is one point of a connection's score series.
type ScorePoint struct {
	At    string `json:"at"`
	Score int    `json:"score"`
}

// DriftView is a live connection compared with its baseline (GET
// /api/connections/{id}/health, and one row of the dashboard's drift list).
type DriftView struct {
	ConnectionID   string           `json:"connection_id"`
	ConnectionName string           `json:"connection_name"`
	RevisionID     string           `json:"revision_id"`
	State          string           `json:"state"`
	Baseline       BaselineView     `json:"baseline"`
	Score          int              `json:"score"`
	Accounts       int              `json:"accounts"`
	Groups         int              `json:"groups"`
	Findings       int              `json:"findings"`
	Events         []DriftEvent     `json:"events"`
	Upgrade        *TemplateUpgrade `json:"template_upgrade"`
	FailStreak     int              `json:"fail_streak"`
	DegradedReason string           `json:"degraded_reason,omitempty"`
	DegradedAt     *string          `json:"degraded_at,omitempty"`
	LastRunAt      *string          `json:"last_scheduled_run_at,omitempty"`
	Series         []ScorePoint     `json:"score_series"` // since activation, oldest first; the UI picks the 7, 30 or 90 day window
}

// DriftBrief is the drift column of the connections table.
type DriftBrief struct {
	Events  int  `json:"events"`
	High    int  `json:"high"`
	Upgrade bool `json:"template_update"`
}

func (v *DriftView) brief() *DriftBrief {
	d := &DriftBrief{Events: len(v.Events), Upgrade: v.Upgrade != nil}
	for _, e := range v.Events {
		if e.Severity == "high" {
			d.High++
		}
	}
	return d
}

// Drift compares a live bundle with its baseline without writing. It returns
// nil for a revision that is not live or has no baseline yet (the first
// scheduled run captures one for revisions activated before baselines existed).
func (s *Service) Drift(c *store.TenantTx, b *Bundle, now time.Time) (*DriftView, error) {
	if !IsLive(b.Rev.State) {
		return nil, nil
	}
	bl, err := c.Baseline(b.Rev.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	obs, err := s.observe(c, b)
	if err != nil {
		return nil, err
	}
	cp := *bl // the view must not record the upgrade's first-seen time
	var dataRun string
	if b.Evidence.DataRun != nil {
		dataRun = b.Evidence.DataRun.ID
	}
	events, up, err := s.driftOf(b, &cp, obs, parseMark(bl.LastCounts).previous(dataRun), now)
	if err != nil {
		return nil, err
	}
	var base BaselineSnapshot
	if err := json.Unmarshal([]byte(bl.Snapshot), &base); err != nil {
		return nil, err
	}
	v := &DriftView{ConnectionID: b.Conn.ID, ConnectionName: b.Conn.Name, RevisionID: b.Rev.ID, State: b.Rev.State,
		Baseline: BaselineView{CapturedAt: store.RT(bl.CapturedAt), Score: bl.Score, ConfigHash: bl.ConfigHash,
			Findings: sumCounts(base.Findings), Accounts: base.Counts.Accounts, Groups: base.Counts.Groups},
		Score: s.ConnectionScore(b).Score, Accounts: obs.Counts.Accounts, Groups: obs.Counts.Groups, Findings: sumCounts(obs.Findings),
		Events: events, Upgrade: up, FailStreak: bl.FailStreak, Series: []ScorePoint{}}
	if bl.DegradedReason != nil {
		v.DegradedReason = *bl.DegradedReason
	}
	if bl.DegradedAt != nil {
		t := store.RT(*bl.DegradedAt)
		v.DegradedAt = &t
	}
	if bl.LastRunAt != nil {
		t := store.RT(*bl.LastRunAt)
		v.LastRunAt = &t
	}
	rows, err := c.ScoreSeries("connection", &b.Conn.ID, 200)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.RevisionID != nil && *r.RevisionID == b.Rev.ID && !r.ComputedAt.Before(bl.CapturedAt) {
			v.Series = append(v.Series, ScorePoint{At: store.RT(r.ComputedAt), Score: r.Score})
		}
	}
	return v, nil
}

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// ---------------------------------------------------------------- Inbox tasks

// Task is an Inbox task raised by deployment readiness (source "connection",
// §7.5): a degraded connection, for its technical owner and the admins.
type Task struct {
	ID             string  `json:"id"`
	Kind           string  `json:"kind"` // connection
	ConnectionID   string  `json:"connection_id"`
	ConnectionName string  `json:"connection_name"`
	Owner          *string `json:"owner"` // the connection's technical owner
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Reason         string  `json:"reason"`
	Since          string  `json:"since"`
	Href           string  `json:"href"`
}

// Tasks lists the Inbox tasks of the tenant: one per degraded connection.
func (s *Service) Tasks(c *store.TenantTx, now time.Time) ([]Task, error) {
	conns, err := c.Connections()
	if err != nil {
		return nil, err
	}
	out := []Task{}
	for _, conn := range conns {
		if conn.RetiredAt != nil || conn.ActiveRevisionID == nil {
			continue
		}
		rev, err := c.Revision(*conn.ActiveRevisionID)
		if err != nil {
			return nil, err
		}
		if rev.State != store.StateDegraded {
			continue
		}
		t := Task{ID: "connection/" + conn.ID + "/degraded", Kind: "connection", ConnectionID: conn.ID, ConnectionName: conn.Name,
			Owner: conn.TechnicalOwner, Severity: "high", Title: conn.Name + " is degraded", Since: store.RT(rev.UpdatedAt),
			Reason: "write-back is stopped; reads continue", Href: "/admin/connections/" + conn.ID}
		switch bl, err := c.Baseline(rev.ID); {
		case err == nil && bl.DegradedReason != nil:
			t.Reason = *bl.DegradedReason
			if bl.DegradedAt != nil {
				t.Since = store.RT(*bl.DegradedAt)
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// scheduleInfo describes the re-run schedule for the dashboard.
func (s *Service) scheduleInfo() map[string]string {
	o := s.Runner.withDefaults()
	return map[string]string{"live_checks": every(o.LiveEvery), "reconciliation": every(o.ReconEvery),
		"job": JobRerun, "note": "scheduled live checks, post-activation reconciliation and drift run in the background job " + JobRerun}
}

func every(d time.Duration) string {
	switch days := int(d / (24 * time.Hour)); days {
	case 1:
		return "daily"
	case 7:
		return "weekly"
	default:
		return fmt.Sprintf("every %d days", days)
	}
}
