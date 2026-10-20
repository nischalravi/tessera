package sod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Violation statuses a mitigation gives (StatusOpen is in detect.go).
const (
	StatusMitigated = "mitigated"          // an approved control covers it until its end date
	StatusAccepted  = "accepted"           // the risk is accepted until its end date
	StatusPending   = "mitigation_pending" // a request is waiting for its second person; still open
)

// Defaults of Settings.
const (
	DefaultMaxMitigationDays = 365
	DefaultWarnDays          = 14
	MaxJustification         = 2000
	MaxEvidenceRefs          = 10
	MaxEvidenceRef           = 300
)

// Settings are the tenant's mitigation limits (configuration, not data).
type Settings struct {
	MaxDays  int // a mitigation ends within this many days of its request
	WarnDays int // owners are warned this many days before it ends
}

// WithDefaults fills unset limits.
func (s Settings) WithDefaults() Settings {
	if s.MaxDays <= 0 {
		s.MaxDays = DefaultMaxMitigationDays
	}
	if s.WarnDays <= 0 {
		s.WarnDays = DefaultWarnDays
	}
	return s
}

// MitigationInput asks to cover an identity's violation of a risk.
type MitigationInput struct {
	RiskID        string
	IdentityID    int64
	Kind          string // store.MitigationControl or store.MitigationAccept
	ControlID     string
	Justification string
	EndsAt        time.Time
	Evidence      []string
}

func mitigationDetail(m *store.SodMitigation) ojson.Object {
	d := ojson.Object{{Key: "mitigation_id", Value: m.ID}, {Key: "risk_id", Value: m.RiskID}, {Key: "identity_id", Value: m.IdentityID},
		{Key: "kind", Value: m.Kind}, {Key: "status", Value: m.Status}, {Key: "ends_at", Value: timeutil.ISO(m.EndsAt)}}
	if m.ControlID != nil {
		d = append(d, ojson.KV{Key: "control_id", Value: *m.ControlID})
	}
	return d
}

// RequestMitigation records a pending request to mitigate or accept a violation.
// Another person must approve it (DecideMitigation). The caller has checked that
// the violation exists now.
func (w *Writer) RequestMitigation(in MitigationInput, set Settings) (*store.SodMitigation, error) {
	set = set.WithDefaults()
	in.Justification = clean(in.Justification)
	switch {
	case in.Kind != store.MitigationControl && in.Kind != store.MitigationAccept:
		return nil, refuse(422, "invalid_kind", "kind is control or accept")
	case in.Justification == "" || len(in.Justification) > MaxJustification:
		return nil, refuse(422, "justification_required", "a justification of 1 to %d characters is required", MaxJustification)
	case in.EndsAt.IsZero():
		return nil, refuse(422, "end_date_required", "an end date is required")
	case !in.EndsAt.After(w.Now):
		return nil, refuse(422, "invalid_end_date", "the end date must be in the future")
	case in.EndsAt.After(w.Now.Add(time.Duration(set.MaxDays) * 24 * time.Hour)):
		return nil, refuse(422, "end_date_too_far", "a mitigation can last at most %d days", set.MaxDays)
	case len(in.Evidence) > MaxEvidenceRefs:
		return nil, refuse(422, "invalid_evidence", "at most %d evidence references", MaxEvidenceRefs)
	}
	for i, e := range in.Evidence {
		in.Evidence[i] = clean(e)
		if in.Evidence[i] == "" || len(in.Evidence[i]) > MaxEvidenceRef {
			return nil, refuse(422, "invalid_evidence", "an evidence reference is 1 to %d characters", MaxEvidenceRef)
		}
	}
	if w.By.UserID == uuid.Nil {
		return nil, refuse(403, "user_required", "a mitigation is requested by a signed-in user")
	}
	risk, err := w.Tx.SodRisk(in.RiskID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "risk_not_found", "risk not found")
	} else if err != nil {
		return nil, err
	}
	if risk.Status != store.SodActive {
		return nil, refuse(409, "risk_retired", "%s is retired", risk.Name)
	}
	opts, err := RiskOptions(w.Tx, risk.ID)
	if err != nil {
		return nil, err
	}
	want := OptMitigate
	if in.Kind == store.MitigationAccept {
		want = OptAccept
	}
	if !Offers(opts, want) {
		return nil, refuse(409, "option_not_offered", "%s does not offer %q as a remediation", risk.Name, want)
	}
	if _, err := w.Tx.Identity(in.IdentityID); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "identity_not_found", "person not found")
	} else if err != nil {
		return nil, err
	}
	m := &store.SodMitigation{ID: uuid.NewString(), RiskID: risk.ID, IdentityID: in.IdentityID, Kind: in.Kind,
		Justification: in.Justification, Evidence: mustJSON(append([]string{}, in.Evidence...)), Status: store.MitigationPending,
		EndsAt: in.EndsAt.UTC(), RequestedBy: w.By.UserID.String(), RequestedAt: w.Now}
	if in.Kind == store.MitigationControl {
		c, err := w.Tx.SodControl(in.ControlID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(422, "control_required", "choose a control from the library")
		} else if err != nil {
			return nil, err
		}
		if c.Status != store.SodActive {
			return nil, refuse(409, "control_retired", "%s is retired", c.Name)
		}
		m.ControlID = &c.ID
	}
	if _, err := w.Tx.LiveSodMitigation(risk.ID, in.IdentityID); err == nil {
		return nil, refuse(409, "already_mitigated", "this violation already has a pending or active mitigation")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err := w.Tx.InsertSodMitigation(m); err != nil {
		return nil, err
	}
	return m, w.audit("sod.mitigation.request", mitigationDetail(m))
}

func (w *Writer) loadMitigation(id string) (*store.SodMitigation, error) {
	m, err := w.Tx.SodMitigation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "mitigation_not_found", "mitigation not found")
	}
	return m, err
}

func (w *Writer) saveMitigation(m *store.SodMitigation, from, action string, extra ...ojson.KV) (*store.SodMitigation, error) {
	if err := w.Tx.SaveSodMitigation(m, from); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "mitigation_changed", "the mitigation changed; reload it")
	} else if err != nil {
		return nil, err
	}
	return m, w.audit(action, append(mitigationDetail(m), extra...))
}

// DecideMitigation approves or rejects a pending mitigation. The person who
// decides must not be the one who requested it (four-eyes). A rejection needs a note.
func (w *Writer) DecideMitigation(id string, approve bool, note string) (*store.SodMitigation, error) {
	m, err := w.loadMitigation(id)
	if err != nil {
		return nil, err
	}
	note = clean(note)
	switch {
	case m.Status != store.MitigationPending:
		return nil, refuse(409, "not_pending", "the mitigation is %s, not pending", m.Status)
	case w.By.UserID == uuid.Nil:
		return nil, refuse(403, "user_required", "a mitigation is decided by a signed-in user")
	case w.By.UserID.String() == m.RequestedBy:
		return nil, refuse(403, "four_eyes", "another person must decide a mitigation you requested")
	case len(note) > MaxNote || (!approve && note == ""):
		return nil, refuse(422, "invalid_note", "a note of 1 to %d characters is required to reject", MaxNote)
	case approve && !m.EndsAt.After(w.Now):
		return nil, refuse(409, "end_date_passed", "the end date has passed; request it again")
	}
	by := w.By.UserID.String()
	m.DecidedBy, m.DecidedAt = &by, &w.Now
	if note != "" {
		m.DecisionNote = &note
	}
	action := "sod.mitigation.reject"
	if approve {
		m.Status, m.StartsAt = store.MitigationActive, &w.Now
		action = "sod.mitigation.approve"
	} else {
		m.Status, m.ClosedAt = store.MitigationRejected, &w.Now
	}
	return w.saveMitigation(m, store.MitigationPending, action)
}

// CancelMitigation withdraws a pending request; only its requester may.
func (w *Writer) CancelMitigation(id string) (*store.SodMitigation, error) {
	m, err := w.loadMitigation(id)
	if err != nil {
		return nil, err
	}
	switch {
	case m.Status != store.MitigationPending:
		return nil, refuse(409, "not_pending", "the mitigation is %s, not pending", m.Status)
	case w.By.UserID == uuid.Nil || w.By.UserID.String() != m.RequestedBy:
		return nil, refuse(403, "requester_only", "only the requester can withdraw a request")
	}
	m.Status, m.ClosedAt = store.MitigationCancelled, &w.Now
	return w.saveMitigation(m, store.MitigationPending, "sod.mitigation.cancel")
}

// RevokeMitigation ends an active mitigation early: the violation is open
// again. The caller has checked the person may (the risk owner, or an approver).
func (w *Writer) RevokeMitigation(id, reason string) (*store.SodMitigation, error) {
	m, err := w.loadMitigation(id)
	if err != nil {
		return nil, err
	}
	reason = clean(reason)
	switch {
	case m.Status != store.MitigationActive:
		return nil, refuse(409, "not_active", "the mitigation is %s, not active", m.Status)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	if w.By.UserID != uuid.Nil {
		by := w.By.UserID.String()
		m.RevokedBy = &by
	}
	m.Status, m.RevokeReason, m.ClosedAt = store.MitigationRevoked, &reason, &w.Now
	return w.saveMitigation(m, store.MitigationActive, "sod.mitigation.revoke", ojson.KV{Key: "reason", Value: reason})
}

// Escalate sends a violation to the risk owner, if the risk offers it.
func (w *Writer) Escalate(riskID string, identityID int64, note string) (*store.SodEscalation, error) {
	note = clean(note)
	risk, err := w.Tx.SodRisk(riskID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "risk_not_found", "risk not found")
	} else if err != nil {
		return nil, err
	}
	opts, err := RiskOptions(w.Tx, risk.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case risk.Status != store.SodActive:
		return nil, refuse(409, "risk_retired", "%s is retired", risk.Name)
	case !Offers(opts, OptEscalate):
		return nil, refuse(409, "option_not_offered", "%s does not offer %q as a remediation", risk.Name, OptEscalate)
	case risk.OwnerID == nil:
		return nil, refuse(409, "no_risk_owner", "%s has no owner to escalate to", risk.Name)
	case note == "" || len(note) > MaxNote:
		return nil, refuse(422, "invalid_note", "a note of 1 to %d characters is required", MaxNote)
	case w.By.UserID == uuid.Nil:
		return nil, refuse(403, "user_required", "a violation is escalated by a signed-in user")
	}
	who, err := w.Tx.Identity(identityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "identity_not_found", "person not found")
	} else if err != nil {
		return nil, err
	}
	e := &store.SodEscalation{ID: uuid.NewString(), RiskID: risk.ID, IdentityID: identityID, EscalatedBy: w.By.UserID.String(), Note: note, CreatedAt: w.Now}
	if err := w.Tx.InsertSodEscalation(e); err != nil {
		return nil, err
	}
	to, err := notify.Identity(w.Tx, *risk.OwnerID)
	if err != nil {
		return nil, err
	}
	if _, err := notify.SecurityAlert(w.Tx, w.Now, "sod.escalation:"+e.ID, "SoD violation escalated: "+risk.Name,
		fmt.Sprintf("%s holds both sides of %q. %s", who.Name, risk.Name, note), "/insights/sod", to...); err != nil {
		return nil, err
	}
	return e, w.audit("sod.violation.escalate", ojson.Object{{Key: "risk_id", Value: risk.ID}, {Key: "identity_id", Value: identityID},
		{Key: "escalation_id", Value: e.ID}})
}

// ------------------------------------------------------------ cover

// Cover is what covers a violation right now.
type Cover struct {
	MitigationID string    `json:"mitigation_id"`
	Kind         string    `json:"kind"`
	Status       string    `json:"status"` // the violation status it gives
	Control      string    `json:"control,omitempty"`
	EndsAt       time.Time `json:"ends_at"`
	Label        string    `json:"label"`
}

// CoverIndex answers which live mitigation covers an identity's violation of a risk.
type CoverIndex map[string]*Cover

func coverKey(riskID string, identityID int64) string {
	return riskID + "|" + strconv.FormatInt(identityID, 10)
}

// For returns the cover of the violation, or nil.
func (c CoverIndex) For(riskID string, identityID int64) *Cover {
	return c[coverKey(riskID, identityID)]
}

// Covers indexes the pending and active mitigations at now. An active one whose
// end date has passed no longer covers, whether or not the sweeper has closed it yet.
func Covers(tx *store.TenantTx, now time.Time) (CoverIndex, error) {
	ms, err := tx.SodMitigations()
	if err != nil {
		return nil, err
	}
	controls, err := tx.SodControls()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, c := range controls {
		names[c.ID] = c.Name
	}
	out := CoverIndex{}
	for _, m := range ms {
		if m.Status != store.MitigationPending && m.Status != store.MitigationActive {
			continue
		}
		c := &Cover{MitigationID: m.ID, Kind: m.Kind, EndsAt: m.EndsAt}
		if m.ControlID != nil {
			c.Control = names[*m.ControlID]
		}
		switch {
		case m.Status == store.MitigationPending:
			c.Status, c.Label = StatusPending, "Mitigation requested"
			if m.Kind == store.MitigationAccept {
				c.Label = "Acceptance requested"
			}
		case !m.EndsAt.After(now):
			continue
		case m.Kind == store.MitigationAccept:
			c.Status, c.Label = StatusAccepted, "Accepted until "+m.EndsAt.UTC().Format("2006-01-02")
		default:
			c.Status, c.Label = StatusMitigated, "Mitigated until "+m.EndsAt.UTC().Format("2006-01-02")
		}
		out[coverKey(m.RiskID, m.IdentityID)] = c
	}
	return out, nil
}

// Closes reports whether a status takes a violation out of the open counts.
func Closes(status string) bool { return status == StatusMitigated || status == StatusAccepted }

// Apply sets each violation's status and cover from the index.
func (c CoverIndex) Apply(vs []Violation) {
	for i := range vs {
		if cv := c.For(vs[i].RiskID, vs[i].IdentityID); cv != nil {
			vs[i].Status, vs[i].Mitigation = cv.Status, cv
		}
	}
}

// ------------------------------------------------------------ sweep

// Sweeper is the actor of the mitigation sweep's events.
const Sweeper = "sod.sweeper"

// Sweep warns about mitigations ending within set.WarnDays (the control's owner
// and the person's manager, once each) and closes the ones whose end date has
// passed: the violation is open again, the risk and control owners are told, and
// the audit ledger records it. It returns how many it warned about and expired.
func Sweep(tx *store.TenantTx, now time.Time, set Settings) (warned, expired int, err error) {
	set = set.WithDefaults()
	ms, err := tx.SodMitigations()
	if err != nil {
		return 0, 0, err
	}
	w := &Writer{Tx: tx, By: Actor{Display: Sweeper}, Now: now}
	for _, m := range ms {
		if m.Status != store.MitigationActive {
			continue
		}
		risk, err := tx.SodRisk(m.RiskID)
		if err != nil {
			return warned, expired, err
		}
		who, err := tx.Identity(m.IdentityID)
		if err != nil {
			return warned, expired, err
		}
		var control *store.SodControl
		if m.ControlID != nil {
			if control, err = tx.SodControl(*m.ControlID); err != nil {
				return warned, expired, err
			}
		}
		what := fmt.Sprintf("The mitigation of %s for %s", risk.Name, who.Name)
		if m.Kind == store.MitigationAccept {
			what = fmt.Sprintf("The acceptance of %s for %s", risk.Name, who.Name)
		}
		if !m.EndsAt.After(now) {
			from := m.Status
			m.Status, m.ClosedAt = store.MitigationExpired, &now
			if _, err := w.saveMitigation(m, from, "sod.mitigation.expire", ojson.KV{Key: "reopened", Value: true}); err != nil {
				return warned, expired, err
			}
			var to []notify.Recipient
			for _, id := range []*int64{risk.OwnerID, ownerOf(control)} {
				if id == nil {
					continue
				}
				r, err := notify.Identity(tx, *id)
				if err != nil {
					return warned, expired, err
				}
				to = append(to, r...)
			}
			if _, err := notify.SecurityAlert(tx, now, "sod.mitigation.expired:"+m.ID, "SoD violation open again: "+risk.Name,
				what+" ended on "+m.EndsAt.UTC().Format("2006-01-02")+". The violation is open again.", "/insights/sod", to...); err != nil {
				return warned, expired, err
			}
			expired++
			continue
		}
		if m.WarnedAt != nil || m.EndsAt.After(now.Add(time.Duration(set.WarnDays)*24*time.Hour)) {
			continue
		}
		var tell []int64
		if control != nil && control.OwnerID != nil {
			tell = append(tell, *control.OwnerID)
		} else if risk.OwnerID != nil {
			tell = append(tell, *risk.OwnerID)
		}
		if who.ManagerID != nil {
			tell = append(tell, *who.ManagerID)
		}
		if len(tell) > 0 {
			if _, err := notify.Expiring(tx, now, notify.Ending{Key: "sod-mitigation:" + m.ID, IdentityID: tell[0], Also: tell[1:],
				What: what, EndsAt: m.EndsAt, Link: "/governance/mitigations"}); err != nil {
				return warned, expired, err
			}
		}
		m.WarnedAt = &now
		from := m.Status
		if _, err := w.saveMitigation(m, from, "sod.mitigation.warn"); err != nil {
			return warned, expired, err
		}
		warned++
	}
	return warned, expired, nil
}

func ownerOf(c *store.SodControl) *int64 {
	if c == nil {
		return nil
	}
	return c.OwnerID
}

// EvidenceRefs decodes a mitigation's evidence references.
func EvidenceRefs(m *store.SodMitigation) []string {
	var out []string
	if json.Unmarshal([]byte(m.Evidence), &out) != nil || out == nil {
		return []string{}
	}
	return out
}

// SweepAll runs Sweep for every active tenant in its own transaction (the
// background sweeper).
func SweepAll(ctx context.Context, db *store.DB, now time.Time, set Settings) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		_, _, err := Sweep(tx, now, set)
		return err
	})
}
