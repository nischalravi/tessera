package helpdesk

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// maxReasons bounds the reasons one case shows.
const maxReasons = 10

// SettingsLimits are the bounds of the recent authentication method window.
const (
	MinRecentDays = 1
	MaxRecentDays = 90
)

// ValidAction reports whether a is a recent authentication method action.
func ValidAction(a string) bool {
	return a == store.HelpdeskRecentOff || a == store.HelpdeskRecentRequireApproval || a == store.HelpdeskRecentBlock
}

func ago(now, t time.Time) string {
	d := int(now.Sub(t).Hours() / 24)
	switch {
	case d <= 0:
		return "today"
	case d == 1:
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", d)
}

func clip(s string, n int) string {
	if r := []rune(strings.TrimSpace(s)); len(r) > n {
		return string(r[:n])
	}
	return strings.TrimSpace(s)
}

// RecentAuthFor applies the tenant's recent authentication method rule to an
// identity (issue #477): it looks, within the tenant's window, for a method
// the identity registered (the MFA posture's enrolled_at, read from the IdPs),
// an MFA device added signal, and a risk signal a connected IdP reported (an
// Entra suspicious authentication method detection). It returns nil when the
// rule is off. A method whose enrolment date the IdP does not report cannot be
// dated, so it never triggers: unknown is not recent. Only labels and kinds
// are read, never a factor value.
func RecentAuthFor(c *store.TenantTx, identityID int64, now time.Time) (*RecentAuth, error) {
	st, err := c.HelpdeskSettings()
	if err != nil {
		return nil, err
	}
	if st.RecentMethodAction == store.HelpdeskRecentOff {
		return nil, nil
	}
	since := now.Add(-time.Duration(st.RecentMethodDays) * 24 * time.Hour)
	recent := func(t time.Time) bool { return !t.Before(since) && !t.After(now.Add(5*time.Minute)) }
	type hit struct {
		at     time.Time
		reason string
	}
	var hits []hit
	methods, err := c.AuthMethodsOfIdentity(identityID)
	if err != nil {
		return nil, err
	}
	for _, m := range methods {
		if m.EnrolledAt != nil && recent(*m.EnrolledAt) {
			what := m.Kind
			if l := clip(m.Label, 60); l != "" {
				what += " " + l
			}
			hits = append(hits, hit{*m.EnrolledAt, fmt.Sprintf("%s method %q added %s", m.System, clip(what, 80), ago(now, *m.EnrolledAt))})
		}
	}
	signals, err := c.HelpdeskSignals(identityID)
	if err != nil {
		return nil, err
	}
	for _, g := range signals {
		if g.Kind == SignalMFADevice && recent(g.OccurredAt) {
			hits = append(hits, hit{g.OccurredAt, fmt.Sprintf("MFA device added signal %s", ago(now, g.OccurredAt))})
		}
	}
	risks, err := c.HelpdeskIdPRisks(identityID)
	if err != nil {
		return nil, err
	}
	for _, r := range risks {
		if r.DismissedAt == nil && recent(r.OccurredAt) {
			hits = append(hits, hit{r.OccurredAt, fmt.Sprintf("%s reported a suspicious authentication method %s", riskReporter(r), ago(now, r.OccurredAt))})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at.After(hits[j].at) })
	out := &RecentAuth{Action: st.RecentMethodAction, Days: st.RecentMethodDays, Reasons: []string{}}
	for _, h := range hits {
		if len(out.Reasons) == maxReasons {
			break
		}
		out.Reasons = append(out.Reasons, h.reason)
	}
	return out, nil
}

// riskReporter says who a risk signal came from. Source is a label the poster typed, so it is shown as the
// poster's own claim: the person who posted it is the real attribution (issue #510).
func riskReporter(r *store.HelpdeskIdPRisk) string {
	label := clip(r.Source, 60)
	if r.SubmittedBy == "" {
		if label == "" {
			return "a risk signal (poster not recorded)"
		}
		return fmt.Sprintf("a risk signal (poster not recorded; source label %q is unverified)", label)
	}
	if label == "" {
		return "reported by " + clip(r.SubmittedBy, 60) + " (manual)"
	}
	return fmt.Sprintf("reported by %s (manual; source label %q is unverified)", clip(r.SubmittedBy, 60), label)
}

// SettingsInput is the recent authentication method rule's settings.
type SettingsInput struct {
	Days   int
	Action string
}

// UpdateSettings saves the tenant's recent authentication method settings and
// audits the change with the old and the new values.
func (s *Service) UpdateSettings(c *store.TenantTx, in SettingsInput, by store.UserRef, now time.Time) (*store.HelpdeskSettings, error) {
	if in.Days < MinRecentDays || in.Days > MaxRecentDays {
		return nil, fail(CodeInvalid, "recent_method_days must be between %d and %d", MinRecentDays, MaxRecentDays)
	}
	if !ValidAction(in.Action) {
		return nil, fail(CodeInvalid, "recent_method_action must be off, require_approval or block")
	}
	old, err := c.HelpdeskSettings()
	if err != nil {
		return nil, err
	}
	next := &store.HelpdeskSettings{RecentMethodDays: in.Days, RecentMethodAction: in.Action}
	if err := c.PutHelpdeskSettings(next, actorName(by), now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actorName(by), "helpdesk.settings.updated", ojson.Object{
		{Key: "recent_method_days", Value: in.Days}, {Key: "recent_method_action", Value: in.Action},
		{Key: "was_days", Value: old.RecentMethodDays}, {Key: "was_action", Value: old.RecentMethodAction}}); err != nil {
		return nil, err
	}
	return c.HelpdeskSettings()
}

// RiskInput is a risk signal a connected IdP reported for an identity.
type RiskInput struct {
	IdentityID int64
	Source     string
	Detail     string
	OccurredAt time.Time
}

// IngestRisk records that an IdP reported a suspiciously added authentication
// method for the identity (Entra's real-time detection). It can only make a
// reset stricter: while it is inside the tenant's window, the identity's cases
// need the extra approval, or are blocked. In production the IdP log connectors
// feed this; until they do, POST /api/helpdesk/risk-signals does, for an admin
// holding helpdesk.risk with step-up. The signal records who posted it: the
// source stays a free label and is shown as unverified. occurred_at must lie
// inside the window the rule looks at (never in the future, never older), so a
// signal cannot be backdated to block resets for longer, and a wrong one can
// be dismissed by a different admin (DismissRisk).
func (s *Service) IngestRisk(c *store.TenantTx, in RiskInput, by store.UserRef, now time.Time) (*store.HelpdeskIdPRisk, error) {
	src := strings.TrimSpace(in.Source)
	if src == "" || len(src) > 60 {
		return nil, fail(CodeInvalid, "source is required: at most 60 characters")
	}
	if len(in.Detail) > 200 {
		return nil, fail(CodeInvalid, "detail is at most 200 characters")
	}
	if in.OccurredAt.IsZero() || in.OccurredAt.After(now.Add(5*time.Minute)) {
		return nil, fail(CodeInvalid, "occurred_at is required and cannot be in the future")
	}
	st, err := c.HelpdeskSettings()
	if err != nil {
		return nil, err
	}
	if in.OccurredAt.Before(now.Add(-time.Duration(st.RecentMethodDays) * 24 * time.Hour)) {
		return nil, fail(CodeInvalid, "occurred_at is older than the rule's window (%d days)", st.RecentMethodDays)
	}
	if _, err := c.Identity(in.IdentityID); errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeNotFound, "identity not found")
	} else if err != nil {
		return nil, err
	}
	r := &store.HelpdeskIdPRisk{IdentityID: in.IdentityID, Kind: "auth_method_added", Source: src,
		Detail: strings.TrimSpace(in.Detail), OccurredAt: in.OccurredAt.UTC(), SubmittedBy: actorName(by), SubmittedByUser: userString(by)}
	if err := c.InsertHelpdeskIdPRisk(r, now); err != nil {
		return nil, err
	}
	return r, c.Audit(now, actorName(by), "helpdesk.risk_signal.ingested", ojson.Object{{Key: "identity_id", Value: in.IdentityID},
		{Key: "source_label_unverified", Value: src}, {Key: "risk_id", Value: r.ID}, {Key: "occurred_at", Value: r.OccurredAt}})
}

func userString(by store.UserRef) string {
	if by.ID == uuid.Nil {
		return ""
	}
	return by.ID.String()
}

// DismissRisk removes a risk signal's effect (a wrong or stale one). A different admin than the one who posted it
// must do it, with a reason; both are audited. The row stays, marked dismissed, so the record is kept.
func (s *Service) DismissRisk(c *store.TenantTx, id, reason string, by store.UserRef, now time.Time) (*store.HelpdeskIdPRisk, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 300 {
		return nil, fail(CodeInvalid, "reason is required: at most 300 characters")
	}
	if by.ID == uuid.Nil {
		return nil, forbid(ReasonOperatorRequired, "only a signed-in admin can dismiss a risk signal")
	}
	r, err := c.HelpdeskIdPRisk(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeNotFound, "risk signal not found")
	} else if err != nil {
		return nil, err
	}
	if r.DismissedAt != nil {
		return nil, fail(CodeConflict, "the risk signal is already dismissed")
	}
	if r.SubmittedByUser != "" && r.SubmittedByUser == by.ID.String() {
		return nil, forbid("different_admin_required", "a risk signal is dismissed by a different admin than the one who posted it")
	}
	if err := c.DismissHelpdeskIdPRisk(id, by.ID.String(), actorName(by), reason, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, actorName(by), "helpdesk.risk_signal.dismissed", ojson.Object{{Key: "risk_id", Value: id},
		{Key: "identity_id", Value: r.IdentityID}, {Key: "submitted_by", Value: r.SubmittedBy}, {Key: "reason", Value: reason}}); err != nil {
		return nil, err
	}
	return c.HelpdeskIdPRisk(id)
}
