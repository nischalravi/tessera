// Package alerts raises alerts from audit events and detections, and
// delivers them to email and webhook channels (issue #168).
//
// Rules are built in. Event rules match audit events (the ledger is the only
// input, so anything audited can alert); a rule fires when Threshold matching
// events with the same key fall within Window. Detection rules look at the
// current state on a slower cadence and resolve their alerts by themselves
// when the condition clears. A tenant can switch a rule off and change its
// severity, threshold and window (store.AlertRuleSetting).
//
// One alert is live per rule and key: repeats bump its count and last-seen
// time. Raising, acknowledging, assigning and resolving are audited
// (alert.*). Deliveries go through an outbox (alert_deliveries) and are
// retried with backoff; webhooks go out through internal/safehttp and are
// signed with the channel's sealed HMAC secret.
package alerts

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/certs"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/nhi"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// Severities, lowest first.
var Severities = []string{"low", "medium", "high", "critical"}

// SeverityRank orders severities (low 0 .. critical 3; unknown -1).
func SeverityRank(s string) int { return slices.Index(Severities, s) }

// Hit is one match of an event rule: the dedup key and the alert's title.
type Hit struct {
	Key   string
	Title string
}

// Finding is one current instance of a detection rule's condition. It
// alerts when Count (0 counts as 1) reaches the rule's threshold.
type Finding struct {
	Key    string
	Title  string
	Count  int
	Detail map[string]any
}

// Rule is a built-in alert rule.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Kind is "event", "detection" (run with the engine's detections) or
	// "scheduled" (run only by RunScheduled, from a durable queue job).
	Kind      string        `json:"kind"`
	Severity  string        `json:"severity"`
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"-"`
	// Match is an event rule's predicate.
	Match func(e *store.AuditEvent) (Hit, bool) `json:"-"`
	// Detect lists a detection rule's current findings.
	Detect func(tx *store.TenantTx, now time.Time) ([]Finding, error) `json:"-"`
}

// Rules are the built-in rules, in display order.
var Rules = []*Rule{
	{
		ID: "break_glass_used", Name: "Break-glass access used", Kind: "event", Severity: "critical", Threshold: 1, Window: time.Hour,
		Description: "A break-glass session started or a break-glass action ran.",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Action != "auth.break_glass.used" && e.Action != "breakglass.action" {
				return Hit{}, false
			}
			who := actorOf(e)
			return Hit{Key: who, Title: "Break-glass access used by " + who}, true
		},
	},
	{
		ID: "admin_role_granted", Name: "New administrator", Kind: "event", Severity: "high", Threshold: 1, Window: time.Hour,
		Description: "Someone was given an admin role (tenant_admin, policy_admin or break_glass).",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Outcome != store.OutcomeSuccess {
				return Hit{}, false
			}
			switch e.Action {
			case "auth.role.granted", "admin.role.granted", "admin.change.applied":
			default:
				return Hit{}, false
			}
			d := detailOf(e)
			role := str(d, "role")
			if role == "" && e.Action == "admin.change.applied" {
				// admin changes carry their payload; only role grants count
				if k := str(d, "kind"); !strings.HasPrefix(k, "role.grant") {
					return Hit{}, false
				}
				role = str(d, "target_role")
			}
			if role != "" && !slices.Contains([]string{"tenant_admin", "policy_admin", "break_glass"}, role) {
				return Hit{}, false
			}
			who := targetOf(e, d)
			return Hit{Key: who + "/" + role, Title: fmt.Sprintf("%s was made %s", who, orStr(role, "an administrator"))}, true
		},
	},
	{
		ID: "mfa_bypass", Name: "MFA bypassed", Kind: "event", Severity: "high", Threshold: 1, Window: time.Hour,
		Description: "A sign-in skipped or bypassed multi-factor authentication (#109).",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if !strings.HasPrefix(e.Action, "auth.mfa.bypass") {
				return Hit{}, false
			}
			who := targetOf(e, detailOf(e))
			return Hit{Key: who, Title: "MFA bypassed for " + who}, true
		},
	},
	{
		ID: "signin_failures", Name: "Repeated sign-in failures", Kind: "event", Severity: "medium", Threshold: 5,
		Window:      15 * time.Minute,
		Description: "Several failed sign-ins for the same account or from the same address in a short time.",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Action != "auth.login.failure" {
				return Hit{}, false
			}
			d := detailOf(e)
			key := orStr(str(d, "email"), str(d, "subject"), str(d, "login_hint"))
			if key == "" && e.IP != nil {
				key = "ip " + *e.IP
			}
			key = orStr(key, "unknown")
			return Hit{Key: key, Title: "Repeated sign-in failures: " + key}, true
		},
	},
	{
		ID: "deletion_held", Name: "Deletions held for approval", Kind: "event", Severity: "high", Threshold: 1, Window: time.Hour,
		Description: "The deletion threshold guard held deletions that passed a category's threshold; a second admin must release or discard them.",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Action != "deletion_guard.held" {
				return Hit{}, false
			}
			d := detailOf(e)
			key := orStr(str(d, "hold_id"), "hold")
			return Hit{Key: key, Title: fmt.Sprintf("Deletions held: %s of %s (%s)", orStr(str(d, "held"), "some"),
				orStr(str(d, "category"), "a category"), orStr(str(d, "source"), "a request"))}, true
		},
	},
	{
		ID: "provisioning_failed", Name: "Provisioning or sync job failed", Kind: "event", Severity: "high", Threshold: 1,
		Window:      time.Hour,
		Description: "A connector sync, connection job, lifecycle (JML) run or admin change failed.",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			// job.failed (internal/jobs) is itself the failure record, whatever its outcome
			failed := e.Action == "job.failed" || e.Outcome == store.OutcomeFailure || e.Outcome == store.OutcomeError
			if !failed {
				return Hit{}, false
			}
			ok := e.Action == "admin.change.failed" || e.Action == "job.failed"
			for _, p := range []string{"connectors.", "connection.", "jml.", "provisioning.", "readiness."} {
				ok = ok || strings.HasPrefix(e.Action, p)
			}
			if !ok {
				return Hit{}, false
			}
			key := e.Action
			if e.TargetID != nil {
				key += "/" + *e.TargetID
			}
			return Hit{Key: key, Title: "Job failed: " + e.Action}, true
		},
	},
	{
		ID: "access_drift", Name: "Access drift needs action", Kind: "event", Severity: "medium", Threshold: 1, Window: time.Hour,
		Description: "Reconciliation found access that differs from what was approved, and its remediation policy acted on it (#301).",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Action != "drift.remediate" || e.Outcome != store.OutcomeSuccess {
				return Hit{}, false
			}
			d := detailOf(e)
			return Hit{Key: orStr(str(d, "drift_id"), "drift"),
				Title: fmt.Sprintf("Access drift (%s) in %s: %s", orStr(str(d, "class"), "unknown"), orStr(str(d, "system"), "a system"), orStr(str(d, "action"), "acted on"))}, true
		},
	},
	{
		ID: "oauth_app_change", Name: "OAuth app credential or permission added", Kind: "event", Severity: "high", Threshold: 1, Window: time.Hour,
		Description: "A sync found a new secret or certificate on an OAuth app, a new application permission or tenant-wide consent, or an owner change (#474). Contain it from the OAuth apps panel.",
		Match: func(e *store.AuditEvent) (Hit, bool) {
			if e.Action != "oauthapps.change_detected" || e.Outcome != store.OutcomeSuccess {
				return Hit{}, false
			}
			d := detailOf(e)
			return Hit{Key: orStr(str(d, "change_id"), "change"), Title: orStr(str(d, "summary"), "An OAuth app changed")}, true
		},
	},
	{
		ID: "audit_anchor_failed", Name: "Audit anchoring failing", Kind: "detection", Severity: "critical", Threshold: 3,
		Description: "Audit checkpoints could not be anchored outside the database, so tampering might go unnoticed.",
		Detect: func(tx *store.TenantTx, _ time.Time) ([]Finding, error) {
			n, err := tx.FailedAuditAnchors()
			if err != nil || n == 0 {
				return nil, err
			}
			return []Finding{{Key: "anchoring", Title: fmt.Sprintf("%d audit checkpoints failed to anchor", n), Count: n,
				Detail: map[string]any{"failed_checkpoints": n}}}, nil
		},
	},
	{
		ID: "orphaned_privileged", Name: "Privileged identity without an owner", Kind: "detection", Severity: "high", Threshold: 1,
		Description: "A machine identity or agent holds privileged access and has no owner, or its owner has left.",
		Detect: func(tx *store.TenantTx, now time.Time) ([]Finding, error) {
			g, err := graph.Build(tx, now)
			if err != nil {
				return nil, err
			}
			u, err := usage.Build(tx, now)
			if err != nil {
				return nil, err
			}
			items, err := nhi.Inventory(tx, g, u)
			if err != nil {
				return nil, err
			}
			var out []Finding
			for _, it := range items {
				orphan := slices.Contains(it.Flags, "orphaned") || slices.Contains(it.Flags, "owner_left")
				if it.Status != "active" || it.PrivilegedPermissions == 0 || !orphan {
					continue
				}
				why := "has no owner"
				if slices.Contains(it.Flags, "owner_left") {
					why = "is owned by someone who left"
				}
				out = append(out, Finding{Key: fmt.Sprintf("identity:%d", it.ID),
					Title: fmt.Sprintf("%s holds privileged access and %s", it.Name, why),
					Detail: map[string]any{"identity_id": it.ID, "identity": it.Name, "type": it.Type,
						"privileged_permissions": it.PrivilegedPermissions, "flags": it.Flags}})
			}
			return out, nil
		},
	},
	{
		ID: "certificate_expiry", Name: "Certificate expiring", Kind: "scheduled", Severity: "high", Threshold: 1,
		Description: "A certificate Tessera holds (SAML SP key, uploaded or mTLS certificate) expires in 30 days or less; raised again in the last 7 days. Checked daily by the job queue.",
		Detect: func(tx *store.TenantTx, now time.Time) ([]Finding, error) {
			es, err := certs.Expiring(tx, now)
			if err != nil {
				return nil, err
			}
			var out []Finding
			for _, e := range es {
				b := certs.Bucket(now, *e.NotAfter)
				out = append(out, Finding{Key: fmt.Sprintf("%s:%dd", e.ID, b), Title: certs.ExpiryTitle(e, now),
					Detail: map[string]any{"certificate": e.ID, "label": e.Label, "purpose": e.Purpose, "used_by": e.UsedBy,
						"fingerprint": e.Fingerprint, "not_after": e.NotAfter.UTC().Format(time.RFC3339), "days_left": certs.DaysLeft(now, *e.NotAfter),
						"warning_days": b}})
			}
			return out, nil
		},
	},
}

// RuleByID returns a built-in rule, or nil.
func RuleByID(id string) *Rule {
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// Effective is a rule with a tenant's settings applied.
type Effective struct {
	*Rule
	Enabled   bool
	Severity  string
	Threshold int
	Window    time.Duration
	Setting   *store.AlertRuleSetting // nil: defaults
}

// EffectiveRules applies the tenant's settings to every built-in rule.
func EffectiveRules(tx *store.TenantTx) ([]Effective, error) {
	settings, err := tx.AlertRuleSettings()
	if err != nil {
		return nil, err
	}
	by := map[string]*store.AlertRuleSetting{}
	for _, s := range settings {
		by[s.RuleID] = s
	}
	out := make([]Effective, 0, len(Rules))
	for _, r := range Rules {
		e := Effective{Rule: r, Enabled: true, Severity: r.Severity, Threshold: r.Threshold, Window: r.Window}
		if s := by[r.ID]; s != nil {
			e.Enabled, e.Severity, e.Threshold, e.Window, e.Setting = s.Enabled, s.Severity, s.Threshold,
				time.Duration(s.WindowMinutes)*time.Minute, s
		}
		out = append(out, e)
	}
	return out, nil
}

func detailOf(e *store.AuditEvent) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(e.Detail, &m)
	return m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func orStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func actorOf(e *store.AuditEvent) string {
	if e.ActorDisplay != nil && *e.ActorDisplay != "" {
		return *e.ActorDisplay
	}
	if e.ActorID != nil {
		return *e.ActorID
	}
	return e.ActorType
}

func targetOf(e *store.AuditEvent, d map[string]any) string {
	if v := orStr(str(d, "user"), str(d, "email"), str(d, "target"), str(d, "subject")); v != "" {
		return v
	}
	if e.TargetID != nil {
		return *e.TargetID
	}
	return actorOf(e)
}
