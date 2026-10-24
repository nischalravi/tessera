package readiness

import (
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Blocker is one reason a transition is refused. The API returns the same
// structure the UI renders (§4.4).
type Blocker struct {
	Item     string `json:"item,omitempty"`
	Finding  string `json:"finding,omitempty"`
	Level    string `json:"level,omitempty"`
	Severity string `json:"severity,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

// GateReport is the result of evaluating a gate. It is stored with every
// successful transition and returned with every refused one.
type GateReport struct {
	Error       string    `json:"error,omitempty"`
	State       string    `json:"state"`
	To          string    `json:"to"`
	Blocking    []Blocker `json:"blocking"`
	ConfigHash  string    `json:"config_hash"`
	EvaluatedAt string    `json:"evaluated_at"`
}

// Blocks reports whether the gate refused the transition.
func (g *GateReport) Blocks() bool { return len(g.Blocking) > 0 }

// Gate evaluates the gate for moving the revision to state to (§4.2). Gates
// are cumulative: a later state's gate includes every earlier one, and every
// condition is re-evaluated from stored evidence, never cached.
func (b *Bundle) Gate(to string, now time.Time) *GateReport {
	g := &GateReport{State: b.Rev.State, To: to, Blocking: []Blocker{}, ConfigHash: b.ConfigHash,
		EvaluatedAt: store.RT(now)}
	seen := map[string]bool{}
	add := func(x Blocker) {
		k := x.Item + "|" + x.Finding
		if !seen[k] {
			seen[k] = true
			g.Blocking = append(g.Blocking, x)
		}
	}
	steps := map[string]int{store.StateReadyToValidate: 1, store.StateValidated: 2, store.StateDryRunReconciled: 3, store.StateActive: 4}
	n := steps[to]
	if n >= 1 {
		b.gateReady(add)
	}
	if n >= 2 {
		b.gateValidated(add, now)
	}
	if n >= 3 {
		b.gateReconciled(add)
	}
	if n >= 4 {
		b.gateActive(add)
	}
	return g
}

func blockerFor(it *ItemEval, status, reason string) Blocker {
	if reason == "" {
		reason = it.Reason
	}
	if reason == "" {
		reason = it.Remediation.Hint
	}
	return Blocker{Item: it.ID, Level: string(it.Level), Status: status, Reason: reason}
}

// draft → ready_to_validate: typed config valid, credential present, and
// every applicable Required attestation-only item attested for the current
// config (items still waiting on a dependency are checked at activation).
func (b *Bundle) gateReady(add func(Blocker)) {
	for _, fe := range ValidateConn(b.Config, b.Template, b.Conn.ConnectorType) {
		add(Blocker{Item: "config." + fe.Field, Status: "invalid", Reason: fe.Msg})
	}
	if b.Rev.SecretRef == nil && (!govLive(b) || needsSecret(b.Conn.ConnectorType)) {
		add(Blocker{Item: "credential", Status: "missing", Reason: "set a credential or a vault reference"})
	}
	for _, it := range b.Eval.Items {
		if !it.Applicable || it.Level != template.Required || !it.OnlyAttestation() || len(it.BlockedBy) > 0 {
			continue
		}
		if st, reason, _ := it.partsOf(template.Attestation); st != StatusPass {
			add(blockerFor(it, st, reason))
		}
	}
}

// ready_to_validate → validated: a validation run finished within the live
// TTL, and every applicable Required live check passes. Freshness against the
// config is judged per item (§4.5): each result is bound to the hash of the
// fields its item depends on, so editing the sync schedule does not
// invalidate the TLS evidence, but editing the host does.
func (b *Bundle) gateValidated(add func(Blocker), now time.Time) {
	run := b.Evidence.LiveRun
	switch {
	case run == nil:
		add(Blocker{Item: "validation", Status: StatusPending, Reason: "run validation"})
	case run.Status != "completed":
		add(Blocker{Item: "validation", Status: run.Status, Reason: "the last validation run did not complete"})
	case run.FinishedAt != nil && now.Sub(*run.FinishedAt) > b.LiveTTL:
		add(Blocker{Item: "validation", Status: StatusStale, Reason: fmt.Sprintf("live evidence older than %s", fmtTTL(b.LiveTTL))})
	}
	for _, it := range b.Eval.Items {
		if !it.Applicable || it.Level != template.Required || !it.HasKind(template.Live) {
			continue
		}
		if len(it.LiveBlockedBy) > 0 {
			add(blockerFor(it, StatusBlocked, "blocked by "+joinIDs(it.LiveBlockedBy)))
			continue
		}
		if st, reason, _ := it.partsOf(template.Live); st != StatusPass {
			add(blockerFor(it, st, reason))
		}
	}
}

// validated → dry_run_reconciled: a dry run for the current config finished,
// every applicable Required data check passes, and no critical or high
// finding is open.
func (b *Bundle) gateReconciled(add func(Blocker)) {
	run := b.Evidence.DataRun
	switch {
	case run == nil:
		add(Blocker{Item: "dry_run", Status: StatusPending, Reason: "run a dry run"})
	case run.Status != "completed":
		add(Blocker{Item: "dry_run", Status: run.Status, Reason: "the last dry run did not complete"})
	case run.ConfigHash != b.ConfigHash:
		add(Blocker{Item: "dry_run", Status: StatusStale, Reason: "configuration changed since the last dry run"})
	}
	for _, it := range b.Eval.Items {
		if !it.Applicable || it.Level != template.Required || !it.HasKind(template.Data) {
			continue
		}
		if len(it.BlockedBy) > 0 {
			add(blockerFor(it, StatusBlocked, it.Reason))
			continue
		}
		if st, reason, _ := it.partsOf(template.Data); st != StatusPass {
			add(blockerFor(it, st, reason))
		}
	}
	for _, f := range b.Evidence.Findings {
		if f.Status == "open" && (f.Severity == "critical" || f.Severity == "high") {
			add(Blocker{Finding: f.Code + f.Variant, Severity: f.Severity, Status: "open", Reason: "acknowledge or resolve: " + f.Title})
		}
	}
}

// dry_run_reconciled → active: everything above, every applicable Required
// item passing in full, and every applicable Recommended item passing or
// skipped with a reason.
func (b *Bundle) gateActive(add func(Blocker)) {
	for _, it := range b.Eval.Items {
		if !it.Applicable {
			continue
		}
		switch it.Level {
		case template.Required:
			if it.Status != StatusPass {
				add(blockerFor(it, it.Status, ""))
			}
		case template.Recommended:
			if it.Status != StatusPass && it.Status != StatusSkipped {
				reason := it.Reason
				if it.Status == StatusPending || reason == "" {
					reason = "pass it, or skip it with a reason"
				}
				add(blockerFor(it, it.Status, reason))
			}
		}
	}
	if mode := writeMode(b.Config); mode != "off" {
		// An approval counts only for the exact revision, configuration and
		// mode it was given for (two-person activation, DR-10).
		if a := b.Evidence.Approval; a == nil || a.RevisionID != b.Rev.ID || a.ConfigHash != b.ConfigHash || a.WriteMode != mode {
			add(Blocker{Item: ApprovalItem, Status: StatusPending,
				Reason: "write-enabled connections need a second approver: request activation, then a different person approves it"})
		}
	}
}
