package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Provisioning pushes to private-network targets through a remote agent (issue
// #302). A target whose settings name an agent (Settings.AgentID) is one the
// server cannot dial. For its operations the engine does not call the target:
// it queues a provision_push job addressed to (tenant, agent), leaves the
// operation "sent", and the agent, which pulls over its mutual-TLS channel,
// applies the change from inside the network, re-reads the target and reports
// the outcome. That report finishes the operation (FinishVerified,
// FinishMismatch or FinishFailed) in the transaction that finishes the job and
// audits it, so the operation, the job and the audit trail never disagree.

// agentJobAttempts is how many times an agent job is handed out before it
// fails for good (the agent crashed, lost the network or the target errored).
const agentJobAttempts = 3

// errAgentGone fails an operation whose target's agent is revoked or missing.
var errAgentGone = errors.New("the agent that reaches this target is revoked or no longer exists")

// agentOf returns the agent that reaches the connection's target ("" when the
// server calls it directly). Results are cached for the pass.
func (e *Engine) agentOf(ctx context.Context, t tenancy.ID, connID string, cache map[string]string) (string, error) {
	if id, ok := cache[connID]; ok {
		return id, nil
	}
	var pt *store.ProvTarget
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) (err error) {
		pt, err = tx.ProvTarget(connID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return "", nil // process reports the missing target
	}
	if err != nil {
		return "", err
	}
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return "", target.Permanent("target settings are unreadable: %v", err)
	}
	cache[connID] = s.AgentID
	return s.AgentID, nil
}

// dispatch queues the agent job of an operation the engine just claimed
// (status sent). It is idempotent: an operation that already has an open job is
// left with it, and its attempt is given back.
func (e *Engine) dispatch(ctx context.Context, t tenancy.ID, op *store.ProvOp, agentID string, st *Stats) error {
	var permanent error
	err := e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := e.now()
		a, err := tx.DirectoryAgent(agentID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && a.Status != store.AgentActive) {
			permanent = errAgentGone
			return nil
		}
		if err != nil {
			return err
		}
		if open, err := tx.HasOpenAgentJobForOp(op.ID); err != nil {
			return err
		} else if open {
			// the agent has not finished (it may be away): keep waiting, spend no attempt
			return tx.SetProvOpState(op.ID, Sent, store.ProvOpState{Status: Sent, Attempts: max(0, op.Attempts-1),
				VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, LastError: sp("waiting for the agent")}, now)
		}
		pt, err := tx.ProvTarget(op.ConnectionID)
		if err != nil {
			return err
		}
		req, err := Request(op)
		if err != nil {
			permanent = err
			return nil
		}
		var s Settings
		if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
			permanent = fmt.Errorf("target settings are unreadable: %w", err)
			return nil
		}
		spec := target.PushSpec{OpID: op.ID, Target: pt.Kind, BaseURL: pt.BaseURL, Dialect: s.Dialect, Op: req.Kind, Key: req.Key,
			Account: req.Account, Group: req.Group}
		if err := spec.Validate(); err != nil {
			permanent = fmt.Errorf("this target cannot be pushed through an agent: %w", err)
			return nil
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		// one job per dispatch: a retried operation (attempts start again) needs a new job, and the open-job
		// check above, in this transaction, is what keeps a pass from queueing two
		key := fmt.Sprintf("push:%s:%s", op.ID, store.NewID())
		job := &store.AgentJob{AgentID: agentID, ConnectionID: op.ConnectionID, Kind: store.AgentJobProvisionPush, OpID: &op.ID,
			Payload: string(raw), IdempotencyKey: &key, MaxAttempts: agentJobAttempts}
		if _, err := tx.EnqueueAgentJob(job, now); err != nil {
			return err
		}
		// the operation stays "sent": the agent holds it now
		if err := tx.SetProvOpState(op.ID, Sent, store.ProvOpState{Status: Sent, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, LastError: nil}, now); err != nil {
			return err
		}
		return tx.Audit(now, WorkerActor, "provision.dispatched", ojson.Object{{Key: "op_id", Value: op.ID},
			{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "agent_id", Value: agentID},
			{Key: "job_id", Value: job.ID}, {Key: "attempts", Value: op.Attempts}})
	})
	if err != nil {
		return err
	}
	if permanent != nil {
		return e.fail(ctx, t, op, target.Permanent("%v", permanent), st)
	}
	return nil
}

// ---------------------------------------------------------------- outcomes

// Inflight reports whether an operation in this status can still be finished
// by an agent's report: it is out with an agent (sent), was queued again while
// the agent was away, or is waiting for its re-read.
func inflightForAgent(status string) bool {
	return status == Sent || status == Queued || status == PendingVerification
}

// InFlightForAgent is inflightForAgent for callers outside the package.
func InFlightForAgent(op *store.ProvOp) bool { return inflightForAgent(op.Status) }

func via(agent string) ojson.Object {
	if agent == "" {
		return nil
	}
	return ojson.Object{{Key: "via_agent", Value: agent}}
}

// FinishVerified marks an operation verified, runs its completion and resolves
// its findings, in tx, with the provision.verified audit event. agentID, when
// set, names the agent that did the work (audited as via_agent). A completion
// that cannot be applied returns a *CompletionError and leaves tx unusable:
// the caller rolls back.
func FinishVerified(tx *store.TenantTx, now time.Time, op *store.ProvOp, observed, agentID string) error {
	if op.Completion != nil {
		if err := runCompletion(tx, now, *op.Completion); err != nil {
			return &CompletionError{Err: err}
		}
	}
	if err := tx.SetProvOpState(op.ID, op.Status, store.ProvOpState{Status: Verified, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, Observed: sp(observed), CompletedAt: &now}, now); err != nil {
		return err
	}
	if _, err := tx.ResolveProvFindings(op.ID, now); err != nil {
		return err
	}
	return tx.Audit(now, WorkerActor, "provision.verified", append(ojson.Object{{Key: "op_id", Value: op.ID},
		{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "attempts", Value: op.Attempts},
		{Key: "observed", Value: observed}}, via(agentID)...))
}

// CompletionError: the target shows the change but Tessera could not apply its
// side of it (the graph changed under the completion).
type CompletionError struct{ Err error }

func (e *CompletionError) Error() string {
	return "verified in the target but Tessera could not apply the change: " + e.Err.Error()
}
func (e *CompletionError) Unwrap() error { return e.Err }

// FinishMismatch ends an operation whose re-read never showed the change, and
// raises a finding, in tx, with the provision.mismatch audit event.
func FinishMismatch(tx *store.TenantTx, now time.Time, op *store.ProvOp, v target.Verdict, agentID string) error {
	severity := "medium"
	if op.Kind == target.DisableAccount || op.Kind == target.DeleteAccount || op.Kind == target.RemoveEntitlement {
		severity = "high" // the access that should be gone is still there
	}
	msg := "the target does not show the change: expected " + v.Expected + ", observed " + v.Observed
	if err := tx.SetProvOpState(op.ID, op.Status, store.ProvOpState{Status: Mismatch, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, LastError: sp(msg), Observed: sp(v.Observed), CompletedAt: &now}, now); err != nil {
		return err
	}
	f := &store.ProvFinding{ID: store.NewID(), OpID: op.ID, ConnectionID: op.ConnectionID, Code: "verify_mismatch",
		Severity: severity, Title: fmt.Sprintf("Target did not apply %s for %s", strings.ReplaceAll(op.Kind, "_", " "), op.TargetRef),
		Expected: v.Expected, Observed: v.Observed}
	if err := tx.InsertProvFinding(f, now); err != nil {
		return err
	}
	return tx.Audit(now, WorkerActor, "provision.mismatch", append(ojson.Object{{Key: "op_id", Value: op.ID},
		{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "status", Value: Mismatch},
		{Key: "attempts", Value: op.Attempts}, {Key: "finding_id", Value: f.ID}, {Key: "expected", Value: v.Expected},
		{Key: "observed", Value: v.Observed}}, via(agentID)...))
}

// FinishFailed ends an operation that can no longer succeed: its completion
// never runs, so the item it was for stays open. In tx, with provision.failed.
func FinishFailed(tx *store.TenantTx, now time.Time, op *store.ProvOp, cause, agentID string) error {
	if err := tx.SetProvOpState(op.ID, op.Status, store.ProvOpState{Status: Failed, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, LastError: sp(cause), CompletedAt: &now}, now); err != nil {
		return err
	}
	return tx.Audit(now, WorkerActor, "provision.failed", append(ojson.Object{{Key: "op_id", Value: op.ID},
		{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "status", Value: Failed},
		{Key: "attempts", Value: op.Attempts}, {Key: "error", Value: cause}}, via(agentID)...))
}
