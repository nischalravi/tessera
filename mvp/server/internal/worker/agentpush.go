package worker

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// AgentPush is the server side of provisioning pushes through a remote agent
// (issue #302): it gives the agent service the target's credential to seal to
// the agent, and finishes the provisioning operation with the agent's report.
// It is the agent.PushHooks of `tessera serve`.
type AgentPush struct {
	// Sealer opens the targets' stored credentials (the KEK).
	Sealer *seal.Sealer
}

var _ agent.PushHooks = (*AgentPush)(nil)

// Credential opens the credential of the target of the job's connection.
func (h *AgentPush) Credential(tx *store.TenantTx, j *store.AgentJob) (string, error) {
	pt, err := tx.ProvTarget(j.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return "", errors.New("the connection no longer has a provisioning target")
	}
	if err != nil {
		return "", err
	}
	if h.Sealer == nil {
		return "", errors.New("the server has no key to open the target's credential")
	}
	return provision.OpenCredential(h.Sealer, tx.Tenant(), pt)
}

// Done finishes the job's operation with the agent's outcome: verified (the
// completion runs and the graph changes), or mismatch (a finding). An
// operation that ended another way while the job was out (it cannot be
// cancelled while sent, but a stale one is queued again) is left as it is.
func (h *AgentPush) Done(tx *store.TenantTx, now time.Time, a *store.DirectoryAgent, j *store.AgentJob, res *agent.PushResult) (ojson.Object, error) {
	op, err := h.op(tx, j)
	if err != nil {
		return nil, err
	}
	if op == nil || !provision.InFlightForAgent(op) {
		status := "gone"
		if op != nil {
			status = op.Status
		}
		return ojson.Object{{Key: "op_id", Value: opID(j)}, {Key: "outcome", Value: "ignored"}, {Key: "operation_status", Value: status}}, nil
	}
	if !res.Applied {
		return nil, agent.ErrBadInput
	}
	if res.Verified {
		if err := provision.FinishVerified(tx, now, op, res.Observed, a.ID); err != nil {
			var ce *provision.CompletionError
			if errors.As(err, &ce) {
				return nil, &agent.PushApplyError{Err: err}
			}
			return nil, err
		}
		return ojson.Object{{Key: "op_id", Value: op.ID}, {Key: "outcome", Value: "verified"}}, nil
	}
	if err := provision.FinishMismatch(tx, now, op, target.Verdict{Expected: res.Expected, Observed: res.Observed}, a.ID); err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "op_id", Value: op.ID}, {Key: "outcome", Value: "mismatch"}}, nil
}

// Failed fails the job's operation when the job will not be tried again (and no
// other job of the operation is still open), with the reason.
func (h *AgentPush) Failed(tx *store.TenantTx, now time.Time, a *store.DirectoryAgent, j *store.AgentJob, msg string, final bool) error {
	if !final {
		return nil // the job is queued again; the operation keeps waiting
	}
	op, err := h.op(tx, j)
	if err != nil || op == nil || !provision.InFlightForAgent(op) {
		return err
	}
	if open, err := tx.HasOpenAgentJobForOp(op.ID); err != nil || open {
		return err
	}
	return provision.FinishFailed(tx, now, op, msg, a.ID)
}

func (h *AgentPush) op(tx *store.TenantTx, j *store.AgentJob) (*store.ProvOp, error) {
	if j.OpID == nil {
		return nil, nil
	}
	op, err := tx.ProvOp(*j.OpID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return op, err
}

func opID(j *store.AgentJob) string {
	if j.OpID == nil {
		return ""
	}
	return *j.OpID
}
