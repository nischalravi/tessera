package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Jobs that remote Directory Agents pull (schema/0461_agent_jobs.sql, issue
// #302). Every statement is scoped by tenant, and a claim, completion or
// failure is also scoped by agent id: the caller passes the id of the
// authenticated agent, never an id the agent sent.

// Agent job statuses.
const (
	AgentJobQueued    = "queued"
	AgentJobLeased    = "leased"
	AgentJobDone      = "done"
	AgentJobFailed    = "failed"
	AgentJobCancelled = "cancelled"
)

// Agent job kinds.
const (
	// AgentJobSync reads a connection's directory in the agent's network and
	// returns what it holds.
	AgentJobSync = "sync"
	// AgentJobProvisionPush carries out one provisioning operation (OpID) against a
	// target in the agent's network and returns the outcome (issue #302).
	AgentJobProvisionPush = "provision_push"
)

// AgentJob is one unit of work for one agent about one connection.
type AgentJob struct {
	ID             string
	AgentID        string
	ConnectionID   string
	Kind           string
	OpID           *string // the provisioning operation of a provision_push job
	Payload        string  // JSON, no secret
	IdempotencyKey *string
	Status         string
	Attempts       int
	MaxAttempts    int
	LeaseExpiresAt *time.Time
	LastError      string
	ResultSummary  *string // JSON, counts only
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     *time.Time
}

// AgentJobFilter narrows AgentJobs. Empty fields match everything.
type AgentJobFilter struct {
	AgentID, ConnectionID, Status string
	Limit                         int
}

const agentJobCols = `j.id, j.agent_id, j.connection_id, j.kind, j.op_id, j.payload, j.idempotency_key, j.status, j.attempts,
	j.max_attempts, j.lease_expires_at, j.last_error, j.result_summary, j.created_at, j.updated_at, j.finished_at`

// agentJobDue: waiting work, or leased work whose lease expired (the agent
// went away, or never answered).
const agentJobDue = `(status = 'queued' OR (status = 'leased' AND lease_expires_at <= @now))`

var (
	agentJobInsert = tq("agent_jobs.insert", `
		INSERT OR IGNORE INTO agent_jobs (id, tenant_id, agent_id, connection_id, kind, op_id, payload, idempotency_key, status,
			attempts, max_attempts, last_error, created_at, updated_at)
		VALUES (@id, @tenant, @agent_id, @connection_id, @kind, @op_id, @payload, @idempotency_key, 'queued', 0, @max_attempts,
			'', @now, @now)`)
	agentJobGet = tq("agent_jobs.get", `
		SELECT `+agentJobCols+` FROM agent_jobs j WHERE j.tenant_id = @tenant AND j.id = @id`)
	agentJobList = tq("agent_jobs.list", `
		SELECT `+agentJobCols+` FROM agent_jobs j
		WHERE j.tenant_id = @tenant AND (@agent_id = '' OR j.agent_id = @agent_id)
			AND (@connection_id = '' OR j.connection_id = @connection_id) AND (@status = '' OR j.status = @status)
		ORDER BY j.created_at DESC, j.id DESC LIMIT @limit`)
	agentJobCandidates = tq("agent_jobs.candidates", `
		SELECT `+agentJobCols+` FROM agent_jobs j
		WHERE j.tenant_id = @tenant AND j.agent_id = @agent_id AND `+agentJobDue+`
		ORDER BY j.created_at, j.id LIMIT @limit`)
	agentJobClaim = tq("agent_jobs.claim", `
		UPDATE agent_jobs SET status = 'leased', attempts = attempts + 1, lease_expires_at = @expires, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND agent_id = @agent_id AND `+agentJobDue)
	agentJobHasDue = tq("agent_jobs.has_due", `
		SELECT count(*) FROM agent_jobs j WHERE j.tenant_id = @tenant AND j.agent_id = @agent_id AND `+agentJobDue)
	agentJobBury = tq("agent_jobs.bury", `
		UPDATE agent_jobs SET status = 'failed', last_error = @error, lease_expires_at = NULL, finished_at = @now,
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND agent_id = @agent_id AND status = 'leased'`)
	agentJobComplete = tq("agent_jobs.complete", `
		UPDATE agent_jobs SET status = 'done', last_error = '', lease_expires_at = NULL, result_summary = @summary,
			finished_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND agent_id = @agent_id AND status = 'leased'`)
	agentJobFail = tq("agent_jobs.fail", `
		UPDATE agent_jobs SET status = @status, last_error = @error, lease_expires_at = NULL, finished_at = @finished_at,
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND agent_id = @agent_id AND status = 'leased'`)
	agentJobCancel = tq("agent_jobs.cancel", `
		UPDATE agent_jobs SET status = 'cancelled', lease_expires_at = NULL, last_error = 'the agent was revoked',
			finished_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND agent_id = @agent_id AND status IN ('queued','leased')`)
	agentJobOpen = tq("agent_jobs.open", `
		SELECT count(*) FROM agent_jobs j
		WHERE j.tenant_id = @tenant AND j.connection_id = @connection_id AND j.kind = @kind
			AND j.status IN ('queued','leased')`)
	agentJobOpenForOp = tq("agent_jobs.open_for_op", `
		SELECT count(*) FROM agent_jobs j
		WHERE j.tenant_id = @tenant AND j.op_id = @op_id AND j.status IN ('queued','leased')`)
	agentJobCancelForOp = tq("agent_jobs.cancel_for_op", `
		UPDATE agent_jobs SET status = 'cancelled', lease_expires_at = NULL, last_error = @reason, finished_at = @now,
			updated_at = @now
		WHERE tenant_id = @tenant AND op_id = @op_id AND status IN ('queued','leased')`)
	agentJobPrune = tq("agent_jobs.prune", `
		DELETE FROM agent_jobs WHERE tenant_id = @tenant AND status IN ('done','failed','cancelled') AND finished_at < @before`)
)

func scanAgentJob(s scanner) (*AgentJob, error) {
	var j AgentJob
	var key, lease, summary, fin, op sql.NullString
	var created, updated string
	if err := s.Scan(&j.ID, &j.AgentID, &j.ConnectionID, &j.Kind, &op, &j.Payload, &key, &j.Status, &j.Attempts,
		&j.MaxAttempts, &lease, &j.LastError, &summary, &created, &updated, &fin); err != nil {
		return nil, err
	}
	j.IdempotencyKey, j.ResultSummary, j.OpID = strp(key), strp(summary), strp(op)
	var err error
	if j.LeaseExpiresAt, err = rtp(lease); err != nil {
		return nil, err
	}
	if j.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if j.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	j.FinishedAt, err = rtp(fin)
	return &j, err
}

// EnqueueAgentJob adds a queued job (ID is set when empty). With an
// IdempotencyKey, a job with that key that already exists (in any status)
// makes this a no-op and created is false. The agent and the connection must
// be this tenant's (the schema refuses others).
func (tx *TenantTx) EnqueueAgentJob(j *AgentJob, now time.Time) (created bool, err error) {
	// checked here as well as by the schema: INSERT OR IGNORE swallows a CHECK violation on SQLite
	switch {
	case j.Kind != AgentJobSync && j.Kind != AgentJobProvisionPush:
		return false, fmt.Errorf("store: unknown agent job kind %q", j.Kind)
	case (j.Kind == AgentJobProvisionPush) != (j.OpID != nil):
		return false, errors.New("store: a provision_push agent job names its operation, a sync job does not")
	}
	if j.ID == "" {
		j.ID = NewID()
	}
	if j.MaxAttempts <= 0 {
		j.MaxAttempts = 3
	}
	res, err := tx.exec(agentJobInsert, sql.Named("id", j.ID), sql.Named("agent_id", j.AgentID),
		sql.Named("connection_id", j.ConnectionID), sql.Named("kind", j.Kind), sql.Named("op_id", SP(j.OpID)),
		sql.Named("payload", j.Payload),
		sql.Named("idempotency_key", SP(j.IdempotencyKey)), sql.Named("max_attempts", j.MaxAttempts),
		sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// AgentJob returns one job of the tenant or ErrNotFound.
func (tx *TenantTx) AgentJob(id string) (*AgentJob, error) {
	return one(tx, scanAgentJob, agentJobGet, sql.Named("id", id))
}

// AgentJobs lists jobs, newest first.
func (tx *TenantTx) AgentJobs(f AgentJobFilter) ([]*AgentJob, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 500
	}
	return collect(tx, scanAgentJob, agentJobList, sql.Named("agent_id", f.AgentID),
		sql.Named("connection_id", f.ConnectionID), sql.Named("status", f.Status), sql.Named("limit", f.Limit))
}

// HasOpenAgentJob reports whether the connection has a queued or leased job of
// the kind, so a schedule does not stack work behind an agent that is away.
func (tx *TenantTx) HasOpenAgentJob(connectionID, kind string) (bool, error) {
	var n int
	err := tx.queryRow(agentJobOpen, sql.Named("connection_id", connectionID), sql.Named("kind", kind)).Scan(&n)
	return n > 0, err
}

// HasOpenAgentJobForOp reports whether a provisioning operation already has a
// queued or leased agent job, so a pass of the engine never queues a second one.
func (tx *TenantTx) HasOpenAgentJobForOp(opID string) (bool, error) {
	var n int
	err := tx.queryRow(agentJobOpenForOp, sql.Named("op_id", opID)).Scan(&n)
	return n > 0, err
}

// CancelAgentJobsForOp cancels a provisioning operation's open agent jobs (the
// operation was cancelled or ended another way). It returns how many.
func (tx *TenantTx) CancelAgentJobsForOp(opID, reason string, now time.Time) (int64, error) {
	res, err := tx.exec(agentJobCancelForOp, sql.Named("op_id", opID), sql.Named("reason", reason), sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// HasDueAgentJobs reports whether ClaimAgentJobs would find work (a cheap
// read-only check, so an idle long-poll never takes the write lock).
func (tx *TenantTx) HasDueAgentJobs(agentID string, now time.Time) (bool, error) {
	var n int
	err := tx.queryRow(agentJobHasDue, sql.Named("agent_id", agentID), sql.Named("now", RT(now))).Scan(&n)
	return n > 0, err
}

// ClaimAgentJobs leases up to limit due jobs of agentID until now+lease and
// returns them. Each claim counts as an attempt. A leased job whose lease
// expired with no attempts left is not handed out again: it fails, and is
// returned in dead. Only agentID's rows are ever read or changed. Run it in a
// write transaction.
func (tx *TenantTx) ClaimAgentJobs(agentID string, now time.Time, lease time.Duration, limit int) (claimed, dead []*AgentJob, err error) {
	if limit <= 0 {
		return nil, nil, nil
	}
	rows, err := collect(tx, scanAgentJob, agentJobCandidates, sql.Named("agent_id", agentID), sql.Named("now", RT(now)),
		sql.Named("limit", limit))
	if err != nil {
		return nil, nil, err
	}
	expires := now.Add(lease)
	for _, j := range rows {
		if j.Status == AgentJobLeased && j.Attempts >= j.MaxAttempts {
			msg := "the lease expired after the last attempt (the agent did not report a result)"
			if err := tx.execOne(agentJobBury, sql.Named("id", j.ID), sql.Named("agent_id", agentID),
				sql.Named("error", msg), sql.Named("now", RT(now))); err != nil {
				return nil, nil, err
			}
			j.Status, j.LastError, j.LeaseExpiresAt = AgentJobFailed, msg, nil
			dead = append(dead, j)
			continue
		}
		if err := tx.execOne(agentJobClaim, sql.Named("id", j.ID), sql.Named("agent_id", agentID),
			sql.Named("expires", RT(expires)), sql.Named("now", RT(now))); err != nil {
			if errors.Is(err, ErrNotFound) { // another claim of the same agent got it first
				continue
			}
			return nil, nil, err
		}
		j.Status, j.Attempts, j.LeaseExpiresAt = AgentJobLeased, j.Attempts+1, &expires
		claimed = append(claimed, j)
	}
	return claimed, dead, nil
}

// CompleteAgentJob marks agentID's leased job done, with a counts-only summary
// (JSON). ErrNotFound: not a leased job of that agent.
func (tx *TenantTx) CompleteAgentJob(id, agentID, summary string, now time.Time) error {
	return tx.execOne(agentJobComplete, sql.Named("id", id), sql.Named("agent_id", agentID),
		sql.Named("summary", summary), sql.Named("now", RT(now)))
}

// FailAgentJob records a failed attempt of agentID's leased job. With
// retry=true and attempts left it is queued again; otherwise it is failed for
// good. ErrNotFound: not a leased job of that agent.
func (tx *TenantTx) FailAgentJob(j *AgentJob, errMsg string, retry bool, now time.Time) error {
	status, fin := AgentJobFailed, any(RT(now))
	if retry && j.Attempts < j.MaxAttempts {
		status, fin = AgentJobQueued, nil
	}
	return tx.execOne(agentJobFail, sql.Named("id", j.ID), sql.Named("agent_id", j.AgentID), sql.Named("status", status),
		sql.Named("error", errMsg), sql.Named("finished_at", fin), sql.Named("now", RT(now)))
}

// CancelAgentJobs cancels the agent's open jobs (it was revoked). It returns how many.
func (tx *TenantTx) CancelAgentJobs(agentID string, now time.Time) (int64, error) {
	res, err := tx.exec(agentJobCancel, sql.Named("agent_id", agentID), sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneAgentJobs deletes finished jobs that finished before before.
func (tx *TenantTx) PruneAgentJobs(before time.Time) (int64, error) {
	res, err := tx.exec(agentJobPrune, sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
