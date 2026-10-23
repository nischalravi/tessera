package store

import (
	"database/sql"
	"strings"
	"time"
)

// Durable job queue (schema/0320_queue.sql, issue #300). The engine is
// internal/queue; this file is only its SQL.

// Queue job statuses.
const (
	QueueQueued    = "queued"
	QueueRunning   = "running"
	QueueSucceeded = "succeeded"
	QueueFailed    = "failed" // the last attempt failed; a retry waits for RunAt
	QueueDead      = "dead"   // attempts exhausted; an operator can retry it
)

// QueueJob is one unit of queued work.
type QueueJob struct {
	ID             string
	Kind           string
	Payload        string // JSON
	IdempotencyKey *string
	ScheduleID     *string
	Status         string
	RunAt          time.Time
	Attempts       int
	MaxAttempts    int
	LastError      string
	LeaseOwner     *string
	LeaseExpiresAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     *time.Time
}

// QueueSchedule is a recurring job: Spec is "@every <duration>" or a 5-field cron.
type QueueSchedule struct {
	ID             string
	Name           string
	Kind           string
	Payload        string // JSON
	Spec           string
	Enabled        bool
	MaxAttempts    int
	NextRunAt      time.Time
	LastEnqueuedAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// QueueJobFilter narrows QueueJobs. Empty fields match everything.
type QueueJobFilter struct {
	Status, Kind string
	Limit        int
}

const queueJobCols = `q.id, q.kind, q.payload, q.idempotency_key, q.schedule_id, q.status, q.run_at, q.attempts,
	q.max_attempts, q.last_error, q.lease_owner, q.lease_expires_at, q.created_at, q.updated_at, q.finished_at`

const queueScheduleCols = `s.id, s.name, s.kind, s.payload, s.spec, s.enabled, s.max_attempts, s.next_run_at,
	s.last_enqueued_at, s.created_at, s.updated_at`

// queueDue is the WHERE clause of work a worker may claim: waiting work whose
// time has come, or running work whose lease expired (its worker is gone).
const queueDue = `((status IN ('queued','failed') AND run_at <= @now)
	OR (status = 'running' AND lease_expires_at <= @now))`

var (
	queueJobInsert = tq("queue_jobs.insert", `
		INSERT OR IGNORE INTO queue_jobs (id, tenant_id, kind, payload, idempotency_key, schedule_id, status, run_at,
			attempts, max_attempts, last_error, created_at, updated_at)
		VALUES (@id, @tenant, @kind, @payload, @idempotency_key, @schedule_id, 'queued', @run_at, 0, @max_attempts, '',
			@now, @now)`)
	queueJobGet = tq("queue_jobs.get", `
		SELECT `+queueJobCols+` FROM queue_jobs q WHERE q.tenant_id = @tenant AND q.id = @id`)
	queueJobList = tq("queue_jobs.list", `
		SELECT `+queueJobCols+` FROM queue_jobs q
		WHERE q.tenant_id = @tenant AND (@status = '' OR q.status = @status) AND (@kind = '' OR q.kind = @kind)
		ORDER BY q.created_at DESC, q.id DESC LIMIT @limit`)
	// Postgres adds FOR UPDATE SKIP LOCKED (pgOverrides): two workers never
	// lock, and so never claim, the same row. SQLite has one writer at a time
	// (the transaction is BEGIN IMMEDIATE), so the plain read is already exclusive.
	queueJobCandidates = tq("queue_jobs.candidates", `
		SELECT `+queueJobCols+` FROM queue_jobs q
		WHERE q.tenant_id = @tenant AND instr(@kinds, ',' || q.kind || ',') > 0 AND `+queueDue+`
		ORDER BY q.run_at, q.id LIMIT @limit`)
	queueJobClaim = tq("queue_jobs.claim", `
		UPDATE queue_jobs SET status = 'running', lease_owner = @owner, lease_expires_at = @expires,
			attempts = attempts + 1, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND `+queueDue)
	queueJobBury = tq("queue_jobs.bury", `
		UPDATE queue_jobs SET status = 'dead', last_error = @error, lease_owner = NULL, lease_expires_at = NULL,
			finished_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'running'`)
	queueJobHeartbeat = tq("queue_jobs.heartbeat", `
		UPDATE queue_jobs SET lease_expires_at = @expires, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'running' AND lease_owner = @owner`)
	queueJobComplete = tq("queue_jobs.complete", `
		UPDATE queue_jobs SET status = 'succeeded', last_error = '', lease_owner = NULL, lease_expires_at = NULL,
			finished_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'running' AND lease_owner = @owner`)
	queueJobFail = tq("queue_jobs.fail", `
		UPDATE queue_jobs SET status = @status, run_at = @run_at, last_error = @error, lease_owner = NULL,
			lease_expires_at = NULL, finished_at = @finished_at, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'running' AND lease_owner = @owner`)
	queueJobRelease = tq("queue_jobs.release", `
		UPDATE queue_jobs SET status = 'queued', run_at = @now, attempts = attempts - 1, lease_owner = NULL,
			lease_expires_at = NULL, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'running' AND lease_owner = @owner AND attempts > 0`)
	queueJobRetryDead = tq("queue_jobs.retry_dead", `
		UPDATE queue_jobs SET status = 'queued', run_at = @now, attempts = 0, lease_owner = NULL, lease_expires_at = NULL,
			finished_at = NULL, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'dead'`)
	queueJobHasDue = tq("queue_jobs.has_due", `
		SELECT count(*) FROM queue_jobs q
		WHERE q.tenant_id = @tenant AND instr(@kinds, ',' || q.kind || ',') > 0 AND `+queueDue)
	queueJobPrune = tq("queue_jobs.prune", `
		DELETE FROM queue_jobs WHERE tenant_id = @tenant AND status = 'succeeded' AND finished_at < @before`)

	queueScheduleEnsure = tq("queue_schedules.ensure", `
		INSERT INTO queue_schedules (id, tenant_id, name, kind, payload, spec, enabled, max_attempts, next_run_at,
			created_at, updated_at)
		VALUES (@id, @tenant, @name, @kind, @payload, @spec, 1, @max_attempts, @next_run_at, @now, @now)
		ON CONFLICT (tenant_id, name) DO UPDATE SET kind = excluded.kind, payload = excluded.payload,
			spec = excluded.spec, max_attempts = excluded.max_attempts, updated_at = @now`)
	queueScheduleSetEnabled = tq("queue_schedules.set_enabled", `
		UPDATE queue_schedules SET enabled = @enabled, updated_at = @now WHERE tenant_id = @tenant AND name = @name`)
	queueScheduleGet = tq("queue_schedules.get", `
		SELECT `+queueScheduleCols+` FROM queue_schedules s WHERE s.tenant_id = @tenant AND s.name = @name`)
	queueScheduleList = tq("queue_schedules.list", `
		SELECT `+queueScheduleCols+` FROM queue_schedules s WHERE s.tenant_id = @tenant ORDER BY s.name`)
	queueScheduleDue = tq("queue_schedules.due", `
		SELECT `+queueScheduleCols+` FROM queue_schedules s
		WHERE s.tenant_id = @tenant AND s.enabled = 1 AND s.next_run_at <= @now ORDER BY s.next_run_at, s.name`)
	// next_run_at = @expected makes the advance a compare-and-set: of two
	// workers that read the same due schedule, only one moves it on.
	queueScheduleAdvance = tq("queue_schedules.advance", `
		UPDATE queue_schedules SET next_run_at = @next, last_enqueued_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND enabled = 1 AND next_run_at = @expected`)
)

func scanQueueJob(s scanner) (*QueueJob, error) {
	var j QueueJob
	var key, sched, owner, lease, fin sql.NullString
	var run, created, updated string
	if err := s.Scan(&j.ID, &j.Kind, &j.Payload, &key, &sched, &j.Status, &run, &j.Attempts, &j.MaxAttempts,
		&j.LastError, &owner, &lease, &created, &updated, &fin); err != nil {
		return nil, err
	}
	j.IdempotencyKey, j.ScheduleID, j.LeaseOwner = strp(key), strp(sched), strp(owner)
	var err error
	if j.RunAt, err = ParseRT(run); err != nil {
		return nil, err
	}
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

func scanQueueSchedule(s scanner) (*QueueSchedule, error) {
	var q QueueSchedule
	var enabled int
	var next, created, updated string
	var last sql.NullString
	if err := s.Scan(&q.ID, &q.Name, &q.Kind, &q.Payload, &q.Spec, &enabled, &q.MaxAttempts, &next, &last, &created,
		&updated); err != nil {
		return nil, err
	}
	q.Enabled = enabled == 1
	var err error
	if q.NextRunAt, err = ParseRT(next); err != nil {
		return nil, err
	}
	if q.LastEnqueuedAt, err = rtp(last); err != nil {
		return nil, err
	}
	if q.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	q.UpdatedAt, err = ParseRT(updated)
	return &q, err
}

// kindList renders kinds for the instr() match of the claim statements.
func kindList(kinds []string) string { return "," + strings.Join(kinds, ",") + "," }

// EnqueueQueueJob adds a queued job (ID is set when empty). With an
// IdempotencyKey, a job of the same kind and key that already exists (in any
// status) makes this a no-op and created is false. Payload defaults to {}.
func (tx *TenantTx) EnqueueQueueJob(j *QueueJob, now time.Time) (created bool, err error) {
	if j.ID == "" {
		j.ID = NewID()
	}
	if j.Payload == "" {
		j.Payload = "{}"
	}
	if j.MaxAttempts <= 0 {
		j.MaxAttempts = 5
	}
	res, err := tx.exec(queueJobInsert, sql.Named("id", j.ID), sql.Named("kind", j.Kind), sql.Named("payload", j.Payload),
		sql.Named("idempotency_key", SP(j.IdempotencyKey)), sql.Named("schedule_id", SP(j.ScheduleID)),
		sql.Named("run_at", RT(j.RunAt)), sql.Named("max_attempts", j.MaxAttempts), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// QueueJob returns one job or ErrNotFound.
func (tx *TenantTx) QueueJob(id string) (*QueueJob, error) {
	return one(tx, scanQueueJob, queueJobGet, sql.Named("id", id))
}

// QueueJobs lists jobs, newest first.
func (tx *TenantTx) QueueJobs(f QueueJobFilter) ([]*QueueJob, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 500
	}
	return collect(tx, scanQueueJob, queueJobList, sql.Named("status", f.Status), sql.Named("kind", f.Kind),
		sql.Named("limit", f.Limit))
}

// ClaimQueueJobs leases up to limit due jobs of the given kinds to owner
// until now+lease: queued or failed jobs whose run_at has passed, and running
// jobs whose lease expired (their worker is gone). Each claim counts as an
// attempt. A running job whose lease expired with no attempts left is not run
// again: it is buried (status dead) and returned in dead. Run it in a write
// transaction; on Postgres the candidate rows are locked with SKIP LOCKED.
func (tx *TenantTx) ClaimQueueJobs(now time.Time, owner string, lease time.Duration, kinds []string, limit int) (claimed, dead []*QueueJob, err error) {
	if limit <= 0 || len(kinds) == 0 {
		return nil, nil, nil
	}
	rows, err := collect(tx, scanQueueJob, queueJobCandidates, sql.Named("kinds", kindList(kinds)),
		sql.Named("now", RT(now)), sql.Named("limit", limit))
	if err != nil {
		return nil, nil, err
	}
	expires := now.Add(lease)
	for _, j := range rows {
		if j.Status == QueueRunning && j.Attempts >= j.MaxAttempts {
			msg := "the lease expired after the last attempt (the worker stopped before finishing)"
			if err := tx.execOne(queueJobBury, sql.Named("id", j.ID), sql.Named("error", msg), sql.Named("now", RT(now))); err != nil {
				return nil, nil, err
			}
			j.Status, j.LastError, j.LeaseOwner, j.LeaseExpiresAt = QueueDead, msg, nil, nil
			dead = append(dead, j)
			continue
		}
		if err := tx.execOne(queueJobClaim, sql.Named("id", j.ID), sql.Named("owner", owner),
			sql.Named("expires", RT(expires)), sql.Named("now", RT(now))); err != nil {
			return nil, nil, err
		}
		j.Status, j.Attempts, j.LeaseOwner, j.LeaseExpiresAt = QueueRunning, j.Attempts+1, &owner, &expires
		claimed = append(claimed, j)
	}
	return claimed, dead, nil
}

// HasDueQueueJobs reports whether ClaimQueueJobs would find work (a cheap
// read-only check, so an idle tenant never takes the write lock).
func (tx *TenantTx) HasDueQueueJobs(now time.Time, kinds []string) (bool, error) {
	if len(kinds) == 0 {
		return false, nil
	}
	var n int
	err := tx.queryRow(queueJobHasDue, sql.Named("kinds", kindList(kinds)), sql.Named("now", RT(now))).Scan(&n)
	return n > 0, err
}

// HeartbeatQueueJob extends owner's lease to now+lease. ErrNotFound: the
// lease is gone (expired and taken by another worker, or the job finished).
func (tx *TenantTx) HeartbeatQueueJob(id, owner string, now time.Time, lease time.Duration) error {
	return tx.execOne(queueJobHeartbeat, sql.Named("id", id), sql.Named("owner", owner),
		sql.Named("expires", RT(now.Add(lease))), sql.Named("now", RT(now)))
}

// CompleteQueueJob marks owner's running job succeeded (ErrNotFound: not the lease holder).
func (tx *TenantTx) CompleteQueueJob(id, owner string, now time.Time) error {
	return tx.execOne(queueJobComplete, sql.Named("id", id), sql.Named("owner", owner), sql.Named("now", RT(now)))
}

// FailQueueJob records a failed attempt of owner's running job: with retryAt
// the job becomes failed and runs again then; without it the job is dead.
// ErrNotFound: not the lease holder.
func (tx *TenantTx) FailQueueJob(id, owner string, now time.Time, errMsg string, retryAt *time.Time) error {
	status, runAt, fin := QueueDead, now, any(RT(now))
	if retryAt != nil {
		status, runAt, fin = QueueFailed, *retryAt, nil
	}
	return tx.execOne(queueJobFail, sql.Named("id", id), sql.Named("owner", owner), sql.Named("status", status),
		sql.Named("run_at", RT(runAt)), sql.Named("error", errMsg), sql.Named("finished_at", fin),
		sql.Named("now", RT(now)))
}

// ReleaseQueueJob hands owner's running job back unrun (a worker shutting
// down): it is queued and due at once, and the attempt the claim counted is
// given back. ErrNotFound: not the lease holder.
func (tx *TenantTx) ReleaseQueueJob(id, owner string, now time.Time) error {
	return tx.execOne(queueJobRelease, sql.Named("id", id), sql.Named("owner", owner), sql.Named("now", RT(now)))
}

// RetryDeadQueueJob puts a dead job back in the queue with a fresh attempt
// budget (the operator retry). ErrNotFound: no such dead job.
func (tx *TenantTx) RetryDeadQueueJob(id string, now time.Time) error {
	return tx.execOne(queueJobRetryDead, sql.Named("id", id), sql.Named("now", RT(now)))
}

// PruneQueueJobs deletes succeeded jobs that finished before before.
func (tx *TenantTx) PruneQueueJobs(before time.Time) (int64, error) {
	res, err := tx.exec(queueJobPrune, sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// EnsureQueueSchedule creates the named schedule, first due at next, or
// updates its kind, payload, spec and attempt budget (its due time and
// enabled flag are kept).
func (tx *TenantTx) EnsureQueueSchedule(s *QueueSchedule, now time.Time) error {
	if s.Payload == "" {
		s.Payload = "{}"
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 5
	}
	_, err := tx.exec(queueScheduleEnsure, sql.Named("id", NewID()), sql.Named("name", s.Name), sql.Named("kind", s.Kind),
		sql.Named("payload", s.Payload), sql.Named("spec", s.Spec), sql.Named("max_attempts", s.MaxAttempts),
		sql.Named("next_run_at", RT(s.NextRunAt)), sql.Named("now", RT(now)))
	return err
}

// QueueSchedule returns one schedule by name or ErrNotFound.
func (tx *TenantTx) QueueSchedule(name string) (*QueueSchedule, error) {
	return one(tx, scanQueueSchedule, queueScheduleGet, sql.Named("name", name))
}

// QueueSchedules lists the tenant's schedules by name.
func (tx *TenantTx) QueueSchedules() ([]*QueueSchedule, error) {
	return collect(tx, scanQueueSchedule, queueScheduleList)
}

// SetQueueScheduleEnabled pauses (false) or resumes (true) the named schedule;
// ErrNotFound when the tenant has none of that name. A paused schedule keeps
// its due time, so a resumed one fires once and then keeps its cadence.
func (tx *TenantTx) SetQueueScheduleEnabled(name string, enabled bool, now time.Time) error {
	e := 0
	if enabled {
		e = 1
	}
	return tx.execOne(queueScheduleSetEnabled, sql.Named("name", name), sql.Named("enabled", e), sql.Named("now", RT(now)))
}

// DueQueueSchedules lists enabled schedules whose next_run_at has passed.
func (tx *TenantTx) DueQueueSchedules(now time.Time) ([]*QueueSchedule, error) {
	return collect(tx, scanQueueSchedule, queueScheduleDue, sql.Named("now", RT(now)))
}

// AdvanceQueueSchedule moves a due schedule from expected to next. ErrNotFound:
// another worker already advanced it (or it was disabled), so the caller must
// not enqueue.
func (tx *TenantTx) AdvanceQueueSchedule(id string, expected, next, now time.Time) error {
	return tx.execOne(queueScheduleAdvance, sql.Named("id", id), sql.Named("expected", RT(expected)),
		sql.Named("next", RT(next)), sql.Named("now", RT(now)))
}
