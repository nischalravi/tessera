package store

import (
	"database/sql"
	"time"
)

// JobRun is one run of a background or on-demand job (issue #172).
type JobRun struct {
	ID           string
	Kind         string // sync | provision | validation | dry_run | health_rerun | jit_sweep | audit_anchor
	Trigger      string // manual | schedule | retry
	Status       string // running | succeeded | failed
	ConnectionID *string
	// Method, Route and Path are the API call that ran the job (Route is
	// the registered pattern); Body its request JSON. A retry replays them.
	Method, Route, Path, Body *string
	Retryable                 bool
	RetryOf                   *string
	Actor                     string
	StartedAt                 time.Time
	FinishedAt                *time.Time
	Result                    *string // JSON summary (counts), when small
	Error                     *string
}

// JobRunFilter narrows JobRuns. Empty fields match everything.
type JobRunFilter struct {
	Status, Kind, ConnectionID string
	Limit                      int
}

const jobCols = `j.id, j.kind, j.trigger, j.status, j.connection_id, j.method, j.route, j.path, j.body, j.retryable,
	j.retry_of, j.actor, j.started_at, j.finished_at, j.result, j.error`

var (
	jobRunInsert = tq("job_runs.insert", `
		INSERT INTO job_runs (id, tenant_id, kind, trigger, status, connection_id, method, route, path, body, retryable,
			retry_of, actor, started_at, finished_at, result, error)
		VALUES (@id, @tenant, @kind, @trigger, @status, @connection_id, @method, @route, @path, @body, @retryable,
			@retry_of, @actor, @started_at, @finished_at, @result, @error)`)
	jobRunFinish = tq("job_runs.finish", `
		UPDATE job_runs SET status = @status, finished_at = @finished_at, result = @result, error = @error
		WHERE tenant_id = @tenant AND id = @id AND status = 'running'`)
	jobRunDeleteRunning = tq("job_runs.delete_running", `
		DELETE FROM job_runs WHERE tenant_id = @tenant AND id = @id AND status = 'running'`)
	jobRunGet = tq("job_runs.get", `
		SELECT `+jobCols+` FROM job_runs j WHERE j.tenant_id = @tenant AND j.id = @id`)
	jobRunList = tq("job_runs.list", `
		SELECT `+jobCols+` FROM job_runs j
		WHERE j.tenant_id = @tenant AND (@status = '' OR j.status = @status) AND (@kind = '' OR j.kind = @kind)
			AND (@connection_id = '' OR j.connection_id = @connection_id)
		ORDER BY j.started_at DESC, j.rowid DESC LIMIT @limit`)
	jobRunFailStale = tq("job_runs.fail_stale", `
		UPDATE job_runs SET status = 'failed', finished_at = @now, error = @error
		WHERE tenant_id = @tenant AND status = 'running' AND started_at < @before`)
	jobRunPrune = tq("job_runs.prune", `
		DELETE FROM job_runs WHERE tenant_id = @tenant AND status <> 'running' AND started_at < @before`)
	jobRunUnlinkRetries = tq("job_runs.unlink_retries", `
		UPDATE job_runs SET retry_of = NULL
		WHERE job_runs.tenant_id = @tenant AND job_runs.retry_of IN (SELECT o.id FROM job_runs o
			WHERE o.tenant_id = @tenant AND o.status <> 'running' AND o.started_at < @before)`)
)

func scanJobRun(s scanner) (*JobRun, error) {
	var j JobRun
	var conn, method, route, path, body, retryOf, result, errs sql.NullString
	var retryable int
	var started, finished nullTime
	if err := s.Scan(&j.ID, &j.Kind, &j.Trigger, &j.Status, &conn, &method, &route, &path, &body, &retryable,
		&retryOf, &j.Actor, &started, &finished, &result, &errs); err != nil {
		return nil, err
	}
	var err error
	if j.StartedAt, err = started.val(); err != nil {
		return nil, err
	}
	j.ConnectionID, j.Method, j.Route, j.Path, j.Body = strp(conn), strp(method), strp(route), strp(path), strp(body)
	j.RetryOf, j.Result, j.Error = strp(retryOf), strp(result), strp(errs)
	j.Retryable = retryable == 1
	if j.FinishedAt, err = finished.ptr(); err != nil {
		return nil, err
	}
	return &j, nil
}

// InsertJobRun records a run (normally as running; a background run that
// is only recorded afterwards is inserted finished).
func (tx *TenantTx) InsertJobRun(j *JobRun) error {
	var fin any
	if j.FinishedAt != nil {
		fin = T(*j.FinishedAt)
	}
	retryable := 0
	if j.Retryable {
		retryable = 1
	}
	_, err := tx.exec(jobRunInsert, sql.Named("id", j.ID), sql.Named("kind", j.Kind), sql.Named("trigger", j.Trigger),
		sql.Named("status", j.Status), sql.Named("connection_id", SP(j.ConnectionID)), sql.Named("method", SP(j.Method)),
		sql.Named("route", SP(j.Route)), sql.Named("path", SP(j.Path)), sql.Named("body", SP(j.Body)),
		sql.Named("retryable", retryable), sql.Named("retry_of", SP(j.RetryOf)), sql.Named("actor", j.Actor),
		sql.Named("started_at", T(j.StartedAt)), sql.Named("finished_at", fin), sql.Named("result", SP(j.Result)),
		sql.Named("error", SP(j.Error)))
	return err
}

// FinishJobRun sets a running run's outcome. ErrNotFound: no such running run.
func (tx *TenantTx) FinishJobRun(id, status string, at time.Time, result, errMsg *string) error {
	return tx.execOne(jobRunFinish, sql.Named("id", id), sql.Named("status", status), sql.Named("finished_at", T(at)),
		sql.Named("result", SP(result)), sql.Named("error", SP(errMsg)))
}

// DeleteRunningJobRun removes a run that never started its work (the
// request was refused before the job ran). ErrNotFound: no such running run.
func (tx *TenantTx) DeleteRunningJobRun(id string) error {
	return tx.execOne(jobRunDeleteRunning, sql.Named("id", id))
}

// JobRun returns one run.
func (tx *TenantTx) JobRun(id string) (*JobRun, error) {
	return one(tx, scanJobRun, jobRunGet, sql.Named("id", id))
}

// JobRuns lists runs, newest first.
func (tx *TenantTx) JobRuns(f JobRunFilter) ([]*JobRun, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 500
	}
	return collect(tx, scanJobRun, jobRunList, sql.Named("status", f.Status), sql.Named("kind", f.Kind),
		sql.Named("connection_id", f.ConnectionID), sql.Named("limit", f.Limit))
}

// FailStaleJobRuns marks runs still running since before as failed with
// msg (the process that ran them stopped). It returns how many.
func (tx *TenantTx) FailStaleJobRuns(before, now time.Time, msg string) (int64, error) {
	res, err := tx.exec(jobRunFailStale, sql.Named("before", T(before)), sql.Named("now", T(now)), sql.Named("error", msg))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneJobRuns deletes finished runs started before before (retention). A
// newer retry's link to a pruned run is cleared first.
func (tx *TenantTx) PruneJobRuns(before time.Time) (int64, error) {
	if _, err := tx.exec(jobRunUnlinkRetries, sql.Named("before", T(before))); err != nil {
		return 0, err
	}
	res, err := tx.exec(jobRunPrune, sql.Named("before", T(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
