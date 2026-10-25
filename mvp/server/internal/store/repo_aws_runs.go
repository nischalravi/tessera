package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// AWS collection runs (schema/0914_aws_collection_runs.sql). Every statement
// binds the tenant.

const awsRunCols = `r.id, r.connector_id, r.trigger, r.status, r.requested_by, r.queued_at, r.started_at, r.finished_at,
	r.snapshot_id, r.changed, r.result, r.error`

var (
	awsRunInsert = tq("aws_collection_runs.insert", `
		INSERT INTO aws_collection_runs (tenant_id, id, connector_id, trigger, status, requested_by, queued_at, started_at,
			finished_at, snapshot_id, changed, result, error)
		VALUES (@tenant, @id, @connector_id, @trigger, @status, @requested_by, @queued_at, @started_at, @finished_at,
			@snapshot_id, @changed, @result, @error)`)
	awsRunGet = tq("aws_collection_runs.get", `
		SELECT `+awsRunCols+` FROM aws_collection_runs r WHERE r.tenant_id = @tenant AND r.id = @id`)
	awsRunList = tq("aws_collection_runs.list", `
		SELECT `+awsRunCols+` FROM aws_collection_runs r
		WHERE r.tenant_id = @tenant AND (@connector_id = '' OR r.connector_id = @connector_id)
		ORDER BY r.queued_at DESC, r.id DESC LIMIT @limit`)
	awsRunActive = tq("aws_collection_runs.active", `
		SELECT `+awsRunCols+` FROM aws_collection_runs r
		WHERE r.tenant_id = @tenant AND r.connector_id = @connector_id AND r.status IN ('queued', 'running')`)
	awsRunStart = tq("aws_collection_runs.start", `
		UPDATE aws_collection_runs SET status = 'running', started_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status IN ('queued', 'running')`)
	awsRunFinish = tq("aws_collection_runs.finish", `
		UPDATE aws_collection_runs SET status = @status, finished_at = @now, snapshot_id = @snapshot_id, changed = @changed,
			result = @result, error = @error
		WHERE tenant_id = @tenant AND id = @id AND status IN ('queued', 'running')`)
	awsRunFailStale = tq("aws_collection_runs.fail_stale", `
		UPDATE aws_collection_runs SET status = 'failed', finished_at = @now, error = @error
		WHERE tenant_id = @tenant AND status IN ('queued', 'running') AND queued_at < @before`)
)

func scanAWSRun(s scanner) (*AWSCollectionRun, error) {
	var r AWSCollectionRun
	var queued string
	var started, finished, snap, result sql.NullString
	var changed int
	if err := s.Scan(&r.ID, &r.ConnectorID, &r.Trigger, &r.Status, &r.RequestedBy, &queued, &started, &finished, &snap, &changed,
		&result, &r.Error); err != nil {
		return nil, err
	}
	var err error
	if r.QueuedAt, err = ParseRT(queued); err != nil {
		return nil, err
	}
	if r.StartedAt, err = rtp(started); err != nil {
		return nil, err
	}
	if r.FinishedAt, err = rtp(finished); err != nil {
		return nil, err
	}
	r.SnapshotID, r.Changed = snap.String, changed == 1
	if result.Valid {
		r.Result = json.RawMessage(result.String)
	}
	return &r, nil
}

// InsertAWSCollectionRun adds a run (queued by the route, or finished by the
// scheduler). ErrDuplicate: the connector already has a queued or running run.
func (tx *TenantTx) InsertAWSCollectionRun(r *AWSCollectionRun) error {
	changed := 0
	if r.Changed {
		changed = 1
	}
	var started, finished, result any
	if r.StartedAt != nil {
		started = RT(*r.StartedAt)
	}
	if r.FinishedAt != nil {
		finished = RT(*r.FinishedAt)
	}
	if len(r.Result) > 0 {
		result = string(r.Result)
	}
	_, err := tx.exec(awsRunInsert, sql.Named("id", r.ID), sql.Named("connector_id", r.ConnectorID), sql.Named("trigger", r.Trigger),
		sql.Named("status", r.Status), sql.Named("requested_by", r.RequestedBy), sql.Named("queued_at", RT(r.QueuedAt)),
		sql.Named("started_at", started), sql.Named("finished_at", finished), sql.Named("snapshot_id", awsNull(r.SnapshotID)),
		sql.Named("changed", changed), sql.Named("result", result), sql.Named("error", r.Error))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// AWSCollectionRun returns one run, or ErrNotFound.
func (tx *TenantTx) AWSCollectionRun(id string) (*AWSCollectionRun, error) {
	return one(tx, scanAWSRun, awsRunGet, sql.Named("id", id))
}

// AWSCollectionRuns lists runs newest first; connectorID "" lists every connector's.
func (tx *TenantTx) AWSCollectionRuns(connectorID string, limit int) ([]*AWSCollectionRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, scanAWSRun, awsRunList, sql.Named("connector_id", connectorID), sql.Named("limit", limit))
}

// ActiveAWSCollectionRun returns the connector's queued or running run, or ErrNotFound.
func (tx *TenantTx) ActiveAWSCollectionRun(connectorID string) (*AWSCollectionRun, error) {
	return one(tx, scanAWSRun, awsRunActive, sql.Named("connector_id", connectorID))
}

// StartAWSCollectionRun moves a queued run to running (a run the queue delivers again after a restart is
// already running and stays so). ErrNotFound: it is not active.
func (tx *TenantTx) StartAWSCollectionRun(id string, now time.Time) error {
	return tx.affectOne(awsRunStart, sql.Named("id", id), sql.Named("now", RT(now)))
}

// FinishAWSCollectionRun records the outcome of a queued or running run.
// ErrNotFound: it already finished (or was failed as stale).
func (tx *TenantTx) FinishAWSCollectionRun(id, status, snapshotID string, changed bool, result json.RawMessage, errMsg string, now time.Time) error {
	c := 0
	if changed {
		c = 1
	}
	var res any
	if len(result) > 0 {
		res = string(result)
	}
	return tx.affectOne(awsRunFinish, sql.Named("id", id), sql.Named("status", status), sql.Named("now", RT(now)),
		sql.Named("snapshot_id", awsNull(snapshotID)), sql.Named("changed", c), sql.Named("result", res), sql.Named("error", errMsg))
}

// FailStaleAWSCollectionRuns fails the queued or running runs queued before
// the given time (their worker stopped), so they stop blocking the connector.
func (tx *TenantTx) FailStaleAWSCollectionRuns(before, now time.Time, errMsg string) (int64, error) {
	res, err := tx.exec(awsRunFailStale, sql.Named("before", RT(before)), sql.Named("now", RT(now)), sql.Named("error", errMsg))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
