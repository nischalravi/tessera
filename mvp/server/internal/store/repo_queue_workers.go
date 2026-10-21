package store

import (
	"database/sql"
	"time"
)

// Worker health (schema/0460_queue_workers.sql, issue #302). The engine that
// beats is internal/worker; this file is only its SQL.

// Worker modes.
const (
	WorkerModeWorker = "worker" // a `tessera worker` process
	WorkerModeAPI    = "api"    // an API process running queue kinds in-process
)

// QueueWorker is one worker as seen by one tenant.
type QueueWorker struct {
	WorkerID        string
	Mode            string
	Hostname        string
	PID             int
	Version         string
	Kinds           string // comma-separated
	Concurrency     int
	Running         int
	StartedAt       time.Time
	LastHeartbeatAt time.Time
}

const queueWorkerCols = `w.worker_id, w.mode, w.hostname, w.pid, w.version, w.kinds, w.concurrency, w.running,
	w.started_at, w.last_heartbeat_at`

var (
	queueWorkerBeat = tq("queue_workers.beat", `
		INSERT INTO queue_workers (id, tenant_id, worker_id, mode, hostname, pid, version, kinds, concurrency, running,
			started_at, last_heartbeat_at)
		VALUES (@id, @tenant, @worker_id, @mode, @hostname, @pid, @version, @kinds, @concurrency, @running,
			@started_at, @now)
		ON CONFLICT (tenant_id, worker_id) DO UPDATE SET mode = excluded.mode, hostname = excluded.hostname,
			pid = excluded.pid, version = excluded.version, kinds = excluded.kinds,
			concurrency = excluded.concurrency, running = excluded.running, last_heartbeat_at = @now`)
	queueWorkerList = tq("queue_workers.list", `
		SELECT `+queueWorkerCols+` FROM queue_workers w WHERE w.tenant_id = @tenant
		ORDER BY w.last_heartbeat_at DESC, w.worker_id`)
	queueWorkerDelete = tq("queue_workers.delete", `
		DELETE FROM queue_workers WHERE tenant_id = @tenant AND worker_id = @worker_id`)
	queueWorkerPrune = tq("queue_workers.prune", `
		DELETE FROM queue_workers WHERE tenant_id = @tenant AND last_heartbeat_at < @before`)
)

func scanQueueWorker(s scanner) (*QueueWorker, error) {
	var w QueueWorker
	var started, beat string
	if err := s.Scan(&w.WorkerID, &w.Mode, &w.Hostname, &w.PID, &w.Version, &w.Kinds, &w.Concurrency, &w.Running,
		&started, &beat); err != nil {
		return nil, err
	}
	var err error
	if w.StartedAt, err = ParseRT(started); err != nil {
		return nil, err
	}
	w.LastHeartbeatAt, err = ParseRT(beat)
	return &w, err
}

// BeatQueueWorker records that the worker is alive now (insert or update). The
// worker's start time is kept from its first beat.
func (tx *TenantTx) BeatQueueWorker(w *QueueWorker, now time.Time) error {
	_, err := tx.exec(queueWorkerBeat, sql.Named("id", NewID()), sql.Named("worker_id", w.WorkerID),
		sql.Named("mode", w.Mode), sql.Named("hostname", w.Hostname), sql.Named("pid", w.PID),
		sql.Named("version", w.Version), sql.Named("kinds", w.Kinds), sql.Named("concurrency", w.Concurrency),
		sql.Named("running", w.Running), sql.Named("started_at", RT(w.StartedAt)), sql.Named("now", RT(now)))
	return err
}

// QueueWorkers lists the tenant's workers, most recently seen first.
func (tx *TenantTx) QueueWorkers() ([]*QueueWorker, error) {
	return collect(tx, scanQueueWorker, queueWorkerList)
}

// DeleteQueueWorker removes a worker that stopped cleanly (a crashed one stays,
// its last beat ageing, until PruneQueueWorkers).
func (tx *TenantTx) DeleteQueueWorker(workerID string) error {
	_, err := tx.exec(queueWorkerDelete, sql.Named("worker_id", workerID))
	return err
}

// PruneQueueWorkers deletes workers whose last beat is before before.
func (tx *TenantTx) PruneQueueWorkers(before time.Time) (int64, error) {
	res, err := tx.exec(queueWorkerPrune, sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
