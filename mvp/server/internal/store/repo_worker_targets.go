package store

import (
	"database/sql"
	"time"
)

// Per-target limits and breaker state of the connector workers
// (schema/0620_connection_limits.sql, issue #302). The engine that uses them
// is internal/worker (Guard); this file is only its SQL.

// ConnectionLimits are the limits of one connection. Zero is "the worker's
// default" for every field.
type ConnectionLimits struct {
	ConnectionID        string
	MaxConcurrency      int
	RatePerMin          int
	Burst               int
	BreakerThreshold    int
	BreakerCooldownSecs int
	UpdatedBy           string
	UpdatedAt           time.Time
}

const connectionLimitCols = `l.connection_id, l.max_concurrency, l.rate_per_min, l.burst, l.breaker_threshold,
	l.breaker_cooldown_secs, l.updated_by, l.updated_at`

// Breaker states.
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half_open"
)

// WorkerTargetState is what one worker knows of one target it called: the
// breaker, the calls in flight and the totals since the worker started.
type WorkerTargetState struct {
	WorkerID            string
	ConnectionID        string
	State               string
	ConsecutiveFailures int
	OpenUntil           *time.Time
	LastError           string
	InFlight            int
	Calls               int64
	Failures            int64
	Rejected            int64
	UpdatedAt           time.Time
}

const workerTargetCols = `s.worker_id, s.connection_id, s.state, s.consecutive_failures, s.open_until, s.last_error,
	s.in_flight, s.calls, s.failures, s.rejected, s.updated_at`

var (
	connLimitGet = tq("connection_limits.get", `
		SELECT `+connectionLimitCols+` FROM connection_limits l WHERE l.tenant_id = @tenant AND l.connection_id = @connection_id`)
	connLimitList = tq("connection_limits.list", `
		SELECT `+connectionLimitCols+` FROM connection_limits l WHERE l.tenant_id = @tenant ORDER BY l.connection_id`)
	connLimitPut = tq("connection_limits.put", `
		INSERT INTO connection_limits (id, tenant_id, connection_id, max_concurrency, rate_per_min, burst, breaker_threshold,
			breaker_cooldown_secs, updated_by, updated_at)
		VALUES (@id, @tenant, @connection_id, @max_concurrency, @rate_per_min, @burst, @breaker_threshold,
			@breaker_cooldown_secs, @updated_by, @now)
		ON CONFLICT (tenant_id, connection_id) DO UPDATE SET max_concurrency = excluded.max_concurrency,
			rate_per_min = excluded.rate_per_min, burst = excluded.burst, breaker_threshold = excluded.breaker_threshold,
			breaker_cooldown_secs = excluded.breaker_cooldown_secs, updated_by = excluded.updated_by, updated_at = @now`)
	connLimitDelete = tq("connection_limits.delete", `
		DELETE FROM connection_limits WHERE tenant_id = @tenant AND connection_id = @connection_id`)

	workerTargetInsert = tq("worker_target_states.insert", `
		INSERT INTO worker_target_states (id, tenant_id, worker_id, connection_id, state, consecutive_failures, open_until,
			last_error, in_flight, calls, failures, rejected, updated_at)
		VALUES (@id, @tenant, @worker_id, @connection_id, @state, @consecutive_failures, @open_until, @last_error,
			@in_flight, @calls, @failures, @rejected, @now)
		ON CONFLICT (tenant_id, worker_id, connection_id) DO UPDATE SET state = excluded.state,
			consecutive_failures = excluded.consecutive_failures, open_until = excluded.open_until,
			last_error = excluded.last_error, in_flight = excluded.in_flight, calls = excluded.calls,
			failures = excluded.failures, rejected = excluded.rejected, updated_at = @now`)
	workerTargetList = tq("worker_target_states.list", `
		SELECT `+workerTargetCols+` FROM worker_target_states s WHERE s.tenant_id = @tenant
		ORDER BY s.worker_id, s.connection_id`)
	workerTargetClear = tq("worker_target_states.clear", `
		DELETE FROM worker_target_states WHERE tenant_id = @tenant AND worker_id = @worker_id`)
	workerTargetPrune = tq("worker_target_states.prune", `
		DELETE FROM worker_target_states WHERE tenant_id = @tenant AND updated_at < @before`)
)

func scanConnectionLimits(s scanner) (*ConnectionLimits, error) {
	var l ConnectionLimits
	var at string
	if err := s.Scan(&l.ConnectionID, &l.MaxConcurrency, &l.RatePerMin, &l.Burst, &l.BreakerThreshold,
		&l.BreakerCooldownSecs, &l.UpdatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	l.UpdatedAt, err = ParseRT(at)
	return &l, err
}

func scanWorkerTarget(s scanner) (*WorkerTargetState, error) {
	var w WorkerTargetState
	var until sql.NullString
	var at string
	if err := s.Scan(&w.WorkerID, &w.ConnectionID, &w.State, &w.ConsecutiveFailures, &until, &w.LastError,
		&w.InFlight, &w.Calls, &w.Failures, &w.Rejected, &at); err != nil {
		return nil, err
	}
	var err error
	if w.OpenUntil, err = rtp(until); err != nil {
		return nil, err
	}
	w.UpdatedAt, err = ParseRT(at)
	return &w, err
}

// ConnectionLimits returns the limits set for a connection, or ErrNotFound
// when none were set (the worker's defaults apply).
func (tx *TenantTx) ConnectionLimits(connectionID string) (*ConnectionLimits, error) {
	return one(tx, scanConnectionLimits, connLimitGet, sql.Named("connection_id", connectionID))
}

// AllConnectionLimits lists every connection's limits of the tenant.
func (tx *TenantTx) AllConnectionLimits() ([]*ConnectionLimits, error) {
	return collect(tx, scanConnectionLimits, connLimitList)
}

// PutConnectionLimits sets (insert or replace) a connection's limits. The
// connection must be this tenant's (the schema refuses others).
func (tx *TenantTx) PutConnectionLimits(l *ConnectionLimits, now time.Time) error {
	_, err := tx.exec(connLimitPut, sql.Named("id", NewID()), sql.Named("connection_id", l.ConnectionID),
		sql.Named("max_concurrency", l.MaxConcurrency), sql.Named("rate_per_min", l.RatePerMin),
		sql.Named("burst", l.Burst), sql.Named("breaker_threshold", l.BreakerThreshold),
		sql.Named("breaker_cooldown_secs", l.BreakerCooldownSecs), sql.Named("updated_by", l.UpdatedBy),
		sql.Named("now", RT(now)))
	return err
}

// DeleteConnectionLimits removes a connection's limits (back to the defaults).
// ErrNotFound when it had none.
func (tx *TenantTx) DeleteConnectionLimits(connectionID string) error {
	return tx.execOne(connLimitDelete, sql.Named("connection_id", connectionID))
}

// ReplaceWorkerTargetStates replaces the worker's target rows of this tenant
// with states (a worker publishes its whole view on every beat).
func (tx *TenantTx) ReplaceWorkerTargetStates(workerID string, states []WorkerTargetState, now time.Time) error {
	if _, err := tx.exec(workerTargetClear, sql.Named("worker_id", workerID)); err != nil {
		return err
	}
	for _, s := range states {
		if _, err := tx.exec(workerTargetInsert, sql.Named("id", NewID()), sql.Named("worker_id", workerID),
			sql.Named("connection_id", s.ConnectionID), sql.Named("state", s.State),
			sql.Named("consecutive_failures", s.ConsecutiveFailures), sql.Named("open_until", RTP(s.OpenUntil)),
			sql.Named("last_error", s.LastError), sql.Named("in_flight", s.InFlight), sql.Named("calls", s.Calls),
			sql.Named("failures", s.Failures), sql.Named("rejected", s.Rejected), sql.Named("now", RT(now))); err != nil {
			return err
		}
	}
	return nil
}

// WorkerTargetStates lists what the tenant's workers last published, by worker
// then connection.
func (tx *TenantTx) WorkerTargetStates() ([]*WorkerTargetState, error) {
	return collect(tx, scanWorkerTarget, workerTargetList)
}

// ClearWorkerTargetStates removes a worker's target rows (it stopped cleanly).
func (tx *TenantTx) ClearWorkerTargetStates(workerID string) error {
	_, err := tx.exec(workerTargetClear, sql.Named("worker_id", workerID))
	return err
}

// PruneWorkerTargetStates deletes rows not refreshed since before (a worker
// that crashed).
func (tx *TenantTx) PruneWorkerTargetStates(before time.Time) (int64, error) {
	res, err := tx.exec(workerTargetPrune, sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
