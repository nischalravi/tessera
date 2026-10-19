package store

import (
	"database/sql"
	"time"
)

// Closed-loop provisioning (issue #103): targets, operations and findings.
// Every statement is tenant-scoped (tq) and linted like the rest of the store.

// ProvTarget is the target system behind a connection.
type ProvTarget struct {
	ID, ConnectionID string
	System           string // the connection's system (set by the by-system lookup and the list)
	Kind             string // scim | okta | fake
	BaseURL          string
	Settings         string // JSON: dialect, fault
	CredentialEnc    []byte // sealed; never leaves the server
	CredentialVer    *string
	WriteBack        bool
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ProvOp is one change to a target system.
type ProvOp struct {
	ID, ConnectionID string
	Kind             string
	TargetRef        string
	Payload          string // JSON
	Completion       *string
	Source           string
	IdempotencyKey   string
	Status           string
	Attempts         int
	VerifyAttempts   int
	NextAttemptAt    time.Time
	LastError        *string
	Observed         *string
	RequestedBy      string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CompletedAt      *time.Time
}

// ProvFinding is raised when a re-read of the target does not show the
// change Tessera made.
type ProvFinding struct {
	ID, OpID, ConnectionID string
	Code, Severity, Title  string
	Expected, Observed     string
	Status                 string
	CreatedAt              time.Time
	ResolvedAt             *time.Time
}

// ProvOpFilter narrows ProvOps. Empty fields match everything.
type ProvOpFilter struct {
	Status, Kind, ConnectionID string
	Limit                      int
}

const provTargetCols = `t.id, t.connection_id, c.system, t.kind, t.base_url, t.settings, t.credential_enc,
	t.credential_version, t.write_back, t.created_by, t.created_at, t.updated_at`

const provOpCols = `o.id, o.connection_id, o.kind, o.target_ref, o.payload, o.completion, o.source, o.idempotency_key,
	o.status, o.attempts, o.verify_attempts, o.next_attempt_at, o.last_error, o.observed, o.requested_by, o.created_at,
	o.updated_at, o.completed_at`

const provFindingCols = `f.id, f.op_id, f.connection_id, f.code, f.severity, f.title, f.expected, f.observed, f.status,
	f.created_at, f.resolved_at`

var (
	provTargetUpsert = tq("provisioning_targets.upsert", `
		INSERT INTO provisioning_targets (id, tenant_id, connection_id, kind, base_url, settings, credential_enc,
			credential_version, write_back, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @connection_id, @kind, @base_url, @settings, @credential_enc, @credential_version,
			@write_back, @created_by, @now, @now)
		ON CONFLICT (tenant_id, connection_id) DO UPDATE SET kind = excluded.kind, base_url = excluded.base_url,
			settings = excluded.settings, credential_enc = excluded.credential_enc,
			credential_version = excluded.credential_version, write_back = excluded.write_back,
			updated_at = excluded.updated_at`)
	provTargetGet = tq("provisioning_targets.get", `
		SELECT `+provTargetCols+` FROM provisioning_targets t
		JOIN connections c ON c.id = t.connection_id AND c.tenant_id = @tenant
		WHERE t.tenant_id = @tenant AND t.connection_id = @connection_id`)
	provTargetBySystem = tq("provisioning_targets.by_system", `
		SELECT `+provTargetCols+` FROM provisioning_targets t
		JOIN connections c ON c.id = t.connection_id AND c.tenant_id = @tenant
		WHERE t.tenant_id = @tenant AND c.system = @system AND c.retired_at IS NULL`)
	provTargetList = tq("provisioning_targets.list", `
		SELECT `+provTargetCols+` FROM provisioning_targets t
		JOIN connections c ON c.id = t.connection_id AND c.tenant_id = @tenant
		WHERE t.tenant_id = @tenant ORDER BY t.created_at, t.rowid`)
	provTargetDelete = tq("provisioning_targets.delete", `
		DELETE FROM provisioning_targets WHERE tenant_id = @tenant AND connection_id = @connection_id`)

	provOpInsert = tq("provisioning_ops.insert", `
		INSERT INTO provisioning_ops (id, tenant_id, connection_id, kind, target_ref, payload, completion, source,
			idempotency_key, status, attempts, verify_attempts, next_attempt_at, requested_by, created_at, updated_at)
		VALUES (@id, @tenant, @connection_id, @kind, @target_ref, @payload, @completion, @source, @idempotency_key,
			'queued', 0, 0, @next_attempt_at, @requested_by, @now, @now)`)
	provOpGet = tq("provisioning_ops.get", `
		SELECT `+provOpCols+` FROM provisioning_ops o WHERE o.tenant_id = @tenant AND o.id = @id`)
	provOpByKey = tq("provisioning_ops.by_key", `
		SELECT `+provOpCols+` FROM provisioning_ops o WHERE o.tenant_id = @tenant AND o.idempotency_key = @key`)
	provOpList = tq("provisioning_ops.list", `
		SELECT `+provOpCols+` FROM provisioning_ops o
		WHERE o.tenant_id = @tenant AND (@status = '' OR o.status = @status) AND (@kind = '' OR o.kind = @kind)
			AND (@connection_id = '' OR o.connection_id = @connection_id)
		ORDER BY o.created_at DESC, o.rowid DESC LIMIT @limit`)
	provOpDue = tq("provisioning_ops.due", `
		SELECT `+provOpCols+` FROM provisioning_ops o
		WHERE o.tenant_id = @tenant AND o.status IN ('queued','pending_verification') AND o.next_attempt_at <= @now
		ORDER BY o.created_at, o.rowid LIMIT @limit`)
	provOpAfter = tq("provisioning_ops.set_state", `
		UPDATE provisioning_ops SET status = @to, attempts = @attempts, verify_attempts = @verify_attempts,
			next_attempt_at = @next_attempt_at, last_error = @last_error, observed = @observed, updated_at = @now,
			completed_at = @completed_at
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)
	provOpStale = tq("provisioning_ops.requeue_stale", `
		UPDATE provisioning_ops SET status = 'queued', next_attempt_at = @now, updated_at = @now,
			last_error = 'interrupted: the worker stopped before the target answered'
		WHERE tenant_id = @tenant AND status = 'sent' AND updated_at < @before`)
	provOpCounts = tq("provisioning_ops.counts", `
		SELECT o.status, count(*) FROM provisioning_ops o WHERE o.tenant_id = @tenant GROUP BY o.status`)

	provFindingInsert = tq("provisioning_findings.insert", `
		INSERT INTO provisioning_findings (id, tenant_id, op_id, connection_id, code, severity, title, expected,
			observed, status, created_at)
		VALUES (@id, @tenant, @op_id, @connection_id, @code, @severity, @title, @expected, @observed, 'open', @now)
		ON CONFLICT (tenant_id, op_id, code) DO UPDATE SET observed = excluded.observed, status = 'open',
			resolved_at = NULL`)
	provFindingList = tq("provisioning_findings.list", `
		SELECT `+provFindingCols+` FROM provisioning_findings f
		WHERE f.tenant_id = @tenant AND (@status = '' OR f.status = @status) AND (@op_id = '' OR f.op_id = @op_id)
		ORDER BY f.created_at DESC, f.rowid DESC LIMIT 500`)
	provFindingResolve = tq("provisioning_findings.resolve", `
		UPDATE provisioning_findings SET status = 'resolved', resolved_at = @now
		WHERE tenant_id = @tenant AND op_id = @op_id AND status = 'open'`)
)

func scanProvTarget(s scanner) (*ProvTarget, error) {
	var t ProvTarget
	var ver sql.NullString
	var wb int
	var created, updated string
	if err := s.Scan(&t.ID, &t.ConnectionID, &t.System, &t.Kind, &t.BaseURL, &t.Settings, &t.CredentialEnc, &ver, &wb,
		&t.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	t.CredentialVer, t.WriteBack = strp(ver), wb == 1
	if t.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	t.UpdatedAt, err = ParseRT(updated)
	return &t, err
}

func scanProvOp(s scanner) (*ProvOp, error) {
	var o ProvOp
	var completion, lastErr, observed sql.NullString
	var next, created, updated string
	var done sql.NullString
	if err := s.Scan(&o.ID, &o.ConnectionID, &o.Kind, &o.TargetRef, &o.Payload, &completion, &o.Source, &o.IdempotencyKey,
		&o.Status, &o.Attempts, &o.VerifyAttempts, &next, &lastErr, &observed, &o.RequestedBy, &created, &updated,
		&done); err != nil {
		return nil, err
	}
	var err error
	o.Completion, o.LastError, o.Observed = strp(completion), strp(lastErr), strp(observed)
	if o.NextAttemptAt, err = ParseRT(next); err != nil {
		return nil, err
	}
	if o.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if o.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	o.CompletedAt, err = rtp(done)
	return &o, err
}

func scanProvFinding(s scanner) (*ProvFinding, error) {
	var f ProvFinding
	var created string
	var resolved sql.NullString
	if err := s.Scan(&f.ID, &f.OpID, &f.ConnectionID, &f.Code, &f.Severity, &f.Title, &f.Expected, &f.Observed, &f.Status,
		&created, &resolved); err != nil {
		return nil, err
	}
	var err error
	if f.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	f.ResolvedAt, err = rtp(resolved)
	return &f, err
}

// UpsertProvTarget creates or replaces the target of a connection.
func (tx *TenantTx) UpsertProvTarget(t *ProvTarget, now time.Time) error {
	var enc any
	if t.CredentialEnc != nil {
		enc = t.CredentialEnc
	}
	_, err := tx.exec(provTargetUpsert, sql.Named("id", t.ID), sql.Named("connection_id", t.ConnectionID),
		sql.Named("kind", t.Kind), sql.Named("base_url", t.BaseURL), sql.Named("settings", t.Settings),
		sql.Named("credential_enc", enc), sql.Named("credential_version", SP(t.CredentialVer)),
		sql.Named("write_back", B(t.WriteBack)), sql.Named("created_by", t.CreatedBy), sql.Named("now", RT(now)))
	return err
}

// ProvTarget returns the target of a connection. ErrNotFound: none.
func (tx *TenantTx) ProvTarget(connectionID string) (*ProvTarget, error) {
	return one(tx, scanProvTarget, provTargetGet, sql.Named("connection_id", connectionID))
}

// ProvTargetBySystem returns the target of the live connection for a system.
// ErrNotFound: none.
func (tx *TenantTx) ProvTargetBySystem(system string) (*ProvTarget, error) {
	return one(tx, scanProvTarget, provTargetBySystem, sql.Named("system", system))
}

// ProvTargets lists the tenant's targets.
func (tx *TenantTx) ProvTargets() ([]*ProvTarget, error) {
	return collect(tx, scanProvTarget, provTargetList)
}

// DeleteProvTarget removes a connection's target. ErrNotFound: none.
func (tx *TenantTx) DeleteProvTarget(connectionID string) error {
	return tx.execOne(provTargetDelete, sql.Named("connection_id", connectionID))
}

// InsertProvOp queues an operation; ErrDuplicate when its idempotency key is taken.
func (tx *TenantTx) InsertProvOp(o *ProvOp, now time.Time) error {
	_, err := tx.exec(provOpInsert, sql.Named("id", o.ID), sql.Named("connection_id", o.ConnectionID),
		sql.Named("kind", o.Kind), sql.Named("target_ref", o.TargetRef), sql.Named("payload", o.Payload),
		sql.Named("completion", SP(o.Completion)), sql.Named("source", o.Source),
		sql.Named("idempotency_key", o.IdempotencyKey), sql.Named("next_attempt_at", RT(now)),
		sql.Named("requested_by", o.RequestedBy), sql.Named("now", RT(now)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// ProvOp returns one operation.
func (tx *TenantTx) ProvOp(id string) (*ProvOp, error) {
	return one(tx, scanProvOp, provOpGet, sql.Named("id", id))
}

// ProvOpByKey returns the operation with an idempotency key.
func (tx *TenantTx) ProvOpByKey(key string) (*ProvOp, error) {
	return one(tx, scanProvOp, provOpByKey, sql.Named("key", key))
}

// ProvOps lists operations, newest first.
func (tx *TenantTx) ProvOps(f ProvOpFilter) ([]*ProvOp, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 500
	}
	return collect(tx, scanProvOp, provOpList, sql.Named("status", f.Status), sql.Named("kind", f.Kind),
		sql.Named("connection_id", f.ConnectionID), sql.Named("limit", f.Limit))
}

// DueProvOps lists queued operations and operations waiting for a re-read
// whose next attempt is due, oldest first.
func (tx *TenantTx) DueProvOps(now time.Time, limit int) ([]*ProvOp, error) {
	return collect(tx, scanProvOp, provOpDue, sql.Named("now", RT(now)), sql.Named("limit", limit))
}

// ProvOpState is the mutable part of an operation.
type ProvOpState struct {
	Status         string
	Attempts       int
	VerifyAttempts int
	NextAttemptAt  time.Time
	LastError      *string
	Observed       *string
	CompletedAt    *time.Time
}

// SetProvOpState moves an operation from status from to st.Status.
// ErrNotFound: no such operation in status from (another worker moved it).
func (tx *TenantTx) SetProvOpState(id, from string, st ProvOpState, now time.Time) error {
	var done any
	if st.CompletedAt != nil {
		done = RT(*st.CompletedAt)
	}
	return tx.execOne(provOpAfter, sql.Named("id", id), sql.Named("from", from), sql.Named("to", st.Status),
		sql.Named("attempts", st.Attempts), sql.Named("verify_attempts", st.VerifyAttempts),
		sql.Named("next_attempt_at", RT(st.NextAttemptAt)), sql.Named("last_error", SP(st.LastError)),
		sql.Named("observed", SP(st.Observed)), sql.Named("now", RT(now)), sql.Named("completed_at", done))
}

// RequeueStaleProvOps puts operations left sent since before back in the
// queue (the worker stopped before the target answered). It returns how many.
func (tx *TenantTx) RequeueStaleProvOps(before, now time.Time) (int64, error) {
	res, err := tx.exec(provOpStale, sql.Named("before", RT(before)), sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ProvOpCounts counts operations per status.
func (tx *TenantTx) ProvOpCounts() (map[string]int, error) {
	rows, err := tx.query(provOpCounts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// InsertProvFinding raises (or re-opens) the finding of an operation.
func (tx *TenantTx) InsertProvFinding(f *ProvFinding, now time.Time) error {
	_, err := tx.exec(provFindingInsert, sql.Named("id", f.ID), sql.Named("op_id", f.OpID),
		sql.Named("connection_id", f.ConnectionID), sql.Named("code", f.Code), sql.Named("severity", f.Severity),
		sql.Named("title", f.Title), sql.Named("expected", f.Expected), sql.Named("observed", f.Observed),
		sql.Named("now", RT(now)))
	return err
}

// ProvFindings lists findings, newest first, optionally of one status or operation.
func (tx *TenantTx) ProvFindings(status, opID string) ([]*ProvFinding, error) {
	return collect(tx, scanProvFinding, provFindingList, sql.Named("status", status), sql.Named("op_id", opID))
}

// ResolveProvFindings closes an operation's open findings (it was retried
// and verified). It returns how many.
func (tx *TenantTx) ResolveProvFindings(opID string, now time.Time) (int64, error) {
	res, err := tx.exec(provFindingResolve, sql.Named("op_id", opID), sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
