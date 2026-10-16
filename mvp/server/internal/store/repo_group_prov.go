package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Group provisioning repository (schema/0283_group_prov.sql). The rules live in
// internal/groups/provisioning; this file is only its statements, all bound to
// the transaction's tenant.

// Provisioner modes.
const (
	ProvModeAdopt  = "adopt"
	ProvModeDryRun = "dry_run"
	ProvModeActive = "active"
	ProvModePaused = "paused"
)

// Sync op statuses (README rule 4: Verified only after a targeted re-read).
const (
	OpPlanned  = "planned"
	OpApplied  = "applied"
	OpVerified = "verified"
	OpFailed   = "failed"
	OpDrift    = "drift"
	OpSkipped  = "skipped"
)

// Sync run statuses and kinds.
const (
	RunRunning = "running"
	RunDone    = "done"
	RunHeld    = "held"
	RunFailed  = "failed"

	RunFull        = "full"
	RunIncremental = "incremental"
)

// Provisioner is one provisioning target. SecretEnc is the sealed credential
// JSON; it never leaves the server.
type Provisioner struct {
	ID           string
	Name         string
	TargetType   string
	ConnectionID *string
	Config       json.RawMessage
	SecretEnc    []byte
	Mode         string
	FullSchedule string
	Failsafe     json.RawMessage
	NeedsFull    bool
	ApproveNext  bool
	CreatedBy    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Version      int64
}

// ProvMark marks a folder or a group as provisionable.
type ProvMark struct {
	ProvisionerID string
	ObjectType    string // folder | group
	ObjectID      string
	Scope         string // self (a group) | one | sub (a folder)
	Include       bool
	Metadata      json.RawMessage
}

// SyncGroup is what a provisioner owns on the target for one group, with the
// last-read target state.
type SyncGroup struct {
	ProvisionerID  string
	GroupID        string
	TargetID       string
	TargetName     string
	StateHash      string
	ChangeToken    string
	StateCache     json.RawMessage // the last-read attributes and members (JSON), nil: nothing cached
	LastReadAt     *time.Time
	LastVerifiedAt *time.Time
	Status         string // adopted | synced | drift | failed | removed
}

// SyncRun is one full or incremental run.
type SyncRun struct {
	ID            string
	ProvisionerID string
	Kind          string
	Mode          string
	Status        string
	FromSeq       int64
	ToSeq         int64
	Summary       json.RawMessage
	Error         string
	StartedAt     time.Time
	FinishedAt    *time.Time
}

// SyncOp is one planned change on the target and how far it got.
type SyncOp struct {
	ID            string
	ProvisionerID string
	RunID         string
	Op            string // create | update | members | delete
	ObjectRef     string
	GroupID       string
	PayloadHash   string
	Detail        json.RawMessage
	CauseSeq      *int64
	Status        string
	Attempts      int
	Error         string
	PlannedAt     time.Time
	AppliedAt     *time.Time
	VerifiedAt    *time.Time
}

const provCols = `p.id, p.name, p.target_type, p.connection_id, p.config, p.secret_enc, p.mode, p.full_schedule, p.failsafe,
	p.needs_full, p.approve_next, p.created_by, p.created_at, p.updated_at, p.version`
const markCols = `m.provisioner_id, m.object_type, m.object_id, m.scope, m.include, m.metadata`
const syncGroupCols = `s.provisioner_id, s.group_id, s.target_id, s.target_name, s.state_hash, s.change_token, s.state_cache,
	s.last_read_at, s.last_verified_at, s.status`
const syncRunCols = `r.id, r.provisioner_id, r.kind, r.mode, r.status, r.from_seq, r.to_seq, r.summary, r.error, r.started_at, r.finished_at`
const opCols = `o.id, o.provisioner_id, o.run_id, o.op, o.object_ref, o.group_id, o.payload_hash, o.detail, o.cause_seq, o.status,
	o.attempts, o.error, o.planned_at, o.applied_at, o.verified_at`

var (
	provInsert = tq("grp_provisioners.insert", `
		INSERT INTO grp_provisioners (id, tenant_id, name, target_type, connection_id, config, secret_enc, mode, full_schedule,
			failsafe, needs_full, created_by, created_at, updated_at, version)
		VALUES (@id, @tenant, @name, @target_type, @connection_id, @config, @secret_enc, @mode, @full_schedule,
			@failsafe, 1, @created_by, @now, @now, 1)`)
	provGet    = tq("grp_provisioners.get", `SELECT `+provCols+` FROM grp_provisioners p WHERE p.tenant_id = @tenant AND p.id = @id`)
	provByName = tq("grp_provisioners.by_name", `SELECT `+provCols+` FROM grp_provisioners p
		WHERE p.tenant_id = @tenant AND p.name = @name`)
	provList = tq("grp_provisioners.list", `SELECT `+provCols+` FROM grp_provisioners p WHERE p.tenant_id = @tenant ORDER BY p.name`)
	// a nil secret_enc keeps the stored secret; every change needs a full sync
	provUpdate = tq("grp_provisioners.update", `
		UPDATE grp_provisioners SET name = @name, connection_id = @connection_id, config = @config,
			secret_enc = COALESCE(@secret_enc, secret_enc), mode = @mode, full_schedule = @full_schedule, failsafe = @failsafe,
			needs_full = 1, updated_at = @now, version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	provNeedsFull = tq("grp_provisioners.needs_full", `UPDATE grp_provisioners SET needs_full = @needs_full, approve_next = @approve
		WHERE tenant_id = @tenant AND id = @id`)
	provDelete = tq("grp_provisioners.delete", `DELETE FROM grp_provisioners WHERE tenant_id = @tenant AND id = @id`)

	markPut = tq("grp_provisionable.put", `
		INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope, include, metadata)
		VALUES (@tenant, @provisioner_id, @object_type, @object_id, @scope, @include, @metadata)
		ON CONFLICT (tenant_id, provisioner_id, object_type, object_id)
		DO UPDATE SET scope = excluded.scope, include = excluded.include, metadata = excluded.metadata`)
	markDelete = tq("grp_provisionable.delete", `DELETE FROM grp_provisionable
		WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id AND object_type = @object_type AND object_id = @object_id`)
	markList = tq("grp_provisionable.list", `SELECT `+markCols+` FROM grp_provisionable m
		WHERE m.tenant_id = @tenant AND m.provisioner_id = @provisioner_id ORDER BY m.object_type, m.object_id`)
	markDeleteAll = tq("grp_provisionable.delete_all", `DELETE FROM grp_provisionable
		WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id`)

	syncGroupPut = tq("grp_sync_groups.put", `
		INSERT INTO grp_sync_groups (tenant_id, provisioner_id, group_id, target_id, target_name, state_hash, change_token,
			state_cache, last_read_at, last_verified_at, status)
		VALUES (@tenant, @provisioner_id, @group_id, @target_id, @target_name, @state_hash, @change_token,
			@state_cache, @last_read_at, @last_verified_at, @status)
		ON CONFLICT (tenant_id, provisioner_id, group_id) DO UPDATE SET target_id = excluded.target_id,
			target_name = excluded.target_name, state_hash = excluded.state_hash, change_token = excluded.change_token,
			state_cache = excluded.state_cache, last_read_at = excluded.last_read_at,
			last_verified_at = excluded.last_verified_at, status = excluded.status`)
	syncGroupGet = tq("grp_sync_groups.get", `SELECT `+syncGroupCols+` FROM grp_sync_groups s
		WHERE s.tenant_id = @tenant AND s.provisioner_id = @provisioner_id AND s.group_id = @group_id`)
	syncGroupList = tq("grp_sync_groups.list", `SELECT `+syncGroupCols+` FROM grp_sync_groups s
		WHERE s.tenant_id = @tenant AND s.provisioner_id = @provisioner_id ORDER BY s.target_name, s.group_id
		LIMIT @limit OFFSET @offset`)
	syncGroupRetry = tq("grp_sync_groups.retry_due", `SELECT `+syncGroupCols+` FROM grp_sync_groups s
		WHERE s.tenant_id = @tenant AND s.provisioner_id = @provisioner_id AND s.status IN ('drift','failed')
		  AND (s.last_read_at IS NULL OR s.last_read_at < @before) ORDER BY s.group_id LIMIT @limit`)
	syncGroupDeleteAll = tq("grp_sync_groups.delete_all", `DELETE FROM grp_sync_groups
		WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id`)

	runInsert = tq("grp_sync_runs.insert", `
		INSERT INTO grp_sync_runs (id, tenant_id, provisioner_id, kind, mode, status, from_seq, to_seq, summary, started_at)
		VALUES (@id, @tenant, @provisioner_id, @kind, @mode, 'running', @from_seq, @to_seq, '{}', @started_at)`)
	runFinish = tq("grp_sync_runs.finish", `
		UPDATE grp_sync_runs SET status = @status, to_seq = @to_seq, summary = @summary, error = @error, finished_at = @finished_at
		WHERE tenant_id = @tenant AND id = @id`)
	runGet  = tq("grp_sync_runs.get", `SELECT `+syncRunCols+` FROM grp_sync_runs r WHERE r.tenant_id = @tenant AND r.id = @id`)
	runList = tq("grp_sync_runs.list", `SELECT `+syncRunCols+` FROM grp_sync_runs r
		WHERE r.tenant_id = @tenant AND r.provisioner_id = @provisioner_id ORDER BY r.started_at DESC, r.id DESC LIMIT @limit OFFSET @offset`)
	runLast = tq("grp_sync_runs.last", `SELECT `+syncRunCols+` FROM grp_sync_runs r
		WHERE r.tenant_id = @tenant AND r.provisioner_id = @provisioner_id AND r.kind = @kind
		ORDER BY r.started_at DESC, r.id DESC LIMIT 1`)
	runRunning = tq("grp_sync_runs.running", `SELECT count(*) FROM grp_sync_runs r
		WHERE r.tenant_id = @tenant AND r.provisioner_id = @provisioner_id AND r.status = 'running' AND r.started_at > @since`)
	runsFailAbandoned = tq("grp_sync_runs.fail_abandoned", `UPDATE grp_sync_runs SET status = 'failed', error = 'abandoned',
			finished_at = @now WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id AND status = 'running' AND started_at <= @since`)
	runDeleteAll = tq("grp_sync_runs.delete_all", `DELETE FROM grp_sync_runs
		WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id`)

	opInsert = tq("grp_sync_ops.insert", `
		INSERT INTO grp_sync_ops (id, tenant_id, provisioner_id, run_id, op, object_ref, group_id, payload_hash, detail, cause_seq,
			status, attempts, error, planned_at, applied_at, verified_at)
		VALUES (@id, @tenant, @provisioner_id, @run_id, @op, @object_ref, @group_id, @payload_hash, @detail, @cause_seq,
			@status, @attempts, @error, @planned_at, @applied_at, @verified_at)`)
	opUpdate = tq("grp_sync_ops.update", `
		UPDATE grp_sync_ops SET status = @status, attempts = @attempts, error = @error, detail = @detail,
			applied_at = @applied_at, verified_at = @verified_at
		WHERE tenant_id = @tenant AND id = @id`)
	opGet  = tq("grp_sync_ops.get", `SELECT `+opCols+` FROM grp_sync_ops o WHERE o.tenant_id = @tenant AND o.id = @id`)
	opList = tq("grp_sync_ops.list", `SELECT `+opCols+` FROM grp_sync_ops o
		WHERE o.tenant_id = @tenant AND o.provisioner_id = @provisioner_id AND (@run_id = '' OR o.run_id = @run_id)
		  AND (@status = '' OR o.status = @status)
		ORDER BY o.planned_at DESC, o.id DESC LIMIT @limit OFFSET @offset`)
	opCount = tq("grp_sync_ops.count", `SELECT o.status, count(*) FROM grp_sync_ops o
		WHERE o.tenant_id = @tenant AND o.provisioner_id = @provisioner_id GROUP BY o.status`)
	opDeleteAll = tq("grp_sync_ops.delete_all", `DELETE FROM grp_sync_ops
		WHERE tenant_id = @tenant AND provisioner_id = @provisioner_id`)
)

func scanProvisioner(s scanner) (*Provisioner, error) {
	var p Provisioner
	var conn, by sql.NullString
	var cfg, fs string
	var needs, approve int
	var created, updated string
	if err := s.Scan(&p.ID, &p.Name, &p.TargetType, &conn, &cfg, &p.SecretEnc, &p.Mode, &p.FullSchedule, &fs, &needs, &approve, &by,
		&created, &updated, &p.Version); err != nil {
		return nil, err
	}
	if conn.Valid {
		p.ConnectionID = &conn.String
	}
	p.Config, p.Failsafe, p.NeedsFull, p.ApproveNext, p.CreatedBy = json.RawMessage(cfg), json.RawMessage(fs), needs == 1, approve == 1, by.String
	var err error
	if p.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	p.UpdatedAt, err = ParseRT(updated)
	return &p, err
}

func scanProvMark(s scanner) (*ProvMark, error) {
	var m ProvMark
	var inc int
	var meta string
	if err := s.Scan(&m.ProvisionerID, &m.ObjectType, &m.ObjectID, &m.Scope, &inc, &meta); err != nil {
		return nil, err
	}
	m.Include, m.Metadata = inc == 1, json.RawMessage(meta)
	return &m, nil
}

func optTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := ParseRT(ns.String)
	return &t, err
}

func scanSyncGroup(s scanner) (*SyncGroup, error) {
	var g SyncGroup
	var tid, tname, hash, token, cache, read, verified sql.NullString
	if err := s.Scan(&g.ProvisionerID, &g.GroupID, &tid, &tname, &hash, &token, &cache, &read, &verified, &g.Status); err != nil {
		return nil, err
	}
	g.TargetID, g.TargetName, g.StateHash, g.ChangeToken = tid.String, tname.String, hash.String, token.String
	if cache.Valid {
		g.StateCache = json.RawMessage(cache.String)
	}
	var err error
	if g.LastReadAt, err = optTime(read); err != nil {
		return nil, err
	}
	g.LastVerifiedAt, err = optTime(verified)
	return &g, err
}

func scanSyncRun(s scanner) (*SyncRun, error) {
	var r SyncRun
	var summary string
	var errText, finished sql.NullString
	var started string
	if err := s.Scan(&r.ID, &r.ProvisionerID, &r.Kind, &r.Mode, &r.Status, &r.FromSeq, &r.ToSeq, &summary, &errText, &started, &finished); err != nil {
		return nil, err
	}
	r.Summary, r.Error = json.RawMessage(summary), errText.String
	var err error
	if r.StartedAt, err = ParseRT(started); err != nil {
		return nil, err
	}
	r.FinishedAt, err = optTime(finished)
	return &r, err
}

func scanSyncOp(s scanner) (*SyncOp, error) {
	var o SyncOp
	var run, group, errText, applied, verified sql.NullString
	var cause sql.NullInt64
	var detail, planned string
	if err := s.Scan(&o.ID, &o.ProvisionerID, &run, &o.Op, &o.ObjectRef, &group, &o.PayloadHash, &detail, &cause, &o.Status,
		&o.Attempts, &errText, &planned, &applied, &verified); err != nil {
		return nil, err
	}
	o.RunID, o.GroupID, o.Error, o.Detail = run.String, group.String, errText.String, json.RawMessage(detail)
	if cause.Valid {
		o.CauseSeq = &cause.Int64
	}
	var err error
	if o.PlannedAt, err = ParseRT(planned); err != nil {
		return nil, err
	}
	if o.AppliedAt, err = optTime(applied); err != nil {
		return nil, err
	}
	o.VerifiedAt, err = optTime(verified)
	return &o, err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------------------------------------------------------------- provisioners

// InsertProvisioner stores a new provisioner (mode as given, needs_full set).
func (tx *TenantTx) InsertProvisioner(p *Provisioner) error {
	var conn any
	if p.ConnectionID != nil {
		conn = *p.ConnectionID
	}
	var secret any
	if p.SecretEnc != nil {
		secret = p.SecretEnc
	}
	_, err := tx.exec(provInsert, sql.Named("id", p.ID), sql.Named("name", p.Name), sql.Named("target_type", p.TargetType),
		sql.Named("connection_id", conn), sql.Named("config", string(p.Config)), sql.Named("secret_enc", secret),
		sql.Named("mode", p.Mode), sql.Named("full_schedule", p.FullSchedule), sql.Named("failsafe", string(p.Failsafe)),
		sql.Named("created_by", nullStr(p.CreatedBy)), sql.Named("now", RT(p.CreatedAt)))
	return err
}

// Provisioner returns one provisioner or ErrNotFound.
func (tx *TenantTx) Provisioner(id string) (*Provisioner, error) {
	return one(tx, scanProvisioner, provGet, sql.Named("id", id))
}

// ProvisionerByName returns a provisioner by name or ErrNotFound.
func (tx *TenantTx) ProvisionerByName(name string) (*Provisioner, error) {
	return one(tx, scanProvisioner, provByName, sql.Named("name", name))
}

// Provisioners lists the tenant's provisioners by name.
func (tx *TenantTx) Provisioners() ([]*Provisioner, error) {
	return collect(tx, scanProvisioner, provList)
}

// UpdateProvisioner replaces the editable fields if p.Version is still the
// stored one (ErrVersionConflict otherwise). A nil SecretEnc keeps the stored secret.
func (tx *TenantTx) UpdateProvisioner(p *Provisioner, now time.Time) error {
	var conn any
	if p.ConnectionID != nil {
		conn = *p.ConnectionID
	}
	var secret any
	if p.SecretEnc != nil {
		secret = p.SecretEnc
	}
	res, err := tx.exec(provUpdate, sql.Named("id", p.ID), sql.Named("name", p.Name), sql.Named("connection_id", conn),
		sql.Named("config", string(p.Config)), sql.Named("secret_enc", secret), sql.Named("mode", p.Mode),
		sql.Named("full_schedule", p.FullSchedule), sql.Named("failsafe", string(p.Failsafe)), sql.Named("now", RT(now)),
		sql.Named("version", p.Version))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := tx.Provisioner(p.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	return nil
}

// SetProvisionerNeedsFull sets or clears the "run a full sync next" flag, and
// whether an admin approved the failsafe limits for that run.
func (tx *TenantTx) SetProvisionerNeedsFull(id string, needs, approve bool) error {
	_, err := tx.exec(provNeedsFull, sql.Named("id", id), sql.Named("needs_full", B(needs)), sql.Named("approve", B(approve)))
	return err
}

// DeleteProvisioner removes a provisioner and everything that belongs to it.
func (tx *TenantTx) DeleteProvisioner(id string) error {
	for _, s := range []tstmt{opDeleteAll, runDeleteAll, syncGroupDeleteAll, markDeleteAll} {
		if _, err := tx.exec(s, sql.Named("provisioner_id", id)); err != nil {
			return err
		}
	}
	res, err := tx.exec(provDelete, sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- marks

// PutProvMark creates or replaces a mark.
func (tx *TenantTx) PutProvMark(m *ProvMark) error {
	meta := m.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage("{}")
	}
	_, err := tx.exec(markPut, sql.Named("provisioner_id", m.ProvisionerID), sql.Named("object_type", m.ObjectType),
		sql.Named("object_id", m.ObjectID), sql.Named("scope", m.Scope), sql.Named("include", B(m.Include)),
		sql.Named("metadata", string(meta)))
	return err
}

// DeleteProvMark removes a mark; ErrNotFound if there was none.
func (tx *TenantTx) DeleteProvMark(provisioner, objectType, objectID string) error {
	res, err := tx.exec(markDelete, sql.Named("provisioner_id", provisioner), sql.Named("object_type", objectType),
		sql.Named("object_id", objectID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ProvMarks lists a provisioner's marks.
func (tx *TenantTx) ProvMarks(provisioner string) ([]*ProvMark, error) {
	return collect(tx, scanProvMark, markList, sql.Named("provisioner_id", provisioner))
}

// ---------------------------------------------------------------- sync groups

// PutSyncGroup creates or replaces what a provisioner owns for a group.
func (tx *TenantTx) PutSyncGroup(g *SyncGroup) error {
	var cache any
	if g.StateCache != nil {
		cache = string(g.StateCache)
	}
	var read, verified any
	if g.LastReadAt != nil {
		read = RT(*g.LastReadAt)
	}
	if g.LastVerifiedAt != nil {
		verified = RT(*g.LastVerifiedAt)
	}
	_, err := tx.exec(syncGroupPut, sql.Named("provisioner_id", g.ProvisionerID), sql.Named("group_id", g.GroupID),
		sql.Named("target_id", nullStr(g.TargetID)), sql.Named("target_name", nullStr(g.TargetName)),
		sql.Named("state_hash", nullStr(g.StateHash)), sql.Named("change_token", nullStr(g.ChangeToken)),
		sql.Named("state_cache", cache), sql.Named("last_read_at", read), sql.Named("last_verified_at", verified),
		sql.Named("status", g.Status))
	return err
}

// SyncGroup returns what a provisioner owns for a group, or ErrNotFound.
func (tx *TenantTx) SyncGroup(provisioner, group string) (*SyncGroup, error) {
	return one(tx, scanSyncGroup, syncGroupGet, sql.Named("provisioner_id", provisioner), sql.Named("group_id", group))
}

// SyncGroups pages what a provisioner owns, by target name; limit <= 0 is 1000.
func (tx *TenantTx) SyncGroups(provisioner string, limit, offset int) ([]*SyncGroup, error) {
	if limit <= 0 {
		limit = 1000
	}
	return collect(tx, scanSyncGroup, syncGroupList, sql.Named("provisioner_id", provisioner), sql.Named("limit", limit),
		sql.Named("offset", offset))
}

// SyncGroupsRetryDue lists groups left in drift or failed whose last read is
// before the given time, so an incremental pass can try them again.
func (tx *TenantTx) SyncGroupsRetryDue(provisioner string, before time.Time, limit int) ([]*SyncGroup, error) {
	if limit <= 0 {
		limit = 1000
	}
	return collect(tx, scanSyncGroup, syncGroupRetry, sql.Named("provisioner_id", provisioner), sql.Named("before", RT(before)),
		sql.Named("limit", limit))
}

// ---------------------------------------------------------------- runs and ops

// InsertSyncRun records a run as running.
func (tx *TenantTx) InsertSyncRun(r *SyncRun) error {
	_, err := tx.exec(runInsert, sql.Named("id", r.ID), sql.Named("provisioner_id", r.ProvisionerID), sql.Named("kind", r.Kind),
		sql.Named("mode", r.Mode), sql.Named("from_seq", r.FromSeq), sql.Named("to_seq", r.ToSeq),
		sql.Named("started_at", RT(r.StartedAt)))
	return err
}

// FinishSyncRun closes a run with its status and summary.
func (tx *TenantTx) FinishSyncRun(r *SyncRun) error {
	if r.FinishedAt == nil {
		return errors.New("store: FinishSyncRun without a finish time")
	}
	summary := r.Summary
	if len(summary) == 0 {
		summary = json.RawMessage("{}")
	}
	_, err := tx.exec(runFinish, sql.Named("id", r.ID), sql.Named("status", r.Status), sql.Named("to_seq", r.ToSeq),
		sql.Named("summary", string(summary)), sql.Named("error", nullStr(r.Error)), sql.Named("finished_at", RT(*r.FinishedAt)))
	return err
}

// SyncRun returns one run or ErrNotFound.
func (tx *TenantTx) SyncRun(id string) (*SyncRun, error) {
	return one(tx, scanSyncRun, runGet, sql.Named("id", id))
}

// SyncRuns pages a provisioner's runs, newest first.
func (tx *TenantTx) SyncRuns(provisioner string, limit, offset int) ([]*SyncRun, error) {
	if limit <= 0 {
		limit = 50
	}
	return collect(tx, scanSyncRun, runList, sql.Named("provisioner_id", provisioner), sql.Named("limit", limit),
		sql.Named("offset", offset))
}

// LastSyncRun returns the newest run of a kind, or ErrNotFound.
func (tx *TenantTx) LastSyncRun(provisioner, kind string) (*SyncRun, error) {
	return one(tx, scanSyncRun, runLast, sql.Named("provisioner_id", provisioner), sql.Named("kind", kind))
}

// SyncRunActive says whether a run started after since has not finished.
func (tx *TenantTx) SyncRunActive(provisioner string, since time.Time) (bool, error) {
	n, err := tx.count(runRunning, sql.Named("provisioner_id", provisioner), sql.Named("since", RT(since)))
	return n > 0, err
}

// FailAbandonedSyncRuns closes runs that started at or before since and never
// finished (a crash mid-run).
func (tx *TenantTx) FailAbandonedSyncRuns(provisioner string, since, now time.Time) error {
	_, err := tx.exec(runsFailAbandoned, sql.Named("provisioner_id", provisioner), sql.Named("since", RT(since)),
		sql.Named("now", RT(now)))
	return err
}

// InsertSyncOp records a planned (or skipped) op.
func (tx *TenantTx) InsertSyncOp(o *SyncOp) error {
	detail := o.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	var cause, applied, verified any
	if o.CauseSeq != nil {
		cause = *o.CauseSeq
	}
	if o.AppliedAt != nil {
		applied = RT(*o.AppliedAt)
	}
	if o.VerifiedAt != nil {
		verified = RT(*o.VerifiedAt)
	}
	_, err := tx.exec(opInsert, sql.Named("id", o.ID), sql.Named("provisioner_id", o.ProvisionerID),
		sql.Named("run_id", nullStr(o.RunID)), sql.Named("op", o.Op), sql.Named("object_ref", o.ObjectRef),
		sql.Named("group_id", nullStr(o.GroupID)), sql.Named("payload_hash", o.PayloadHash), sql.Named("detail", string(detail)),
		sql.Named("cause_seq", cause), sql.Named("status", o.Status), sql.Named("attempts", o.Attempts),
		sql.Named("error", nullStr(o.Error)), sql.Named("planned_at", RT(o.PlannedAt)), sql.Named("applied_at", applied),
		sql.Named("verified_at", verified))
	return err
}

// UpdateSyncOp stores an op's progress.
func (tx *TenantTx) UpdateSyncOp(o *SyncOp) error {
	detail := o.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	var applied, verified any
	if o.AppliedAt != nil {
		applied = RT(*o.AppliedAt)
	}
	if o.VerifiedAt != nil {
		verified = RT(*o.VerifiedAt)
	}
	_, err := tx.exec(opUpdate, sql.Named("id", o.ID), sql.Named("status", o.Status), sql.Named("attempts", o.Attempts),
		sql.Named("error", nullStr(o.Error)), sql.Named("detail", string(detail)), sql.Named("applied_at", applied),
		sql.Named("verified_at", verified))
	return err
}

// SyncOp returns one op or ErrNotFound.
func (tx *TenantTx) SyncOp(id string) (*SyncOp, error) {
	return one(tx, scanSyncOp, opGet, sql.Named("id", id))
}

// SyncOpFilter selects ops; empty fields do not filter.
type SyncOpFilter struct {
	RunID  string
	Status string
	Limit  int
	Offset int
}

// SyncOps pages a provisioner's ops, newest first.
func (tx *TenantTx) SyncOps(provisioner string, f SyncOpFilter) ([]*SyncOp, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanSyncOp, opList, sql.Named("provisioner_id", provisioner), sql.Named("run_id", f.RunID),
		sql.Named("status", f.Status), sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// SyncOpCounts counts a provisioner's ops by status.
func (tx *TenantTx) SyncOpCounts(provisioner string) (map[string]int, error) {
	rows, err := tx.query(opCount, sql.Named("provisioner_id", provisioner))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}
