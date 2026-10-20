package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Group loader repository (schema/0377_group_loaders.sql, issue #53, GR-10).
// The rules of loaders (sources, failsafes, subject resolution) live in
// internal/groups/loaders; this file is only the statements, all bound to the
// transaction's tenant.

// Loader statuses and run kinds and statuses.
const (
	LoaderEnabled  = "enabled"
	LoaderDisabled = "disabled"
	LoaderHeld     = "held"

	RunFull        = "full"
	RunIncremental = "incremental"
	RunPreview     = "preview"

	RunApplied   = "applied"
	RunHeld      = "held"
	RunFailed    = "failed"
	RunApproved  = "approved"
	RunRejected  = "rejected"
	RunPreviewed = "previewed"
)

// GrpLoader is a loader definition. Config is JSON typed per loader type and
// holds no secret; SecretEnc is the sealed credential (never returned by the
// API). Failsafe is JSON.
type GrpLoader struct {
	ID              string
	TenantID        tenancy.ID
	Name            string
	Type            string
	ConnectionID    *string
	Config          string
	SecretEnc       []byte
	TargetFolder    FolderID
	NameTemplate    string
	OnMissingGroup  string
	AndGroup        *GroupID
	Schedule        string
	IncrementalSecs *int64
	Failsafe        string
	Status          string
	Cursor          *string
	LastFullAt      *time.Time
	LastIncrAt      *time.Time
	CreatedBy       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Version         int64
}

// GrpLoaderRun is one run of a loader. Plan is what the run computed (JSON);
// a held run keeps it so an approval applies it as it was computed. Impact is
// the JSON downstream impact of a held run.
type GrpLoaderRun struct {
	ID              string
	TenantID        tenancy.ID
	LoaderID        string
	Kind            string
	StartedAt       time.Time
	FinishedAt      *time.Time
	Status          string
	SourceRows      *int64
	GroupsSeen      *int64
	Adds            *int64
	Removes         *int64
	Unresolved      *int64
	FailsafeTripped *string
	Impact          *string
	Plan            *string
	SourceHash      *string
	Error           *string
	CursorAfter     *string
	RequestedBy     *string
	DecidedBy       *string
	DecidedAt       *time.Time
}

// GrpLoaderUnresolved is a subject a source named that matches no identity.
// Groups is a JSON list of group names.
type GrpLoaderUnresolved struct {
	LoaderID   string
	Source     string
	Identifier string
	FirstSeen  time.Time
	LastSeen   time.Time
	Groups     string
}

const loaderCols = `l.id, l.tenant_id, l.name, l.type, l.connection_id, l.config, l.secret_enc, l.target_folder_id,
	l.name_template, l.on_missing_group, l.and_group_id, l.schedule, l.incremental_secs, l.failsafe, l.status, l.cursor,
	l.last_full_at, l.last_incremental_at, l.created_by, l.created_at, l.updated_at, l.version`

const loaderRunCols = `r.id, r.tenant_id, r.loader_id, r.kind, r.started_at, r.finished_at, r.status, r.source_rows,
	r.groups_seen, r.adds, r.removes, r.unresolved, r.failsafe_tripped, r.impact, r.plan, r.source_hash, r.error,
	r.cursor_after, r.requested_by, r.decided_by, r.decided_at`

const loaderUnresolvedCols = `u.loader_id, u.source, u.identifier, u.first_seen, u.last_seen, u.groups`

var (
	grpLoaderInsert = tq("grp_loaders.insert", `
		INSERT INTO grp_loaders (id, tenant_id, name, type, connection_id, config, secret_enc, target_folder_id, name_template,
			on_missing_group, and_group_id, schedule, incremental_secs, failsafe, status, cursor, last_full_at,
			last_incremental_at, created_by, created_at, updated_at, version)
		VALUES (@id, @tenant, @name, @type, @connection_id, @config, @secret_enc, @target_folder_id, @name_template,
			@on_missing_group, @and_group_id, @schedule, @incremental_secs, @failsafe, @status, @cursor, @last_full_at,
			@last_incremental_at, @created_by, @created_at, @updated_at, 1)`)
	grpLoaderGet = tq("grp_loaders.get", `SELECT `+loaderCols+` FROM grp_loaders l WHERE l.tenant_id = @tenant AND l.id = @id`)
	// names are unique case-insensitively
	grpLoaderByName = tq("grp_loaders.by_name", `SELECT `+loaderCols+` FROM grp_loaders l
		WHERE l.tenant_id = @tenant AND lower(l.name) = lower(@name)`)
	grpLoaderList   = tq("grp_loaders.list", `SELECT `+loaderCols+` FROM grp_loaders l WHERE l.tenant_id = @tenant ORDER BY lower(l.name), l.id`)
	grpLoaderUpdate = tq("grp_loaders.update", `
		UPDATE grp_loaders SET name = @name, connection_id = @connection_id, config = @config, secret_enc = @secret_enc,
			name_template = @name_template, on_missing_group = @on_missing_group, and_group_id = @and_group_id,
			schedule = @schedule, incremental_secs = @incremental_secs, failsafe = @failsafe, status = @status,
			updated_at = @updated_at, version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	grpLoaderSetStatus = tq("grp_loaders.set_status", `UPDATE grp_loaders SET status = @status, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	grpLoaderRan = tq("grp_loaders.ran", `UPDATE grp_loaders SET cursor = COALESCE(@cursor, cursor),
		last_full_at = CASE WHEN @kind = 'full' THEN @at ELSE last_full_at END,
		last_incremental_at = CASE WHEN @kind = 'incremental' THEN @at ELSE last_incremental_at END
		WHERE tenant_id = @tenant AND id = @id`)

	grpLoaderRunInsert = tq("grp_loader_runs.insert", `
		INSERT INTO grp_loader_runs (id, tenant_id, loader_id, kind, started_at, finished_at, status, source_rows, groups_seen,
			adds, removes, unresolved, failsafe_tripped, impact, plan, source_hash, error, cursor_after, requested_by,
			decided_by, decided_at)
		VALUES (@id, @tenant, @loader_id, @kind, @started_at, @finished_at, @status, @source_rows, @groups_seen,
			@adds, @removes, @unresolved, @failsafe_tripped, @impact, @plan, @source_hash, @error, @cursor_after,
			@requested_by, @decided_by, @decided_at)`)
	grpLoaderRunGet = tq("grp_loader_runs.get", `SELECT `+loaderRunCols+` FROM grp_loader_runs r
		WHERE r.tenant_id = @tenant AND r.id = @id`)
	grpLoaderRunsOf = tq("grp_loader_runs.of_loader", `SELECT `+loaderRunCols+` FROM grp_loader_runs r
		WHERE r.tenant_id = @tenant AND r.loader_id = @loader_id ORDER BY r.started_at DESC, r.id LIMIT @limit OFFSET @offset`)
	grpLoaderRunsCount = tq("grp_loader_runs.count", `SELECT count(*) FROM grp_loader_runs r
		WHERE r.tenant_id = @tenant AND r.loader_id = @loader_id`)
	grpLoaderRunsHeld = tq("grp_loader_runs.held", `SELECT `+loaderRunCols+` FROM grp_loader_runs r
		WHERE r.tenant_id = @tenant AND r.status = 'held' ORDER BY r.started_at, r.id`)
	// the newest run that did something (a preview is not a run of the loader); kind '' is any
	grpLoaderRunLast = tq("grp_loader_runs.last", `SELECT `+loaderRunCols+` FROM grp_loader_runs r
		WHERE r.tenant_id = @tenant AND r.loader_id = @loader_id AND r.kind <> 'preview' AND (@kind = '' OR r.kind = @kind)
		ORDER BY r.started_at DESC, r.id LIMIT 1`)
	grpLoaderRunDecide = tq("grp_loader_runs.decide", `UPDATE grp_loader_runs SET status = @status, decided_by = @decided_by,
		decided_at = @decided_at WHERE tenant_id = @tenant AND id = @id AND status = 'held'`)

	grpLoaderUnresolvedUpsert = tq("grp_loader_unresolved.upsert", `
		INSERT INTO grp_loader_unresolved (tenant_id, loader_id, source, identifier, first_seen, last_seen, groups)
		VALUES (@tenant, @loader_id, @source, @identifier, @first_seen, @last_seen, @groups)
		ON CONFLICT (tenant_id, loader_id, source, identifier) DO UPDATE SET last_seen = excluded.last_seen, groups = excluded.groups`)
	grpLoaderUnresolvedPrune = tq("grp_loader_unresolved.prune", `DELETE FROM grp_loader_unresolved
		WHERE tenant_id = @tenant AND loader_id = @loader_id AND last_seen < @before`)
	grpLoaderUnresolvedList = tq("grp_loader_unresolved.list", `SELECT `+loaderUnresolvedCols+` FROM grp_loader_unresolved u
		WHERE u.tenant_id = @tenant AND u.loader_id = @loader_id ORDER BY u.source, u.identifier LIMIT @limit OFFSET @offset`)
	grpLoaderUnresolvedCount = tq("grp_loader_unresolved.count", `SELECT count(*) FROM grp_loader_unresolved u
		WHERE u.tenant_id = @tenant AND u.loader_id = @loader_id`)
	// resolved subjects leave the list: the keys a run resolved
	grpLoaderUnresolvedDelete = tq("grp_loader_unresolved.delete", `DELETE FROM grp_loader_unresolved
		WHERE tenant_id = @tenant AND loader_id = @loader_id AND source = @source AND identifier = @identifier`)

	grpGroupsOfLoader = tq("grp_groups.of_loader", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.loader_id = @loader_id ORDER BY lower(g.name), g.id`)
	grpDmBySource = tq("grp_dm.by_source", `SELECT `+dmCols+` FROM grp_direct_memberships d
		WHERE d.tenant_id = @tenant AND d.group_id = @group_id AND d.list_id = @list_id AND d.source = @source
		  AND d.source_ref = @source_ref ORDER BY d.id`)
)

func scanGrpLoader(s scanner) (*GrpLoader, error) {
	var l GrpLoader
	var tenant, created, updated string
	var conn, andGroup, by, cursor, fullAt, incrAt sql.NullString
	var incr sql.NullInt64
	if err := s.Scan(&l.ID, &tenant, &l.Name, &l.Type, &conn, &l.Config, &l.SecretEnc, &l.TargetFolder, &l.NameTemplate,
		&l.OnMissingGroup, &andGroup, &l.Schedule, &incr, &l.Failsafe, &l.Status, &cursor, &fullAt, &incrAt, &by, &created,
		&updated, &l.Version); err != nil {
		return nil, err
	}
	var err error
	if l.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	l.ConnectionID, l.IncrementalSecs, l.CreatedBy, l.Cursor = strp(conn), intp(incr), strp(by), strp(cursor)
	if andGroup.Valid {
		g := GroupID(andGroup.String)
		l.AndGroup = &g
	}
	if l.LastFullAt, err = rtp(fullAt); err != nil {
		return nil, err
	}
	if l.LastIncrAt, err = rtp(incrAt); err != nil {
		return nil, err
	}
	if l.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	l.UpdatedAt, err = ParseRT(updated)
	return &l, err
}

func scanGrpLoaderRun(s scanner) (*GrpLoaderRun, error) {
	var r GrpLoaderRun
	var tenant, started string
	var finished, tripped, impact, plan, hash, runErr, cursor, req, decBy, decAt sql.NullString
	var rows, groups, adds, removes, unresolved sql.NullInt64
	if err := s.Scan(&r.ID, &tenant, &r.LoaderID, &r.Kind, &started, &finished, &r.Status, &rows, &groups, &adds, &removes,
		&unresolved, &tripped, &impact, &plan, &hash, &runErr, &cursor, &req, &decBy, &decAt); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	r.SourceRows, r.GroupsSeen, r.Adds, r.Removes, r.Unresolved = intp(rows), intp(groups), intp(adds), intp(removes), intp(unresolved)
	r.FailsafeTripped, r.Impact, r.Plan, r.SourceHash, r.Error = strp(tripped), strp(impact), strp(plan), strp(hash), strp(runErr)
	r.CursorAfter, r.RequestedBy, r.DecidedBy = strp(cursor), strp(req), strp(decBy)
	if r.StartedAt, err = ParseRT(started); err != nil {
		return nil, err
	}
	if r.FinishedAt, err = rtp(finished); err != nil {
		return nil, err
	}
	r.DecidedAt, err = rtp(decAt)
	return &r, err
}

func scanGrpLoaderUnresolved(s scanner) (*GrpLoaderUnresolved, error) {
	var u GrpLoaderUnresolved
	var first, last string
	if err := s.Scan(&u.LoaderID, &u.Source, &u.Identifier, &first, &last, &u.Groups); err != nil {
		return nil, err
	}
	var err error
	if u.FirstSeen, err = ParseRT(first); err != nil {
		return nil, err
	}
	u.LastSeen, err = ParseRT(last)
	return &u, err
}

// InsertGrpLoader adds a loader (a zero ID gets a fresh one) at version 1.
// ErrDuplicate if the tenant has a loader of this name.
func (tx *TenantTx) InsertGrpLoader(l *GrpLoader) error {
	if err := tx.own(l.TenantID); err != nil {
		return err
	}
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	if l.Status == "" {
		l.Status = LoaderEnabled
	}
	var andGroup any
	if l.AndGroup != nil {
		andGroup = string(*l.AndGroup)
	}
	_, err := tx.exec(grpLoaderInsert, sql.Named("id", l.ID), sql.Named("name", l.Name), sql.Named("type", l.Type),
		sql.Named("connection_id", SP(l.ConnectionID)), sql.Named("config", l.Config), sql.Named("secret_enc", l.SecretEnc),
		sql.Named("target_folder_id", string(l.TargetFolder)), sql.Named("name_template", l.NameTemplate),
		sql.Named("on_missing_group", l.OnMissingGroup), sql.Named("and_group_id", andGroup), sql.Named("schedule", l.Schedule),
		sql.Named("incremental_secs", IP(l.IncrementalSecs)), sql.Named("failsafe", l.Failsafe), sql.Named("status", l.Status),
		sql.Named("cursor", SP(l.Cursor)), sql.Named("last_full_at", RTP(l.LastFullAt)),
		sql.Named("last_incremental_at", RTP(l.LastIncrAt)), sql.Named("created_by", SP(l.CreatedBy)),
		sql.Named("created_at", RT(l.CreatedAt)), sql.Named("updated_at", RT(l.UpdatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	if err == nil {
		l.TenantID, l.Version = tx.tenant, 1
	}
	return err
}

// GrpLoader returns one loader or ErrNotFound.
func (tx *TenantTx) GrpLoader(id string) (*GrpLoader, error) {
	return one(tx, scanGrpLoader, grpLoaderGet, sql.Named("id", id))
}

// GrpLoaderByName finds a loader by name, case-insensitively, or ErrNotFound.
func (tx *TenantTx) GrpLoaderByName(name string) (*GrpLoader, error) {
	return one(tx, scanGrpLoader, grpLoaderByName, sql.Named("name", name))
}

// GrpLoaders lists the tenant's loaders by name.
func (tx *TenantTx) GrpLoaders() ([]*GrpLoader, error) {
	return collect(tx, scanGrpLoader, grpLoaderList)
}

// UpdateGrpLoader writes the editable fields of l if the stored version is
// still l.Version, and bumps it. ErrNotFound for a missing (or other tenant's)
// loader, ErrVersionConflict for a stale version, ErrDuplicate for a name taken.
func (tx *TenantTx) UpdateGrpLoader(l *GrpLoader) error {
	var andGroup any
	if l.AndGroup != nil {
		andGroup = string(*l.AndGroup)
	}
	res, err := tx.exec(grpLoaderUpdate, sql.Named("id", l.ID), sql.Named("name", l.Name),
		sql.Named("connection_id", SP(l.ConnectionID)), sql.Named("config", l.Config), sql.Named("secret_enc", l.SecretEnc),
		sql.Named("name_template", l.NameTemplate), sql.Named("on_missing_group", l.OnMissingGroup),
		sql.Named("and_group_id", andGroup), sql.Named("schedule", l.Schedule), sql.Named("incremental_secs", IP(l.IncrementalSecs)),
		sql.Named("failsafe", l.Failsafe), sql.Named("status", l.Status), sql.Named("updated_at", RT(l.UpdatedAt)),
		sql.Named("version", l.Version))
	if isUnique(err) {
		return ErrDuplicate
	}
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.GrpLoader(l.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	l.Version++
	return nil
}

// SetGrpLoaderStatus sets enabled, disabled or held (ErrNotFound if this
// tenant has no such loader).
func (tx *TenantTx) SetGrpLoaderStatus(id, status string, at time.Time) error {
	return tx.execOne(grpLoaderSetStatus, sql.Named("id", id), sql.Named("status", status), sql.Named("at", RT(at)))
}

// RecordGrpLoaderRan stamps the time of a full or incremental run that
// applied and, if cursor is not nil, advances the incremental cursor.
func (tx *TenantTx) RecordGrpLoaderRan(id, kind string, at time.Time, cursor *string) error {
	return tx.execOne(grpLoaderRan, sql.Named("id", id), sql.Named("kind", kind), sql.Named("at", RT(at)),
		sql.Named("cursor", SP(cursor)))
}

// InsertGrpLoaderRun records a run (a zero ID gets a fresh one).
func (tx *TenantTx) InsertGrpLoaderRun(r *GrpLoaderRun) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	_, err := tx.exec(grpLoaderRunInsert, sql.Named("id", r.ID), sql.Named("loader_id", r.LoaderID), sql.Named("kind", r.Kind),
		sql.Named("started_at", RT(r.StartedAt)), sql.Named("finished_at", RTP(r.FinishedAt)), sql.Named("status", r.Status),
		sql.Named("source_rows", IP(r.SourceRows)), sql.Named("groups_seen", IP(r.GroupsSeen)), sql.Named("adds", IP(r.Adds)),
		sql.Named("removes", IP(r.Removes)), sql.Named("unresolved", IP(r.Unresolved)),
		sql.Named("failsafe_tripped", SP(r.FailsafeTripped)), sql.Named("impact", SP(r.Impact)), sql.Named("plan", SP(r.Plan)),
		sql.Named("source_hash", SP(r.SourceHash)), sql.Named("error", SP(r.Error)), sql.Named("cursor_after", SP(r.CursorAfter)),
		sql.Named("requested_by", SP(r.RequestedBy)), sql.Named("decided_by", SP(r.DecidedBy)), sql.Named("decided_at", RTP(r.DecidedAt)))
	if err == nil {
		r.TenantID = tx.tenant
	}
	return err
}

// GrpLoaderRun returns one run or ErrNotFound.
func (tx *TenantTx) GrpLoaderRun(id string) (*GrpLoaderRun, error) {
	return one(tx, scanGrpLoaderRun, grpLoaderRunGet, sql.Named("id", id))
}

// GrpLoaderRuns lists a loader's runs, newest first.
func (tx *TenantTx) GrpLoaderRuns(loaderID string, limit, offset int) ([]*GrpLoaderRun, error) {
	return collect(tx, scanGrpLoaderRun, grpLoaderRunsOf, sql.Named("loader_id", loaderID), sql.Named("limit", limit),
		sql.Named("offset", offset))
}

// GrpLoaderRunCount counts a loader's runs.
func (tx *TenantTx) GrpLoaderRunCount(loaderID string) (int, error) {
	return tx.count(grpLoaderRunsCount, sql.Named("loader_id", loaderID))
}

// GrpLoaderHeldRuns lists the runs that await a decision, oldest first.
func (tx *TenantTx) GrpLoaderHeldRuns() ([]*GrpLoaderRun, error) {
	return collect(tx, scanGrpLoaderRun, grpLoaderRunsHeld)
}

// GrpLoaderLastRun is the newest run of a loader of the kind (full or
// incremental; "" for either), or ErrNotFound.
func (tx *TenantTx) GrpLoaderLastRun(loaderID, kind string) (*GrpLoaderRun, error) {
	return one(tx, scanGrpLoaderRun, grpLoaderRunLast, sql.Named("loader_id", loaderID), sql.Named("kind", kind))
}

// DecideGrpLoaderRun marks a held run approved or rejected (ErrNotFound if
// this tenant has no such held run).
func (tx *TenantTx) DecideGrpLoaderRun(id, status, by string, at time.Time) error {
	return tx.execOne(grpLoaderRunDecide, sql.Named("id", id), sql.Named("status", status), sql.Named("decided_by", by),
		sql.Named("decided_at", RT(at)))
}

// UpsertGrpLoaderUnresolved records a subject a run could not resolve: the
// first sighting is kept, the last and the group list are updated.
func (tx *TenantTx) UpsertGrpLoaderUnresolved(u *GrpLoaderUnresolved) error {
	_, err := tx.exec(grpLoaderUnresolvedUpsert, sql.Named("loader_id", u.LoaderID), sql.Named("source", u.Source),
		sql.Named("identifier", u.Identifier), sql.Named("first_seen", RT(u.FirstSeen)), sql.Named("last_seen", RT(u.LastSeen)),
		sql.Named("groups", u.Groups))
	return err
}

// PruneGrpLoaderUnresolved forgets the subjects of a loader that no run has
// seen since before (they resolved, or the source stopped naming them).
func (tx *TenantTx) PruneGrpLoaderUnresolved(loaderID string, before time.Time) (int, error) {
	res, err := tx.exec(grpLoaderUnresolvedPrune, sql.Named("loader_id", loaderID), sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteGrpLoaderUnresolved forgets one subject (an incremental run resolved it).
func (tx *TenantTx) DeleteGrpLoaderUnresolved(loaderID, source, identifier string) error {
	_, err := tx.exec(grpLoaderUnresolvedDelete, sql.Named("loader_id", loaderID), sql.Named("source", source),
		sql.Named("identifier", identifier))
	return err
}

// GrpLoaderUnresolved lists a loader's unresolved subjects.
func (tx *TenantTx) GrpLoaderUnresolved(loaderID string, limit, offset int) ([]*GrpLoaderUnresolved, error) {
	return collect(tx, scanGrpLoaderUnresolved, grpLoaderUnresolvedList, sql.Named("loader_id", loaderID),
		sql.Named("limit", limit), sql.Named("offset", offset))
}

// GrpLoaderUnresolvedCount counts a loader's unresolved subjects.
func (tx *TenantTx) GrpLoaderUnresolvedCount(loaderID string) (int, error) {
	return tx.count(grpLoaderUnresolvedCount, sql.Named("loader_id", loaderID))
}

// GrpGroupsOfLoader lists the groups a loader created, whatever their status.
func (tx *TenantTx) GrpGroupsOfLoader(loaderID string) ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupsOfLoader, sql.Named("loader_id", loaderID))
}

// GrpDirectBySource lists the direct rows of a group's list that a source put
// there (a loader id as sourceRef, "loader" as source).
func (tx *TenantTx) GrpDirectBySource(group GroupID, list ListID, source, sourceRef string) ([]*DirectMembership, error) {
	return collect(tx, scanGrpDirect, grpDmBySource, sql.Named("group_id", string(group)), sql.Named("list_id", string(list)),
		sql.Named("source", source), sql.Named("source_ref", sourceRef))
}
