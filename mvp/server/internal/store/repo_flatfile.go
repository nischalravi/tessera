package store

import (
	"database/sql"
	"time"
)

// Flat-file import for disconnected applications (schema/0352_flatfile.sql).
// The parsing, delta and task rules live in internal/flatfile; the store only
// holds the rows.

// Flat-file upload and task states.
const (
	FlatUploadApplied  = "applied"
	FlatUploadRejected = "rejected"

	FlatTaskOpen      = "open"
	FlatTaskConfirmed = "confirmed"
	FlatTaskClosed    = "closed"
)

// ---------------------------------------------------------------- mappings

// FlatMapping is the saved column mapping of one disconnected app (system).
// AccountCols and EntitlementCols are JSON owned by internal/flatfile.
type FlatMapping struct {
	ID              string
	System          string
	Name            string
	Owner           string
	AccountCols     string
	EntitlementCols string
	CreatedBy       string
	CreatedAt       time.Time
	UpdatedBy       string
	UpdatedAt       time.Time
}

const flatMappingCols = `m.id, m.system, m.name, m.owner, m.account_cols, m.entitlement_cols, m.created_by, m.created_at,
	m.updated_by, m.updated_at`

var (
	flatMappingPut = tq("flatfile_mappings.put", `
		INSERT INTO flatfile_mappings (id, tenant_id, system, name, owner, account_cols, entitlement_cols, created_by, created_at,
			updated_by, updated_at)
		VALUES (@id, @tenant, @system, @name, @owner, @account_cols, @entitlement_cols, @by, @at, @by, @at)
		ON CONFLICT (tenant_id, system) DO UPDATE SET name = excluded.name, owner = excluded.owner,
			account_cols = excluded.account_cols, entitlement_cols = excluded.entitlement_cols,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	flatMappingGet = tq("flatfile_mappings.get", `
		SELECT `+flatMappingCols+` FROM flatfile_mappings m WHERE m.tenant_id = @tenant AND m.system = @system`)
	flatMappingList = tq("flatfile_mappings.list", `
		SELECT `+flatMappingCols+` FROM flatfile_mappings m WHERE m.tenant_id = @tenant ORDER BY m.system`)
)

func scanFlatMapping(s scanner) (*FlatMapping, error) {
	var m FlatMapping
	var created, updated string
	if err := s.Scan(&m.ID, &m.System, &m.Name, &m.Owner, &m.AccountCols, &m.EntitlementCols, &m.CreatedBy, &created,
		&m.UpdatedBy, &updated); err != nil {
		return nil, err
	}
	var err error
	if m.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	m.UpdatedAt, err = ParseRT(updated)
	return &m, err
}

// PutFlatMapping saves the mapping of m.System, replacing the one there is.
func (tx *TenantTx) PutFlatMapping(m *FlatMapping) error {
	id := NewID()
	_, err := tx.exec(flatMappingPut, sql.Named("id", id), sql.Named("system", m.System), sql.Named("name", m.Name),
		sql.Named("owner", m.Owner), sql.Named("account_cols", m.AccountCols), sql.Named("entitlement_cols", m.EntitlementCols),
		sql.Named("by", m.UpdatedBy), sql.Named("at", RT(m.UpdatedAt)))
	return err
}

// FlatMapping returns the mapping of a system or ErrNotFound.
func (tx *TenantTx) FlatMapping(system string) (*FlatMapping, error) {
	return one(tx, scanFlatMapping, flatMappingGet, sql.Named("system", system))
}

// FlatMappings lists the tenant's mappings by system.
func (tx *TenantTx) FlatMappings() ([]*FlatMapping, error) {
	return collect(tx, scanFlatMapping, flatMappingList)
}

// ---------------------------------------------------------------- uploads

// FlatUpload is one upload in the history: what was uploaded, by whom, and
// its delta.
type FlatUpload struct {
	ID             string
	MappingID      string
	System         string
	Kind           string // accounts | entitlements
	Source         string // api (a later SFTP drop uses sftp)
	Filename       string
	SHA256         string
	SizeBytes      int
	Status         string // applied | rejected
	RowsTotal      int
	RowsRejected   int
	Added          int
	Removed        int
	Changed        int
	Unchanged      int
	TasksConfirmed int
	UploadedBy     string
	UploadedAt     time.Time
}

// FlatUploadError is one rejected row (Row 0: the file as a whole).
type FlatUploadError struct {
	Seq     int
	Row     int
	Column  string
	Code    string
	Message string
}

// FlatChange is one line of an upload's delta.
type FlatChange struct {
	Seq    int
	Kind   string // accounts | entitlements
	Change string // added | removed | changed
	Label  string
	Detail string
}

const flatUploadCols = `u.id, u.mapping_id, u.system, u.kind, u.source, u.filename, u.sha256, u.size_bytes, u.status,
	u.rows_total, u.rows_rejected, u.added, u.removed, u.changed, u.unchanged, u.tasks_confirmed, u.uploaded_by, u.uploaded_at`

var (
	flatUploadInsert = tq("flatfile_uploads.insert", `
		INSERT INTO flatfile_uploads (id, tenant_id, mapping_id, system, kind, source, filename, sha256, size_bytes, status,
			rows_total, rows_rejected, added, removed, changed, unchanged, tasks_confirmed, uploaded_by, uploaded_at)
		VALUES (@id, @tenant, @mapping_id, @system, @kind, @source, @filename, @sha256, @size_bytes, @status,
			@rows_total, @rows_rejected, @added, @removed, @changed, @unchanged, @tasks_confirmed, @uploaded_by, @uploaded_at)`)
	flatUploadGet = tq("flatfile_uploads.get", `
		SELECT `+flatUploadCols+` FROM flatfile_uploads u WHERE u.tenant_id = @tenant AND u.id = @id`)
	flatUploadList = tq("flatfile_uploads.list", `
		SELECT `+flatUploadCols+` FROM flatfile_uploads u WHERE u.tenant_id = @tenant
		ORDER BY u.uploaded_at DESC, u.id LIMIT 200`)
	flatUploadListSystem = tq("flatfile_uploads.list_system", `
		SELECT `+flatUploadCols+` FROM flatfile_uploads u WHERE u.tenant_id = @tenant AND u.system = @system
		ORDER BY u.uploaded_at DESC, u.id LIMIT 200`)
	flatErrorInsert = tq("flatfile_upload_errors.insert", `
		INSERT INTO flatfile_upload_errors (tenant_id, upload_id, seq, row_num, col, code, message)
		VALUES (@tenant, @upload_id, @seq, @row_num, @col, @code, @message)`)
	flatErrorList = tq("flatfile_upload_errors.list", `
		SELECT e.seq, e.row_num, e.col, e.code, e.message FROM flatfile_upload_errors e
		WHERE e.tenant_id = @tenant AND e.upload_id = @upload_id ORDER BY e.seq`)
	flatChangeInsert = tq("flatfile_changes.insert", `
		INSERT INTO flatfile_changes (tenant_id, upload_id, seq, kind, change, label, detail)
		VALUES (@tenant, @upload_id, @seq, @kind, @change, @label, @detail)`)
	flatChangeList = tq("flatfile_changes.list", `
		SELECT c.seq, c.kind, c.change, c.label, c.detail FROM flatfile_changes c
		WHERE c.tenant_id = @tenant AND c.upload_id = @upload_id ORDER BY c.seq`)
)

func scanFlatUpload(s scanner) (*FlatUpload, error) {
	var u FlatUpload
	var at string
	if err := s.Scan(&u.ID, &u.MappingID, &u.System, &u.Kind, &u.Source, &u.Filename, &u.SHA256, &u.SizeBytes, &u.Status,
		&u.RowsTotal, &u.RowsRejected, &u.Added, &u.Removed, &u.Changed, &u.Unchanged, &u.TasksConfirmed, &u.UploadedBy, &at); err != nil {
		return nil, err
	}
	var err error
	u.UploadedAt, err = ParseRT(at)
	return &u, err
}

// InsertFlatUpload adds an upload to the history (u.ID is set when empty).
func (tx *TenantTx) InsertFlatUpload(u *FlatUpload) error {
	if u.ID == "" {
		u.ID = NewID()
	}
	_, err := tx.exec(flatUploadInsert, sql.Named("id", u.ID), sql.Named("mapping_id", u.MappingID),
		sql.Named("system", u.System), sql.Named("kind", u.Kind), sql.Named("source", u.Source),
		sql.Named("filename", u.Filename), sql.Named("sha256", u.SHA256), sql.Named("size_bytes", u.SizeBytes),
		sql.Named("status", u.Status), sql.Named("rows_total", u.RowsTotal), sql.Named("rows_rejected", u.RowsRejected),
		sql.Named("added", u.Added), sql.Named("removed", u.Removed), sql.Named("changed", u.Changed),
		sql.Named("unchanged", u.Unchanged), sql.Named("tasks_confirmed", u.TasksConfirmed),
		sql.Named("uploaded_by", u.UploadedBy), sql.Named("uploaded_at", RT(u.UploadedAt)))
	return err
}

// FlatUpload returns one upload or ErrNotFound.
func (tx *TenantTx) FlatUpload(id string) (*FlatUpload, error) {
	return one(tx, scanFlatUpload, flatUploadGet, sql.Named("id", id))
}

// FlatUploads lists the newest uploads (at most 200), of one system when
// system is not empty.
func (tx *TenantTx) FlatUploads(system string) ([]*FlatUpload, error) {
	if system != "" {
		return collect(tx, scanFlatUpload, flatUploadListSystem, sql.Named("system", system))
	}
	return collect(tx, scanFlatUpload, flatUploadList)
}

// InsertFlatUploadError records one rejected row of an upload.
func (tx *TenantTx) InsertFlatUploadError(uploadID string, e FlatUploadError) error {
	_, err := tx.exec(flatErrorInsert, sql.Named("upload_id", uploadID), sql.Named("seq", e.Seq),
		sql.Named("row_num", e.Row), sql.Named("col", e.Column), sql.Named("code", e.Code), sql.Named("message", e.Message))
	return err
}

// FlatUploadErrors lists an upload's rejected rows in order.
func (tx *TenantTx) FlatUploadErrors(uploadID string) ([]*FlatUploadError, error) {
	return collect(tx, func(s scanner) (*FlatUploadError, error) {
		var e FlatUploadError
		err := s.Scan(&e.Seq, &e.Row, &e.Column, &e.Code, &e.Message)
		return &e, err
	}, flatErrorList, sql.Named("upload_id", uploadID))
}

// InsertFlatChange records one line of an upload's delta.
func (tx *TenantTx) InsertFlatChange(uploadID string, c FlatChange) error {
	_, err := tx.exec(flatChangeInsert, sql.Named("upload_id", uploadID), sql.Named("seq", c.Seq),
		sql.Named("kind", c.Kind), sql.Named("change", c.Change), sql.Named("label", c.Label), sql.Named("detail", c.Detail))
	return err
}

// FlatChanges lists an upload's delta in order.
func (tx *TenantTx) FlatChanges(uploadID string) ([]*FlatChange, error) {
	return collect(tx, func(s scanner) (*FlatChange, error) {
		var c FlatChange
		err := s.Scan(&c.Seq, &c.Kind, &c.Change, &c.Label, &c.Detail)
		return &c, err
	}, flatChangeList, sql.Named("upload_id", uploadID))
}

// ---------------------------------------------------------------- records

// FlatRecord is one row of the snapshot the last applied upload left.
type FlatRecord struct {
	System   string
	Kind     string
	Key      string
	Data     string // normalised row, JSON
	Hash     string
	UploadID string
}

var (
	flatRecordPut = tq("flatfile_records.put", `
		INSERT INTO flatfile_records (tenant_id, system, kind, rec_key, data, row_hash, upload_id)
		VALUES (@tenant, @system, @kind, @rec_key, @data, @row_hash, @upload_id)
		ON CONFLICT (tenant_id, system, kind, rec_key) DO UPDATE SET data = excluded.data, row_hash = excluded.row_hash,
			upload_id = excluded.upload_id`)
	flatRecordList = tq("flatfile_records.list", `
		SELECT r.system, r.kind, r.rec_key, r.data, r.row_hash, r.upload_id FROM flatfile_records r
		WHERE r.tenant_id = @tenant AND r.system = @system AND r.kind = @kind ORDER BY r.rec_key`)
	flatRecordDelete = tq("flatfile_records.delete", `
		DELETE FROM flatfile_records WHERE tenant_id = @tenant AND system = @system AND kind = @kind AND rec_key = @rec_key`)
)

// PutFlatRecord stores (or replaces) one snapshot row.
func (tx *TenantTx) PutFlatRecord(r *FlatRecord) error {
	_, err := tx.exec(flatRecordPut, sql.Named("system", r.System), sql.Named("kind", r.Kind), sql.Named("rec_key", r.Key),
		sql.Named("data", r.Data), sql.Named("row_hash", r.Hash), sql.Named("upload_id", r.UploadID))
	return err
}

// FlatRecords lists a system's snapshot of one kind, ordered by key.
func (tx *TenantTx) FlatRecords(system, kind string) ([]*FlatRecord, error) {
	return collect(tx, func(s scanner) (*FlatRecord, error) {
		var r FlatRecord
		err := s.Scan(&r.System, &r.Kind, &r.Key, &r.Data, &r.Hash, &r.UploadID)
		return &r, err
	}, flatRecordList, sql.Named("system", system), sql.Named("kind", kind))
}

// DeleteFlatRecord removes one snapshot row.
func (tx *TenantTx) DeleteFlatRecord(system, kind, key string) error {
	_, err := tx.exec(flatRecordDelete, sql.Named("system", system), sql.Named("kind", kind), sql.Named("rec_key", key))
	return err
}

// ---------------------------------------------------------------- tasks

// FlatTask is a manual fulfilment task of a disconnected app.
type FlatTask struct {
	ID             string
	System         string
	Kind           string // disable_account | remove_entitlement
	AccountID      int64
	AccountXID     string
	AccountLabel   string
	Entitlement    string // "" for disable_account
	IdentityID     *int64
	Trigger        string // leaver, revoke, review, ...
	Status         string // open | confirmed | closed
	CreatedBy      string
	CreatedAt      time.Time
	ClosedBy       *string
	ClosedAt       *time.Time
	CloseReason    string
	ClosedUploadID *string
}

const flatTaskCols = `t.id, t.system, t.kind, t.account_id, t.account_xid, t.account_label, t.entitlement, t.identity_id,
	t.trigger, t.status, t.created_by, t.created_at, t.closed_by, t.closed_at, t.close_reason, t.closed_upload_id`

var (
	flatTaskInsert = tq("flatfile_tasks.insert", `
		INSERT INTO flatfile_tasks (id, tenant_id, system, kind, account_id, account_xid, account_label, entitlement,
			identity_id, trigger, status, created_by, created_at)
		VALUES (@id, @tenant, @system, @kind, @account_id, @account_xid, @account_label, @entitlement,
			@identity_id, @trigger, 'open', @created_by, @created_at)`)
	flatTaskGet = tq("flatfile_tasks.get", `
		SELECT `+flatTaskCols+` FROM flatfile_tasks t WHERE t.tenant_id = @tenant AND t.id = @id`)
	flatTaskList = tq("flatfile_tasks.list", `
		SELECT `+flatTaskCols+` FROM flatfile_tasks t WHERE t.tenant_id = @tenant
		ORDER BY t.created_at DESC, t.id LIMIT 500`)
	flatTaskListStatus = tq("flatfile_tasks.list_status", `
		SELECT `+flatTaskCols+` FROM flatfile_tasks t WHERE t.tenant_id = @tenant AND t.status = @status
		ORDER BY t.created_at DESC, t.id LIMIT 500`)
	flatTaskOpenSystem = tq("flatfile_tasks.open_system", `
		SELECT `+flatTaskCols+` FROM flatfile_tasks t WHERE t.tenant_id = @tenant AND t.system = @system AND t.status = 'open'
		ORDER BY t.created_at, t.id`)
	flatTaskOpenFor = tq("flatfile_tasks.open_for", `
		SELECT `+flatTaskCols+` FROM flatfile_tasks t WHERE t.tenant_id = @tenant AND t.status = 'open'
		AND t.account_id = @account_id AND t.kind = @kind AND t.entitlement = @entitlement`)
	flatTaskClose = tq("flatfile_tasks.close", `
		UPDATE flatfile_tasks SET status = @status, closed_by = @by, closed_at = @at, close_reason = @reason,
			closed_upload_id = @upload_id
		WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)
)

func scanFlatTask(s scanner) (*FlatTask, error) {
	var t FlatTask
	var ident sql.NullInt64
	var created string
	var by, at, upload sql.NullString
	if err := s.Scan(&t.ID, &t.System, &t.Kind, &t.AccountID, &t.AccountXID, &t.AccountLabel, &t.Entitlement, &ident,
		&t.Trigger, &t.Status, &t.CreatedBy, &created, &by, &at, &t.CloseReason, &upload); err != nil {
		return nil, err
	}
	t.IdentityID, t.ClosedBy, t.ClosedUploadID = intp(ident), strp(by), strp(upload)
	var err error
	if t.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	t.ClosedAt, err = rtp(at)
	return &t, err
}

// InsertFlatTask adds an open task (t.ID is set when empty).
func (tx *TenantTx) InsertFlatTask(t *FlatTask) error {
	if t.ID == "" {
		t.ID = NewID()
	}
	_, err := tx.exec(flatTaskInsert, sql.Named("id", t.ID), sql.Named("system", t.System), sql.Named("kind", t.Kind),
		sql.Named("account_id", t.AccountID), sql.Named("account_xid", t.AccountXID), sql.Named("account_label", t.AccountLabel),
		sql.Named("entitlement", t.Entitlement), sql.Named("identity_id", IP(t.IdentityID)), sql.Named("trigger", t.Trigger),
		sql.Named("created_by", t.CreatedBy), sql.Named("created_at", RT(t.CreatedAt)))
	return err
}

// FlatTask returns one task or ErrNotFound.
func (tx *TenantTx) FlatTask(id string) (*FlatTask, error) {
	return one(tx, scanFlatTask, flatTaskGet, sql.Named("id", id))
}

// FlatTasks lists the newest tasks (at most 500), of one status when status
// is not empty.
func (tx *TenantTx) FlatTasks(status string) ([]*FlatTask, error) {
	if status != "" {
		return collect(tx, scanFlatTask, flatTaskListStatus, sql.Named("status", status))
	}
	return collect(tx, scanFlatTask, flatTaskList)
}

// OpenFlatTasks lists a system's open tasks, oldest first.
func (tx *TenantTx) OpenFlatTasks(system string) ([]*FlatTask, error) {
	return collect(tx, scanFlatTask, flatTaskOpenSystem, sql.Named("system", system))
}

// OpenFlatTask returns the open task of an account's step, or ErrNotFound.
// entitlement is "" for disable_account.
func (tx *TenantTx) OpenFlatTask(accountID int64, kind, entitlement string) (*FlatTask, error) {
	return one(tx, scanFlatTask, flatTaskOpenFor, sql.Named("account_id", accountID), sql.Named("kind", kind),
		sql.Named("entitlement", entitlement))
}

// CloseFlatTask ends an open task as confirmed or closed (ErrNotFound when it
// is not open any more). uploadID is the confirming upload, if any.
func (tx *TenantTx) CloseFlatTask(id, status, by string, at time.Time, reason string, uploadID *string) error {
	return tx.execOne(flatTaskClose, sql.Named("id", id), sql.Named("status", status), sql.Named("by", by),
		sql.Named("at", RT(at)), sql.Named("reason", reason), sql.Named("upload_id", SP(uploadID)))
}
