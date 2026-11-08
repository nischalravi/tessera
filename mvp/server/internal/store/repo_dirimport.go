package store

import (
	"database/sql"
	"time"
)

// The snapshot a directory CSV import left in one manual source (schema/0965_dirimport.sql). The parsing,
// plan and ingest rules live in internal/flatfile; the store only holds the rows.

// Kinds of snapshot row.
const (
	ImportPeople       = "people"
	ImportEntitlements = "entitlements"
)

// ImportRecord is one row of the snapshot.
type ImportRecord struct {
	System     string
	Kind       string
	Key        string // the external id of the identity or group
	Data       string // normalised row, JSON
	Hash       string
	ImportedBy string
	ImportedAt time.Time
}

// ImportSource is a manual source and how many rows of one kind its snapshot holds.
type ImportSource struct {
	System string
	Kind   string
	Rows   int
}

var (
	importRecordPut = tq("dirimport_records.put", `
		INSERT INTO dirimport_records (tenant_id, system, kind, rec_key, data, row_hash, imported_by, imported_at)
		VALUES (@tenant, @system, @kind, @rec_key, @data, @row_hash, @by, @at)
		ON CONFLICT (tenant_id, system, kind, rec_key) DO UPDATE SET data = excluded.data, row_hash = excluded.row_hash,
			imported_by = excluded.imported_by, imported_at = excluded.imported_at`)
	importRecordList = tq("dirimport_records.list", `
		SELECT r.system, r.kind, r.rec_key, r.data, r.row_hash, r.imported_by, r.imported_at FROM dirimport_records r
		WHERE r.tenant_id = @tenant AND r.system = @system AND r.kind = @kind ORDER BY r.rec_key`)
	importRecordDelete = tq("dirimport_records.delete", `
		DELETE FROM dirimport_records WHERE tenant_id = @tenant AND system = @system AND kind = @kind AND rec_key = @rec_key`)
	importRecordSystems = tq("dirimport_records.systems", `
		SELECT r.system, r.kind, COUNT(*) FROM dirimport_records r WHERE r.tenant_id = @tenant
		GROUP BY r.system, r.kind ORDER BY r.system, r.kind`)
	importRecordBy = tq("dirimport_records.by", `
		SELECT r.imported_by FROM dirimport_records r WHERE r.tenant_id = @tenant AND r.kind = @kind AND r.rec_key = @rec_key
		ORDER BY r.imported_at DESC, r.system LIMIT 1`)
	importRecordSource = tq("dirimport_records.source", `
		SELECT r.system FROM dirimport_records r WHERE r.tenant_id = @tenant AND r.kind = @kind AND r.rec_key = @rec_key
		ORDER BY r.system LIMIT 1`)
)

// PutImportRecord stores (or replaces) one snapshot row.
func (tx *TenantTx) PutImportRecord(r *ImportRecord) error {
	_, err := tx.exec(importRecordPut, sql.Named("system", r.System), sql.Named("kind", r.Kind), sql.Named("rec_key", r.Key),
		sql.Named("data", r.Data), sql.Named("row_hash", r.Hash), sql.Named("by", r.ImportedBy), sql.Named("at", RT(r.ImportedAt)))
	return err
}

// ImportRecords lists a manual source's snapshot of one kind, ordered by key.
func (tx *TenantTx) ImportRecords(system, kind string) ([]*ImportRecord, error) {
	return collect(tx, func(s scanner) (*ImportRecord, error) {
		var r ImportRecord
		var at string
		if err := s.Scan(&r.System, &r.Kind, &r.Key, &r.Data, &r.Hash, &r.ImportedBy, &at); err != nil {
			return nil, err
		}
		var err error
		r.ImportedAt, err = ParseRT(at)
		return &r, err
	}, importRecordList, sql.Named("system", system), sql.Named("kind", kind))
}

// DeleteImportRecord removes one snapshot row.
func (tx *TenantTx) DeleteImportRecord(system, kind, key string) error {
	_, err := tx.exec(importRecordDelete, sql.Named("system", system), sql.Named("kind", kind), sql.Named("rec_key", key))
	return err
}

// ImportSources lists the manual sources that hold rows, per kind.
func (tx *TenantTx) ImportSources() ([]*ImportSource, error) {
	return collect(tx, func(s scanner) (*ImportSource, error) {
		var o ImportSource
		err := s.Scan(&o.System, &o.Kind, &o.Rows)
		return &o, err
	}, importRecordSystems)
}

// ImportRecordSource names the manual source that holds the object of this kind and external id, "" if none.
func (tx *TenantTx) ImportRecordSource(kind, key string) (string, error) {
	rows, err := collect(tx, func(s scanner) (*string, error) {
		var v string
		err := s.Scan(&v)
		return &v, err
	}, importRecordSource, sql.Named("kind", kind), sql.Named("rec_key", key))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return *rows[0], nil
}

// ImportedByOf is who last imported or edited the object of this kind and external id in a manual source: the
// platform user id of the admin (the display name for a row an older server wrote or a caller with no user), ""
// if no manual source holds it.
func (tx *TenantTx) ImportedByOf(kind, key string) (string, error) {
	rows, err := collect(tx, func(s scanner) (*string, error) {
		var v string
		err := s.Scan(&v)
		return &v, err
	}, importRecordBy, sql.Named("kind", kind), sql.Named("rec_key", key))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return *rows[0], nil
}
