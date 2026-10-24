package store

import (
	"database/sql"
	"time"
)

// Datasets (schema/0910_datasets.sql, issue #588): named lookup tables of distinct string values.
// The rules (limits, CSV, audit) live in internal/datasets.

// Dataset is a lookup table; Count is the number of its values.
type Dataset struct {
	ID          string
	Name        string
	Description string
	Version     int
	Count       int
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedBy   string
	UpdatedAt   time.Time
}

const dsCols = `d.id, d.name, d.description, d.version, (SELECT COUNT(*) FROM dataset_values v WHERE v.tenant_id = @tenant AND v.dataset_id = d.id),
	d.created_by, d.created_at, d.updated_by, d.updated_at`

var (
	dsList   = tq("datasets.list", `SELECT `+dsCols+` FROM datasets d WHERE d.tenant_id = @tenant ORDER BY d.name, d.id`)
	dsGet    = tq("datasets.get", `SELECT `+dsCols+` FROM datasets d WHERE d.tenant_id = @tenant AND d.id = @id`)
	dsByName = tq("datasets.by_name", `SELECT `+dsCols+` FROM datasets d WHERE d.tenant_id = @tenant AND d.name = @name`)
	dsIns    = tq("datasets.insert", `
		INSERT INTO datasets (id, tenant_id, name, description, version, created_by, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @name, @description, 1, @by, @now, @by, @now)`)
	dsUpd = tq("datasets.update", `
		UPDATE datasets SET name = @name, description = @description, version = version + 1, updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	dsTouch = tq("datasets.touch", `
		UPDATE datasets SET version = version + 1, updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	dsDel   = tq("datasets.delete", `DELETE FROM datasets WHERE tenant_id = @tenant AND id = @id`)
	dsCount = tq("datasets.count", `SELECT COUNT(*) FROM datasets WHERE tenant_id = @tenant`)

	dsvList = tq("dataset_values.list", `
		SELECT v.value FROM dataset_values v WHERE v.tenant_id = @tenant AND v.dataset_id = @id
		ORDER BY v.value LIMIT @limit OFFSET @offset`)
	dsvHas = tq("dataset_values.has", `
		SELECT COUNT(*) FROM dataset_values v WHERE v.tenant_id = @tenant AND v.dataset_id = @id AND v.value = @value`)
	dsvIns = tq("dataset_values.insert", `
		INSERT INTO dataset_values (tenant_id, dataset_id, value) VALUES (@tenant, @id, @value)
		ON CONFLICT (tenant_id, dataset_id, value) DO NOTHING`)
	dsvDel   = tq("dataset_values.delete", `DELETE FROM dataset_values WHERE tenant_id = @tenant AND dataset_id = @id AND value = @value`)
	dsvClear = tq("dataset_values.clear", `DELETE FROM dataset_values WHERE tenant_id = @tenant AND dataset_id = @id`)
	dsvCount = tq("dataset_values.count", `SELECT COUNT(*) FROM dataset_values v WHERE v.tenant_id = @tenant AND v.dataset_id = @id`)
)

func scanDataset(s scanner) (*Dataset, error) {
	var d Dataset
	var c, u string
	if err := s.Scan(&d.ID, &d.Name, &d.Description, &d.Version, &d.Count, &d.CreatedBy, &c, &d.UpdatedBy, &u); err != nil {
		return nil, err
	}
	var err error
	if d.CreatedAt, err = ParseRT(c); err != nil {
		return nil, err
	}
	d.UpdatedAt, err = ParseRT(u)
	return &d, err
}

// Datasets lists the tenant's datasets by name.
func (tx *TenantTx) Datasets() ([]*Dataset, error) { return collect(tx, scanDataset, dsList) }

// Dataset returns one by id; ErrNotFound if it is not the tenant's.
func (tx *TenantTx) Dataset(id string) (*Dataset, error) {
	return one(tx, scanDataset, dsGet, sql.Named("id", id))
}

// DatasetByName returns one by its (unique) name; ErrNotFound if there is none.
func (tx *TenantTx) DatasetByName(name string) (*Dataset, error) {
	return one(tx, scanDataset, dsByName, sql.Named("name", name))
}

// DatasetCount is how many datasets the tenant has.
func (tx *TenantTx) DatasetCount() (n int, err error) {
	err = tx.queryRow(dsCount).Scan(&n)
	return n, err
}

// InsertDataset creates a dataset at version 1. A taken name is a unique-constraint error; the service checks first.
func (tx *TenantTx) InsertDataset(id, name, description, by string, now time.Time) error {
	_, err := tx.exec(dsIns, sql.Named("id", id), sql.Named("name", name), sql.Named("description", description),
		sql.Named("by", by), sql.Named("now", RT(now)))
	return err
}

// UpdateDataset renames a dataset and moves its version on; false means the version moved.
func (tx *TenantTx) UpdateDataset(id string, version int, name, description, by string, now time.Time) (bool, error) {
	return changed(tx.exec(dsUpd, sql.Named("id", id), sql.Named("version", version), sql.Named("name", name),
		sql.Named("description", description), sql.Named("by", by), sql.Named("now", RT(now))))
}

// TouchDataset moves the version on after a change to its values; false means the version moved.
func (tx *TenantTx) TouchDataset(id string, version int, by string, now time.Time) (bool, error) {
	return changed(tx.exec(dsTouch, sql.Named("id", id), sql.Named("version", version), sql.Named("by", by), sql.Named("now", RT(now))))
}

// DeleteDataset removes a dataset and its values.
func (tx *TenantTx) DeleteDataset(id string) error {
	if _, err := tx.exec(dsvClear, sql.Named("id", id)); err != nil {
		return err
	}
	ok, err := changed(tx.exec(dsDel, sql.Named("id", id)))
	if err == nil && !ok {
		return ErrNotFound
	}
	return err
}

func changed(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DatasetValues lists a page of values in order.
func (tx *TenantTx) DatasetValues(id string, limit, offset int) ([]string, error) {
	vs, err := collect(tx, func(s scanner) (*string, error) {
		var v string
		return &v, s.Scan(&v)
	}, dsvList, sql.Named("id", id), sql.Named("limit", limit), sql.Named("offset", offset))
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, *v)
	}
	return out, err
}

// DatasetHas reports whether a dataset holds a value (exact match).
func (tx *TenantTx) DatasetHas(id, value string) (bool, error) {
	var n int
	err := tx.queryRow(dsvHas, sql.Named("id", id), sql.Named("value", value)).Scan(&n)
	return n > 0, err
}

// DatasetValueCount is how many values a dataset holds.
func (tx *TenantTx) DatasetValueCount(id string) (n int, err error) {
	err = tx.queryRow(dsvCount, sql.Named("id", id)).Scan(&n)
	return n, err
}

// AddDatasetValue adds a value; false if the dataset already held it.
func (tx *TenantTx) AddDatasetValue(id, value string) (bool, error) {
	return changed(tx.exec(dsvIns, sql.Named("id", id), sql.Named("value", value)))
}

// RemoveDatasetValue removes a value; false if the dataset did not hold it.
func (tx *TenantTx) RemoveDatasetValue(id, value string) (bool, error) {
	return changed(tx.exec(dsvDel, sql.Named("id", id), sql.Named("value", value)))
}

// ClearDatasetValues removes every value of a dataset.
func (tx *TenantTx) ClearDatasetValues(id string) error {
	_, err := tx.exec(dsvClear, sql.Named("id", id))
	return err
}
