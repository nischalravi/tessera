package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Tenant-level SoD page configuration (schema/0490_sod_view_settings.sql, issue
// #298). One row per tenant; internal/sod treats ErrNotFound as "never set".

// SodViewSettingsRow is the stored form of the SoD page configuration.
type SodViewSettingsRow struct {
	Columns   []string
	Filters   []string
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

var (
	sodViewGet = tq("sod_view_settings.get", `
		SELECT s.visible_columns, s.visible_filters, s.version, s.updated_by, s.updated_at
		FROM sod_view_settings s WHERE s.tenant_id = @tenant`)
	sodViewPut = tq("sod_view_settings.put", `
		INSERT INTO sod_view_settings (tenant_id, visible_columns, visible_filters, version, updated_by, updated_at)
		VALUES (@tenant, @visible_columns, @visible_filters, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET visible_columns = excluded.visible_columns,
			visible_filters = excluded.visible_filters, version = sod_view_settings.version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// SodViewSettings returns the tenant's saved configuration; ErrNotFound if it never saved any.
func (tx *TenantTx) SodViewSettings() (*SodViewSettingsRow, error) {
	return one(tx, func(s scanner) (*SodViewSettingsRow, error) {
		var r SodViewSettingsRow
		var cols, filters, at string
		if err := s.Scan(&cols, &filters, &r.Version, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cols), &r.Columns); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(filters), &r.Filters); err != nil {
			return nil, err
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, sodViewGet)
}

// PutSodViewSettings replaces the tenant's configuration and moves the version on.
func (tx *TenantTx) PutSodViewSettings(r *SodViewSettingsRow, now time.Time) error {
	cols, err := JSON(nonNilStrings(r.Columns))
	if err != nil {
		return err
	}
	filters, err := JSON(nonNilStrings(r.Filters))
	if err != nil {
		return err
	}
	_, err = tx.exec(sodViewPut, sql.Named("visible_columns", cols), sql.Named("visible_filters", filters),
		sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ErrNoSettings reports whether err means a settings row was never saved.
func ErrNoSettings(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}
