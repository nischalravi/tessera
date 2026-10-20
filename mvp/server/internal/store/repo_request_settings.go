package store

import (
	"database/sql"
	"errors"
	"time"
)

// Tenant-wide access request settings (schema/0380_request_settings.sql, issue
// #298). One row per tenant; the defaults live in internal/requests, which
// treats ErrNotFound as "never set".

// RequestSettingsRow is the stored form of requests.Settings.
type RequestSettingsRow struct {
	JustificationRequired bool
	JustificationMin      int
	DefaultHours          *float64
	MaxHours              *float64
	AttachmentsAllowed    bool
	HistoryVisibility     string
	ForOthers             string
	Version               int
	UpdatedBy             string
	UpdatedAt             time.Time
}

var (
	rsGet = tq("request_settings.get", `
		SELECT s.justification_required, s.justification_min_length, s.default_hours, s.max_hours, s.attachments_allowed,
			s.history_visibility, s.for_others, s.version, s.updated_by, s.updated_at
		FROM request_settings s WHERE s.tenant_id = @tenant`)
	rsPut = tq("request_settings.put", `
		INSERT INTO request_settings (tenant_id, justification_required, justification_min_length, default_hours, max_hours,
			attachments_allowed, history_visibility, for_others, version, updated_by, updated_at)
		VALUES (@tenant, @justification_required, @justification_min_length, @default_hours, @max_hours,
			@attachments_allowed, @history_visibility, @for_others, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET justification_required = excluded.justification_required,
			justification_min_length = excluded.justification_min_length, default_hours = excluded.default_hours,
			max_hours = excluded.max_hours, attachments_allowed = excluded.attachments_allowed,
			history_visibility = excluded.history_visibility, for_others = excluded.for_others,
			version = request_settings.version + 1, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// RequestSettings returns the tenant's saved settings; ErrNotFound if it never saved any.
func (tx *TenantTx) RequestSettings() (*RequestSettingsRow, error) {
	return one(tx, func(s scanner) (*RequestSettingsRow, error) {
		var r RequestSettingsRow
		var req, att int
		var def, max sql.NullFloat64
		var at string
		if err := s.Scan(&req, &r.JustificationMin, &def, &max, &att, &r.HistoryVisibility, &r.ForOthers, &r.Version, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		r.JustificationRequired, r.AttachmentsAllowed = req == 1, att == 1
		if def.Valid {
			r.DefaultHours = &def.Float64
		}
		if max.Valid {
			r.MaxHours = &max.Float64
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, rsGet)
}

// PutRequestSettings replaces the tenant's settings and moves the version on.
func (tx *TenantTx) PutRequestSettings(r *RequestSettingsRow, now time.Time) error {
	var def, max any
	if r.DefaultHours != nil {
		def = *r.DefaultHours
	}
	if r.MaxHours != nil {
		max = *r.MaxHours
	}
	_, err := tx.exec(rsPut, sql.Named("justification_required", B(r.JustificationRequired)),
		sql.Named("justification_min_length", r.JustificationMin), sql.Named("default_hours", def), sql.Named("max_hours", max),
		sql.Named("attachments_allowed", B(r.AttachmentsAllowed)), sql.Named("history_visibility", r.HistoryVisibility),
		sql.Named("for_others", r.ForOthers), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// ErrNoRequestSettings reports whether err means the tenant never saved settings.
func ErrNoRequestSettings(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}
