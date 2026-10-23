package store

import (
	"database/sql"
	"time"
)

// Label settings (schema/0765_tenant_label_settings.sql): the language, renamed terms and email-logo switch of Admin >
// Branding & labels. One row per tenant.

// LabelSettingsRow is the saved row; Labels is the JSON object of renamed terms.
type LabelSettingsRow struct {
	DefaultLanguage string
	EmailLogo       bool
	Labels          string
	Version         int
	UpdatedBy       string
	UpdatedAt       time.Time
}

var (
	labelSettingsGet = tq("tenant_label_settings.get", `
		SELECT s.default_language, s.email_logo, s.labels, s.version, s.updated_by, s.updated_at
		FROM tenant_label_settings s WHERE s.tenant_id = @tenant`)
	labelSettingsPut = tq("tenant_label_settings.put", `
		INSERT INTO tenant_label_settings (tenant_id, default_language, email_logo, labels, version, updated_by, updated_at)
		VALUES (@tenant, @default_language, @email_logo, @labels, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET default_language = excluded.default_language, email_logo = excluded.email_logo,
			labels = excluded.labels, version = tenant_label_settings.version + 1, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
)

// LabelSettings returns the tenant's saved label settings; ErrNotFound if it never saved any.
func (tx *TenantTx) LabelSettings() (*LabelSettingsRow, error) {
	return one(tx, func(s scanner) (*LabelSettingsRow, error) {
		var r LabelSettingsRow
		var logo int
		var at string
		if err := s.Scan(&r.DefaultLanguage, &logo, &r.Labels, &r.Version, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		r.EmailLogo = logo == 1
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, labelSettingsGet)
}

// PutLabelSettings replaces the tenant's label settings and moves the version on.
func (tx *TenantTx) PutLabelSettings(r *LabelSettingsRow, now time.Time) error {
	_, err := tx.exec(labelSettingsPut, sql.Named("default_language", r.DefaultLanguage), sql.Named("email_logo", B(r.EmailLogo)),
		sql.Named("labels", r.Labels), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}
