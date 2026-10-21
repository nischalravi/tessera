package store

import (
	"database/sql"
	"time"
)

// Campaign configuration per review type (schema/0491_review_types.sql, issue
// #298). internal/reviews holds the defaults for a type with no row.

// ReviewTypeSettingsRow is the stored form of reviews.TypeSettings.
type ReviewTypeSettingsRow struct {
	ReviewType         string
	Enabled            bool
	ReviewerSource     string // owner | owner_or_backup | fixed
	ReviewerIdentityID *int64
	FallbackReviewerID *int64
	OnIncomplete       string // revoke | escalate | keep
	EscalationDays     int
	Version            int
	UpdatedBy          string
	UpdatedAt          time.Time
}

// TemplateReviewType is the review type a template runs as.
type TemplateReviewType struct {
	TemplateID string
	ReviewType string
}

const reviewTypeCols = `s.review_type, s.enabled, s.reviewer_source, s.reviewer_identity_id, s.fallback_reviewer_id,
	s.on_incomplete, s.escalation_days, s.version, s.updated_by, s.updated_at`

var (
	reviewTypesList = tq("review_type_settings.list", `
		SELECT `+reviewTypeCols+` FROM review_type_settings s WHERE s.tenant_id = @tenant ORDER BY s.review_type`)
	reviewTypesGet = tq("review_type_settings.get", `
		SELECT `+reviewTypeCols+` FROM review_type_settings s WHERE s.tenant_id = @tenant AND s.review_type = @review_type`)
	reviewTypesPut = tq("review_type_settings.put", `
		INSERT INTO review_type_settings (tenant_id, review_type, enabled, reviewer_source, reviewer_identity_id,
			fallback_reviewer_id, on_incomplete, escalation_days, version, updated_by, updated_at)
		VALUES (@tenant, @review_type, @enabled, @reviewer_source, @reviewer_identity_id, @fallback_reviewer_id,
			@on_incomplete, @escalation_days, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, review_type) DO UPDATE SET enabled = excluded.enabled,
			reviewer_source = excluded.reviewer_source, reviewer_identity_id = excluded.reviewer_identity_id,
			fallback_reviewer_id = excluded.fallback_reviewer_id, on_incomplete = excluded.on_incomplete,
			escalation_days = excluded.escalation_days, version = review_type_settings.version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	templateTypesList = tq("review_template_types.list", `
		SELECT t.template_id, t.review_type FROM review_template_types t WHERE t.tenant_id = @tenant
		ORDER BY t.template_id`)
	templateTypesGet = tq("review_template_types.get", `
		SELECT t.template_id, t.review_type FROM review_template_types t
		WHERE t.tenant_id = @tenant AND t.template_id = @template_id`)
	templateTypesPut = tq("review_template_types.put", `
		INSERT INTO review_template_types (tenant_id, template_id, review_type) VALUES (@tenant, @template_id, @review_type)
		ON CONFLICT (tenant_id, template_id) DO UPDATE SET review_type = excluded.review_type`)
	templateTypesDelete = tq("review_template_types.delete", `
		DELETE FROM review_template_types WHERE tenant_id = @tenant AND template_id = @template_id`)
)

func scanReviewTypeSettings(s scanner) (*ReviewTypeSettingsRow, error) {
	var r ReviewTypeSettingsRow
	var en int
	var rev, fb sql.NullInt64
	var at string
	if err := s.Scan(&r.ReviewType, &en, &r.ReviewerSource, &rev, &fb, &r.OnIncomplete, &r.EscalationDays, &r.Version,
		&r.UpdatedBy, &at); err != nil {
		return nil, err
	}
	r.Enabled, r.ReviewerIdentityID, r.FallbackReviewerID = en == 1, intp(rev), intp(fb)
	var err error
	r.UpdatedAt, err = ParseRT(at)
	return &r, err
}

// ReviewTypeSettingsList lists the types the tenant configured.
func (tx *TenantTx) ReviewTypeSettingsList() ([]*ReviewTypeSettingsRow, error) {
	return collect(tx, scanReviewTypeSettings, reviewTypesList)
}

// ReviewTypeSettings returns one type's row; ErrNotFound if the tenant never configured it.
func (tx *TenantTx) ReviewTypeSettings(reviewType string) (*ReviewTypeSettingsRow, error) {
	return one(tx, scanReviewTypeSettings, reviewTypesGet, sql.Named("review_type", reviewType))
}

// PutReviewTypeSettings replaces one type's settings and moves its version on.
func (tx *TenantTx) PutReviewTypeSettings(r *ReviewTypeSettingsRow, now time.Time) error {
	_, err := tx.exec(reviewTypesPut, sql.Named("review_type", r.ReviewType), sql.Named("enabled", B(r.Enabled)),
		sql.Named("reviewer_source", r.ReviewerSource), sql.Named("reviewer_identity_id", IP(r.ReviewerIdentityID)),
		sql.Named("fallback_reviewer_id", IP(r.FallbackReviewerID)), sql.Named("on_incomplete", r.OnIncomplete),
		sql.Named("escalation_days", r.EscalationDays), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// TemplateReviewTypes lists the review type of every template that has one.
func (tx *TenantTx) TemplateReviewTypes() ([]*TemplateReviewType, error) {
	return collect(tx, func(s scanner) (*TemplateReviewType, error) {
		var t TemplateReviewType
		return &t, s.Scan(&t.TemplateID, &t.ReviewType)
	}, templateTypesList)
}

// TemplateReviewType returns the type a template runs as; ErrNotFound for the original all-purpose schedule.
func (tx *TenantTx) TemplateReviewType(templateID string) (string, error) {
	t, err := one(tx, func(s scanner) (*TemplateReviewType, error) {
		var t TemplateReviewType
		return &t, s.Scan(&t.TemplateID, &t.ReviewType)
	}, templateTypesGet, sql.Named("template_id", templateID))
	if err != nil {
		return "", err
	}
	return t.ReviewType, nil
}

// SetTemplateReviewType sets the type a template runs as.
func (tx *TenantTx) SetTemplateReviewType(templateID, reviewType string) error {
	_, err := tx.exec(templateTypesPut, sql.Named("template_id", templateID), sql.Named("review_type", reviewType))
	return err
}

// ClearTemplateReviewType returns a template to the original all-purpose schedule.
func (tx *TenantTx) ClearTemplateReviewType(templateID string) error {
	_, err := tx.exec(templateTypesDelete, sql.Named("template_id", templateID))
	return err
}
