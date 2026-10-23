package store

import (
	"database/sql"
	"errors"
	"time"
)

// Recently added authentication methods and the help-desk reset
// (schema/0720_helpdesk_auth_method_risk.sql, issue #477). What counts as a
// trigger is decided by internal/helpdesk; the store holds the settings and
// the IdP risk signals, and reads an identity's methods.

// Actions of the recent authentication method rule.
const (
	HelpdeskRecentOff             = "off"
	HelpdeskRecentRequireApproval = "require_approval"
	HelpdeskRecentBlock           = "block"
)

// Defaults of a tenant with no settings row.
const (
	HelpdeskDefaultRecentDays   = 7
	HelpdeskDefaultRecentAction = HelpdeskRecentRequireApproval
)

// HelpdeskSettings is the tenant's help-desk policy settings.
type HelpdeskSettings struct {
	RecentMethodDays   int
	RecentMethodAction string
	UpdatedBy          string
	UpdatedAt          *time.Time // nil: the defaults, never saved
}

// HelpdeskIdPRisk is a risk signal a connected IdP reported for an identity.
type HelpdeskIdPRisk struct {
	ID         string
	IdentityID int64
	Kind       string // auth_method_added
	Source     string
	Detail     string
	OccurredAt time.Time
	CreatedAt  time.Time
}

const (
	helpdeskSettingsCols = `s.recent_method_days, s.recent_method_action, s.updated_by, s.updated_at`
	helpdeskIdPRiskCols  = `r.id, r.identity_id, r.kind, r.source, r.detail, r.occurred_at, r.created_at`
)

var (
	helpdeskSettingsGet = tq("helpdesk_settings.get", `
		SELECT `+helpdeskSettingsCols+` FROM helpdesk_settings s WHERE s.tenant_id = @tenant`)
	helpdeskSettingsPut = tq("helpdesk_settings.put", `
		INSERT INTO helpdesk_settings (tenant_id, recent_method_days, recent_method_action, updated_by, updated_at)
		VALUES (@tenant, @days, @action, @by, @now)
		ON CONFLICT (tenant_id) DO UPDATE SET recent_method_days = excluded.recent_method_days,
			recent_method_action = excluded.recent_method_action, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
	helpdeskIdPRiskInsert = tq("helpdesk_idp_risks.insert", `
		INSERT INTO helpdesk_idp_risks (id, tenant_id, identity_id, kind, source, detail, occurred_at, created_at)
		VALUES (@id, @tenant, @identity_id, @kind, @source, @detail, @occurred_at, @now)`)
	helpdeskIdPRisksFor = tq("helpdesk_idp_risks.for_identity", `
		SELECT `+helpdeskIdPRiskCols+` FROM helpdesk_idp_risks r
		WHERE r.tenant_id = @tenant AND r.identity_id = @identity_id ORDER BY r.occurred_at, r.id`)
	authMethodsOfIdentity = tq("auth_methods.of_identity", `
		SELECT `+authMethodCols+` FROM auth_methods m
		JOIN accounts a ON a.tenant_id = m.tenant_id AND a.id = m.account_id
		WHERE m.tenant_id = @tenant AND a.tenant_id = @tenant AND a.identity_id = @identity_id ORDER BY m.account_id, m.external_id`)
)

func scanHelpdeskSettings(s scanner) (*HelpdeskSettings, error) {
	var h HelpdeskSettings
	var at string
	if err := s.Scan(&h.RecentMethodDays, &h.RecentMethodAction, &h.UpdatedBy, &at); err != nil {
		return nil, err
	}
	t, err := ParseRT(at)
	h.UpdatedAt = &t
	return &h, err
}

func scanHelpdeskIdPRisk(s scanner) (*HelpdeskIdPRisk, error) {
	var r HelpdeskIdPRisk
	var occ, created string
	if err := s.Scan(&r.ID, &r.IdentityID, &r.Kind, &r.Source, &r.Detail, &occ, &created); err != nil {
		return nil, err
	}
	var err error
	if r.OccurredAt, err = ParseRT(occ); err != nil {
		return nil, err
	}
	r.CreatedAt, err = ParseRT(created)
	return &r, err
}

// HelpdeskSettings returns the tenant's settings, or the defaults when none
// were saved.
func (tx *TenantTx) HelpdeskSettings() (*HelpdeskSettings, error) {
	h, err := one(tx, scanHelpdeskSettings, helpdeskSettingsGet)
	if errors.Is(err, ErrNotFound) {
		return &HelpdeskSettings{RecentMethodDays: HelpdeskDefaultRecentDays, RecentMethodAction: HelpdeskDefaultRecentAction}, nil
	}
	return h, err
}

// PutHelpdeskSettings saves the tenant's settings.
func (tx *TenantTx) PutHelpdeskSettings(h *HelpdeskSettings, by string, now time.Time) error {
	_, err := tx.exec(helpdeskSettingsPut, sql.Named("days", h.RecentMethodDays), sql.Named("action", h.RecentMethodAction),
		sql.Named("by", by), sql.Named("now", RT(now)))
	return err
}

// InsertHelpdeskIdPRisk records a risk signal an IdP reported.
func (tx *TenantTx) InsertHelpdeskIdPRisk(r *HelpdeskIdPRisk, now time.Time) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	_, err := tx.exec(helpdeskIdPRiskInsert, sql.Named("id", r.ID), sql.Named("identity_id", r.IdentityID), sql.Named("kind", r.Kind),
		sql.Named("source", r.Source), sql.Named("detail", r.Detail), sql.Named("occurred_at", RT(r.OccurredAt)), sql.Named("now", RT(now)))
	return err
}

// HelpdeskIdPRisks lists an identity's IdP risk signals, oldest first.
func (tx *TenantTx) HelpdeskIdPRisks(identityID int64) ([]*HelpdeskIdPRisk, error) {
	return collect(tx, scanHelpdeskIdPRisk, helpdeskIdPRisksFor, sql.Named("identity_id", identityID))
}

// AuthMethodsOfIdentity lists the registered methods of every account of the identity.
func (tx *TenantTx) AuthMethodsOfIdentity(identityID int64) ([]*AuthMethod, error) {
	return collect(tx, scanAuthMethod, authMethodsOfIdentity, sql.Named("identity_id", identityID))
}
