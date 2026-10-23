package store

import (
	"database/sql"
	"time"
)

// Identity rules (schema/0766_identity_rules.sql): the correlation order, authoritative source per attribute and
// dormancy thresholds of Admin > Identity rules. One row per tenant.

// IdentityRulesRow is the saved row; CorrelationOrder and Authoritative are JSON.
type IdentityRulesRow struct {
	CorrelationOrder   string
	Authoritative      string
	DormantServiceDays int
	DormantAIAgentDays int
	Version            int
	UpdatedBy          string
	UpdatedAt          time.Time
}

var (
	identityRulesGet = tq("identity_rules.get", `
		SELECT r.correlation_order, r.authoritative, r.dormant_service_days, r.dormant_ai_agent_days, r.version, r.updated_by,
			r.updated_at
		FROM identity_rules r WHERE r.tenant_id = @tenant`)
	identityRulesPut = tq("identity_rules.put", `
		INSERT INTO identity_rules (tenant_id, correlation_order, authoritative, dormant_service_days, dormant_ai_agent_days,
			version, updated_by, updated_at)
		VALUES (@tenant, @correlation_order, @authoritative, @dormant_service_days, @dormant_ai_agent_days, 1, @updated_by,
			@updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET correlation_order = excluded.correlation_order,
			authoritative = excluded.authoritative, dormant_service_days = excluded.dormant_service_days,
			dormant_ai_agent_days = excluded.dormant_ai_agent_days, version = identity_rules.version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// IdentityRules returns the tenant's saved identity rules; ErrNotFound if it never saved any.
func (tx *TenantTx) IdentityRules() (*IdentityRulesRow, error) {
	return one(tx, func(s scanner) (*IdentityRulesRow, error) {
		var r IdentityRulesRow
		var at string
		if err := s.Scan(&r.CorrelationOrder, &r.Authoritative, &r.DormantServiceDays, &r.DormantAIAgentDays, &r.Version,
			&r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, identityRulesGet)
}

// PutIdentityRules replaces the tenant's identity rules and moves the version on.
func (tx *TenantTx) PutIdentityRules(r *IdentityRulesRow, now time.Time) error {
	_, err := tx.exec(identityRulesPut, sql.Named("correlation_order", r.CorrelationOrder), sql.Named("authoritative", r.Authoritative),
		sql.Named("dormant_service_days", r.DormantServiceDays), sql.Named("dormant_ai_agent_days", r.DormantAIAgentDays),
		sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}
