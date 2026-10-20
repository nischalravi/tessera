package store

import (
	"database/sql"
	"time"
)

// Ruleset-level remediation defaults of SoD violations (schema/0381_sod_remediation.sql, issue #298).

// SodRulesetRemediation is what a ruleset's risks offer when they set no options of their own.
type SodRulesetRemediation struct {
	RulesetID  string
	Options    string // JSON list of remediations; [] means all four
	EscalateTo *int64 // approver an escalation goes to; nil: the risk owner
	UpdatedBy  string
	UpdatedAt  time.Time
}

var (
	srrList = tq("sod_ruleset_remediation.list", `
		SELECT r.ruleset_id, r.options, r.escalate_to_identity_id, r.updated_by, r.updated_at
		FROM sod_ruleset_remediation r WHERE r.tenant_id = @tenant ORDER BY r.ruleset_id`)
	srrPut = tq("sod_ruleset_remediation.put", `
		INSERT INTO sod_ruleset_remediation (tenant_id, ruleset_id, options, escalate_to_identity_id, updated_by, updated_at)
		VALUES (@tenant, @ruleset_id, @options, @escalate_to, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, ruleset_id) DO UPDATE SET options = excluded.options,
			escalate_to_identity_id = excluded.escalate_to_identity_id, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
)

// SodRulesetRemediations returns every ruleset's remediation defaults.
func (tx *TenantTx) SodRulesetRemediations() ([]*SodRulesetRemediation, error) {
	return collect(tx, func(s scanner) (*SodRulesetRemediation, error) {
		var r SodRulesetRemediation
		var to sql.NullInt64
		var at string
		if err := s.Scan(&r.RulesetID, &r.Options, &to, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		if to.Valid {
			r.EscalateTo = &to.Int64
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, srrList)
}

// PutSodRulesetRemediation sets a ruleset's remediation defaults.
func (tx *TenantTx) PutSodRulesetRemediation(r *SodRulesetRemediation) error {
	_, err := tx.exec(srrPut, sql.Named("ruleset_id", r.RulesetID), sql.Named("options", r.Options),
		sql.Named("escalate_to", IP(r.EscalateTo)), sql.Named("updated_by", r.UpdatedBy), sql.Named("updated_at", RT(r.UpdatedAt)))
	return err
}
