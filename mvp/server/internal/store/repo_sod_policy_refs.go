package store

import "database/sql"

// The repository change behind each SoD ruleset an apply wrote (schema/0955_sod_policy_refs.sql, issue #652, AC-6).
// Every statement binds the tenant.

// SodPolicyRef is one apply's write of a ruleset: its version afterwards and the JSON {commit, path, bundle_sha256}.
type SodPolicyRef struct {
	ID             int64
	RulesetID      string
	RulesetVersion int
	PolicyRef      string
	Actor          string
	AppliedAt      string
}

var (
	sprInsert = tq("sod_policy_refs.insert", `
		INSERT INTO sod_policy_refs (tenant_id, ruleset_id, ruleset_version, policy_ref, actor, applied_at)
		VALUES (@tenant, @ruleset_id, @ruleset_version, @policy_ref, @actor, @applied_at)`)
	sprList = tq("sod_policy_refs.list", `
		SELECT r.id, r.ruleset_id, r.ruleset_version, r.policy_ref, r.actor, r.applied_at
		FROM sod_policy_refs r WHERE r.tenant_id = @tenant ORDER BY r.id`)
)

// AddSodPolicyRef appends the record of an apply writing a ruleset.
func (tx *TenantTx) AddSodPolicyRef(r *SodPolicyRef) error {
	_, err := tx.exec(sprInsert, sql.Named("ruleset_id", r.RulesetID), sql.Named("ruleset_version", r.RulesetVersion),
		sql.Named("policy_ref", r.PolicyRef), sql.Named("actor", r.Actor), sql.Named("applied_at", r.AppliedAt))
	return err
}

// SodPolicyRefs returns every record, oldest first. A ruleset with one is managed by the policy repository.
func (tx *TenantTx) SodPolicyRefs() ([]*SodPolicyRef, error) {
	return collect(tx, func(s scanner) (*SodPolicyRef, error) {
		var r SodPolicyRef
		err := s.Scan(&r.ID, &r.RulesetID, &r.RulesetVersion, &r.PolicyRef, &r.Actor, &r.AppliedAt)
		return &r, err
	}, sprList)
}
