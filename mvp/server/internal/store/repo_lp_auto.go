package store

import (
	"database/sql"
	"errors"
	"time"
)

// The automatic policy of the least-privilege loop (schema/0953_lp_auto_policy.sql, issue #664, LP-8). Every
// statement binds the tenant. What the policy means is internal/lpauto; when it is applied is internal/admin.

// LPAutoPolicy is the policy a tenant's access-as-code repository carried when two admins approved it.
type LPAutoPolicy struct {
	Policy       string // canonical JSON of internal/lpauto
	PolicySHA256 string
	Commit       string
	AppliedBy    string
	ApprovedBy   string
	AppliedAt    time.Time
}

var (
	lpAutoGet = tq("lp_auto_policy.get", `
		SELECT a.policy, a.policy_sha256, a.commit_ref, a.applied_by, a.approved_by, a.applied_at
		FROM lp_auto_policy a WHERE a.tenant_id = @tenant`)
	lpAutoPut = tq("lp_auto_policy.put", `
		INSERT INTO lp_auto_policy (tenant_id, policy, policy_sha256, commit_ref, applied_by, approved_by, applied_at)
		VALUES (@tenant, @policy, @policy_sha256, @commit_ref, @applied_by, @approved_by, @applied_at)
		ON CONFLICT (tenant_id) DO UPDATE SET policy = excluded.policy, policy_sha256 = excluded.policy_sha256,
			commit_ref = excluded.commit_ref, applied_by = excluded.applied_by, approved_by = excluded.approved_by,
			applied_at = excluded.applied_at`)
	lpRevApprovedBy = tq("lp_revocations.approved_by_since", `
		SELECT COUNT(*) FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.approved_by = @actor AND r.approved_at IS NOT NULL AND r.approved_at >= @since`)
)

// LPAutoPolicy returns the tenant's automatic policy; ErrNotFound when none was ever applied (auto mode is then
// not available).
func (tx *TenantTx) LPAutoPolicy() (*LPAutoPolicy, error) {
	return one(tx, func(r scanner) (*LPAutoPolicy, error) {
		var p LPAutoPolicy
		var at string
		if err := r.Scan(&p.Policy, &p.PolicySHA256, &p.Commit, &p.AppliedBy, &p.ApprovedBy, &at); err != nil {
			return nil, err
		}
		var err error
		p.AppliedAt, err = ParseRT(at)
		return &p, err
	}, lpAutoGet)
}

// PutLPAutoPolicy replaces the tenant's automatic policy.
func (tx *TenantTx) PutLPAutoPolicy(p *LPAutoPolicy, now time.Time) error {
	if p.Policy == "" || len(p.PolicySHA256) != 64 || p.Commit == "" {
		return errors.New("store: an automatic policy needs its JSON, digest and commit")
	}
	_, err := tx.exec(lpAutoPut, sql.Named("policy", p.Policy), sql.Named("policy_sha256", p.PolicySHA256),
		sql.Named("commit_ref", p.Commit), sql.Named("applied_by", p.AppliedBy), sql.Named("approved_by", p.ApprovedBy),
		sql.Named("applied_at", RT(now)))
	return err
}

// LPApprovedBySince counts the revocations the named actor approved at or after since (the loop's own actor for the
// ones the automatic policy announced).
func (tx *TenantTx) LPApprovedBySince(actor string, since time.Time) (int, error) {
	return tx.count(lpRevApprovedBy, sql.Named("actor", actor), sql.Named("since", RT(since)))
}
