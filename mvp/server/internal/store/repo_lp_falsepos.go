package store

import (
	"database/sql"
	"time"
)

// False positives of the loop (schema/0923_lp_false_positives.sql, issue #663, LP-7). Every statement binds the
// tenant. Which revocations a JIT request or a restore labels is decided by internal/lp.

// LPFPJIT is the source of a label from a JIT request; the restore triggers (denial, owner, admin, undo_run) are the others.
const LPFPJIT = "jit"

// LPFalsePositive labels one revocation as access that was needed.
type LPFalsePositive struct {
	ID           string
	RevocationID string
	Source       string
	Ref          string
	Principal    string
	PolicyARN    string
	Confidence   string
	CreatedAt    time.Time
}

// LPCalibrationRow is the counts of one confidence level over a window.
type LPCalibrationRow struct {
	Confidence     string
	Revocations    int
	FalsePositives int
}

var (
	lpFPInsert = tq("lp_false_positives.insert", `
		INSERT INTO lp_false_positives (tenant_id, id, revocation_id, source, ref, principal_arn, policy_arn, confidence, created_at)
		VALUES (@tenant, @id, @revocation_id, @source, @ref, @principal_arn, @policy_arn, @confidence, @created_at)`)
	lpFPForRevocation = tq("lp_false_positives.for_revocation", `
		SELECT COUNT(*) FROM lp_false_positives f WHERE f.tenant_id = @tenant AND f.revocation_id = @revocation_id`)
	lpFPCount = tq("lp_false_positives.count", `
		SELECT COUNT(*) FROM lp_false_positives f WHERE f.tenant_id = @tenant AND f.confidence = @confidence AND f.created_at >= @since`)
	lpRevExecutedByConf = tq("lp_revocations.executed_by_confidence", `
		SELECT COUNT(*) FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.confidence = @confidence AND r.executed_at IS NOT NULL AND r.executed_at >= @since`)
	lpRevRevokedForGrant = tq("lp_revocations.revoked_for_grant", `
		SELECT `+lpRevCols+` FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.state = 'revoked' AND r.principal_arn = @principal AND r.policy_arn = @policy
		ORDER BY r.created_at, r.id LIMIT 50`)
)

// InsertLPFalsePositive labels a revocation. ErrDuplicate: it was labelled already (the first label stands).
func (tx *TenantTx) InsertLPFalsePositive(f *LPFalsePositive) error {
	if f.ID == "" {
		f.ID = NewID()
	}
	_, err := tx.exec(lpFPInsert, sql.Named("id", f.ID), sql.Named("revocation_id", f.RevocationID), sql.Named("source", f.Source),
		sql.Named("ref", f.Ref), sql.Named("principal_arn", f.Principal), sql.Named("policy_arn", f.PolicyARN),
		sql.Named("confidence", f.Confidence), sql.Named("created_at", RT(f.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// LPLabelled reports whether the revocation is labelled a false positive.
func (tx *TenantTx) LPLabelled(revocationID string) (bool, error) {
	n, err := tx.count(lpFPForRevocation, sql.Named("revocation_id", revocationID))
	return n > 0, err
}

// LPCalibration counts, for each confidence level, the revocations carried out at or after since and the false
// positives labelled at or after since.
func (tx *TenantTx) LPCalibration(since time.Time) ([]LPCalibrationRow, error) {
	var out []LPCalibrationRow
	for _, level := range []string{"high", "medium"} {
		rev, err := tx.count(lpRevExecutedByConf, sql.Named("confidence", level), sql.Named("since", RT(since)))
		if err != nil {
			return nil, err
		}
		fp, err := tx.count(lpFPCount, sql.Named("confidence", level), sql.Named("since", RT(since)))
		if err != nil {
			return nil, err
		}
		out = append(out, LPCalibrationRow{Confidence: level, Revocations: rev, FalsePositives: fp})
	}
	return out, nil
}

// LPRevokedForGrant lists the revoked (not yet final) revocations of one grant: a principal and a policy.
func (tx *TenantTx) LPRevokedForGrant(principal, policy string) ([]*LPRevocation, error) {
	return collect(tx, scanLPRevocation, lpRevRevokedForGrant, sql.Named("principal", principal), sql.Named("policy", policy))
}
