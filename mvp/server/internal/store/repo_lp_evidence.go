package store

import (
	"database/sql"
	"time"
)

// Reads for the least-privilege evidence and metrics (issue #666, LP-10). Nothing is stored for them: the evidence of
// a revocation is computed from lp_revocations, lp_revocation_events, lp_false_positives and lp_denials, so there is
// no second copy to drift. Every statement binds the tenant.

// LPEvidenceMaxRows caps one export or metrics read; the caller says when it was reached.
const LPEvidenceMaxRows = 5000

var (
	// The revocations carried out (queued for the write target) in a half-open period, oldest first.
	lpRevExecutedBetween = tq("lp_revocations.executed_between", `
		SELECT `+lpRevCols+` FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.executed_at IS NOT NULL AND r.executed_at >= @from AND r.executed_at < @to
		ORDER BY r.executed_at, r.id LIMIT @limit`)
	lpFPGetForRevocation = tq("lp_false_positives.get_for_revocation", `
		SELECT f.id, f.revocation_id, f.source, f.ref, f.principal_arn, f.policy_arn, f.confidence, f.created_at
		FROM lp_false_positives f WHERE f.tenant_id = @tenant AND f.revocation_id = @revocation_id`)
	lpDenialsForRev = tq("lp_denials.for_revocation", `
		SELECT d.id, d.source, d.event_id, d.principal_arn, d.action, d.resource, d.occurred_at, d.arrived_at, d.outcome, d.revocation_id, d.detail
		FROM lp_denials d WHERE d.tenant_id = @tenant AND d.revocation_id = @revocation_id ORDER BY d.arrived_at, d.id`)
)

// LPExecutedBetween lists the revocations whose operation was queued in [from, to), oldest first, at most limit
// (<= 0 or above LPEvidenceMaxRows is LPEvidenceMaxRows).
func (tx *TenantTx) LPExecutedBetween(from, to time.Time, limit int) ([]*LPRevocation, error) {
	if limit <= 0 || limit > LPEvidenceMaxRows {
		limit = LPEvidenceMaxRows
	}
	return collect(tx, scanLPRevocation, lpRevExecutedBetween, sql.Named("from", RT(from)), sql.Named("to", RT(to)), sql.Named("limit", limit))
}

// LPFalsePositive returns the label of a revocation, or ErrNotFound when it has none.
func (tx *TenantTx) LPFalsePositive(revocationID string) (*LPFalsePositive, error) {
	return one(tx, func(s scanner) (*LPFalsePositive, error) {
		var f LPFalsePositive
		var at string
		if err := s.Scan(&f.ID, &f.RevocationID, &f.Source, &f.Ref, &f.Principal, &f.PolicyARN, &f.Confidence, &at); err != nil {
			return nil, err
		}
		var err error
		f.CreatedAt, err = ParseRT(at)
		return &f, err
	}, lpFPGetForRevocation, sql.Named("revocation_id", revocationID))
}

// LPDenialsFor lists the denial events that led to a restore of the revocation, oldest first.
func (tx *TenantTx) LPDenialsFor(revocationID string) ([]*LPDenial, error) {
	return collect(tx, scanLPDenial, lpDenialsForRev, sql.Named("revocation_id", revocationID))
}
