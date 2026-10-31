package store

import (
	"database/sql"
	"errors"
	"time"
)

// Merge sync of the policy repository (schema/0961_policy_syncs.sql, 0962_policy_sync_findings.sql, issue #657, AC-11).
// Every statement binds the tenant.

// Kinds and check results of a policy sync.
const (
	PolicySyncKindSync     = "sync"
	PolicySyncKindRollback = "rollback"

	PolicySyncPending  = "pending"
	PolicySyncVerified = "verified"
	// PolicySyncPartial: nothing differed in what could be compared, but the comparison was not complete (a cut prediction,
	// or no policies to evaluate violations with); never reported as verified.
	PolicySyncPartial  = "partial"
	PolicySyncMismatch = "mismatch"
)

// PolicySync is one sync request: the commit, the change request that applies it, what was predicted and, once applied,
// what the check after the apply found.
type PolicySync struct {
	ID           string
	Repo         string
	SHA          string
	Kind         string
	RollbackFrom string
	ChangeID     string
	BundleSHA256 string
	PlanSHA256   string
	// Prediction is the JSON of the prediction the approver reviewed.
	Prediction  string
	RequestedBy string
	CreatedAt   time.Time
	AppliedAt   *time.Time
	// ActiveKey is repo|sha|kind while the request is open or applied, and empty once it ended without applying.
	ActiveKey   string
	CheckStatus string
	CheckedAt   *time.Time
	CheckDetail string
	// ChangeStatus is the status of the change request now (a read-only join).
	ChangeStatus string
}

// PolicySyncFinding is one difference between the prediction and what was observed.
type PolicySyncFinding struct {
	ID        string
	SyncID    string
	Kind      string
	Subject   string
	Predicted string
	Observed  string
	RaisedAt  time.Time
}

// PolicySyncActiveKey is the idempotency key of a sync request.
func PolicySyncActiveKey(repo, sha, kind string) string { return repo + "|" + sha + "|" + kind }

const policySyncCols = `s.id, s.repo, s.sha, s.kind, s.rollback_from, s.change_id, s.bundle_sha256, s.plan_sha256, s.prediction,
	s.requested_by, s.created_at, s.applied_at, s.active_key, s.check_status, s.checked_at, s.check_detail,
	COALESCE((SELECT c.status FROM admin_change_requests c WHERE c.tenant_id = @tenant AND c.id = s.change_id), '')`

var (
	policySyncInsert = tq("policy_syncs.insert", `
		INSERT INTO policy_syncs (tenant_id, id, repo, sha, kind, rollback_from, change_id, bundle_sha256, plan_sha256, prediction,
			requested_by, created_at, active_key)
		VALUES (@tenant, @id, @repo, @sha, @kind, @rollback_from, @change_id, @bundle_sha256, @plan_sha256, @prediction,
			@requested_by, @now, @active_key)`)
	policySyncByKey = tq("policy_syncs.by_key", `
		SELECT `+policySyncCols+` FROM policy_syncs s
		WHERE s.tenant_id = @tenant AND s.repo = @repo AND s.sha = @sha AND s.kind = @kind
		ORDER BY CASE WHEN s.active_key IS NULL THEN 1 ELSE 0 END, s.created_at DESC, s.id DESC LIMIT 1`)
	policySyncByChange = tq("policy_syncs.by_change", `
		SELECT `+policySyncCols+` FROM policy_syncs s WHERE s.tenant_id = @tenant AND s.change_id = @change_id`)
	policySyncClose = tq("policy_syncs.close", `
		UPDATE policy_syncs SET active_key = NULL WHERE tenant_id = @tenant AND change_id = @change_id AND applied_at IS NULL`)
	policySyncApplied = tq("policy_syncs.applied", `
		UPDATE policy_syncs SET applied_at = @now, checked_at = @now, check_status = @check_status, check_detail = @check_detail,
			active_key = CASE WHEN kind = 'rollback' THEN NULL ELSE active_key END
		WHERE tenant_id = @tenant AND change_id = @change_id AND applied_at IS NULL`)
	// once a request is the repository's newest applied one, older applied requests no longer hold their commit: it may be
	// synced again (a merge re-applied after a rollback)
	policySyncFree = tq("policy_syncs.free_older", `
		UPDATE policy_syncs SET active_key = NULL
		WHERE tenant_id = @tenant AND repo = @repo AND applied_at IS NOT NULL AND change_id <> @change_id AND active_key IS NOT NULL`)
	policySyncLast = tq("policy_syncs.last", `
		SELECT `+policySyncCols+` FROM policy_syncs s
		WHERE s.tenant_id = @tenant AND s.repo = @repo AND s.applied_at IS NOT NULL
		ORDER BY s.applied_at DESC, s.id DESC LIMIT 1`)
	policySyncAppliedAt = tq("policy_syncs.applied_commit", `
		SELECT `+policySyncCols+` FROM policy_syncs s
		WHERE s.tenant_id = @tenant AND s.repo = @repo AND s.sha = @sha AND s.applied_at IS NOT NULL
		ORDER BY s.applied_at DESC, s.id DESC LIMIT 1`)
	policySyncRecent = tq("policy_syncs.recent", `
		SELECT `+policySyncCols+` FROM policy_syncs s WHERE s.tenant_id = @tenant AND s.repo = @repo
		ORDER BY s.created_at DESC, s.id DESC LIMIT @limit`)
	policySyncFindingInsert = tq("policy_sync_findings.insert", `
		INSERT INTO policy_sync_findings (tenant_id, id, sync_id, kind, subject, predicted, observed, raised_at)
		VALUES (@tenant, @id, @sync_id, @kind, @subject, @predicted, @observed, @now)`)
	policySyncFindingsOf = tq("policy_sync_findings.of_sync", `
		SELECT f.id, f.sync_id, f.kind, f.subject, f.predicted, f.observed, f.raised_at FROM policy_sync_findings f
		WHERE f.tenant_id = @tenant AND f.sync_id = @sync_id ORDER BY f.raised_at, f.id LIMIT @limit`)
	policySyncFindingsCount = tq("policy_sync_findings.count", `
		SELECT COUNT(*) FROM policy_sync_findings f WHERE f.tenant_id = @tenant AND f.sync_id = @sync_id`)
)

func scanPolicySync(r scanner) (*PolicySync, error) {
	var s PolicySync
	var created string
	var applied, checked, active sql.NullString
	if err := r.Scan(&s.ID, &s.Repo, &s.SHA, &s.Kind, &s.RollbackFrom, &s.ChangeID, &s.BundleSHA256, &s.PlanSHA256, &s.Prediction,
		&s.RequestedBy, &created, &applied, &active, &s.CheckStatus, &checked, &s.CheckDetail, &s.ChangeStatus); err != nil {
		return nil, err
	}
	var err error
	if s.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if applied.Valid {
		t, err := ParseRT(applied.String)
		if err != nil {
			return nil, err
		}
		s.AppliedAt = &t
	}
	if checked.Valid {
		t, err := ParseRT(checked.String)
		if err != nil {
			return nil, err
		}
		s.CheckedAt = &t
	}
	s.ActiveKey = active.String
	return &s, nil
}

// InsertPolicySync records a sync request in the transaction that files its change request. ErrDuplicate when the
// repository, commit and kind already have an open or applied request, or the change request already has a row.
func (tx *TenantTx) InsertPolicySync(s *PolicySync, now time.Time) error {
	if s.ID == "" {
		s.ID = NewID()
	}
	_, err := tx.exec(policySyncInsert, sql.Named("id", s.ID), sql.Named("repo", s.Repo), sql.Named("sha", s.SHA), sql.Named("kind", s.Kind),
		sql.Named("rollback_from", s.RollbackFrom), sql.Named("change_id", s.ChangeID), sql.Named("bundle_sha256", s.BundleSHA256),
		sql.Named("plan_sha256", s.PlanSHA256), sql.Named("prediction", s.Prediction), sql.Named("requested_by", s.RequestedBy),
		sql.Named("now", RT(now)), sql.Named("active_key", PolicySyncActiveKey(s.Repo, s.SHA, s.Kind)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

func orNil(r *PolicySync, err error) (*PolicySync, error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// PolicySyncByKey returns the sync request of the commit and kind on the repository that holds it, else the newest one, or nil.
func (tx *TenantTx) PolicySyncByKey(repo, sha, kind string) (*PolicySync, error) {
	return orNil(one(tx, scanPolicySync, policySyncByKey, sql.Named("repo", repo), sql.Named("sha", sha), sql.Named("kind", kind)))
}

// PolicySyncByChange returns the sync request filed with the change request, or nil.
func (tx *TenantTx) PolicySyncByChange(changeID string) (*PolicySync, error) {
	return orNil(one(tx, scanPolicySync, policySyncByChange, sql.Named("change_id", changeID)))
}

// ClosePolicySync frees the commit of a request that ended without applying (rejected, cancelled, expired or failed), so
// it can be filed again.
func (tx *TenantTx) ClosePolicySync(changeID string) error {
	_, err := tx.exec(policySyncClose, sql.Named("change_id", changeID))
	return err
}

// MarkPolicySyncApplied records, in the apply's transaction, that the request was applied and what the check found
// (PolicySyncVerified or PolicySyncMismatch, with the JSON detail).
func (tx *TenantTx) MarkPolicySyncApplied(repo, changeID string, now time.Time, check, detail string) error {
	res, err := tx.exec(policySyncApplied, sql.Named("change_id", changeID), sql.Named("now", RT(now)),
		sql.Named("check_status", check), sql.Named("check_detail", detail))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	_, err = tx.exec(policySyncFree, sql.Named("repo", repo), sql.Named("change_id", changeID))
	return err
}

// LastPolicySync is the newest applied request of the repository: its commit is the last synced commit. Nil when
// nothing was applied.
func (tx *TenantTx) LastPolicySync(repo string) (*PolicySync, error) {
	return orNil(one(tx, scanPolicySync, policySyncLast, sql.Named("repo", repo)))
}

// AppliedPolicySync returns the newest applied request of the commit on the repository, or nil: the commits a rollback
// may return to.
func (tx *TenantTx) AppliedPolicySync(repo, sha string) (*PolicySync, error) {
	return orNil(one(tx, scanPolicySync, policySyncAppliedAt, sql.Named("repo", repo), sql.Named("sha", sha)))
}

// RecentPolicySyncs lists the repository's latest requests, newest first.
func (tx *TenantTx) RecentPolicySyncs(repo string, limit int) ([]*PolicySync, error) {
	return collect(tx, scanPolicySync, policySyncRecent, sql.Named("repo", repo), sql.Named("limit", limit))
}

// InsertPolicySyncFinding records one difference between the prediction and the observation.
func (tx *TenantTx) InsertPolicySyncFinding(f *PolicySyncFinding, now time.Time) error {
	_, err := tx.exec(policySyncFindingInsert, sql.Named("id", NewID()), sql.Named("sync_id", f.SyncID), sql.Named("kind", f.Kind),
		sql.Named("subject", f.Subject), sql.Named("predicted", f.Predicted), sql.Named("observed", f.Observed), sql.Named("now", RT(now)))
	return err
}

// PolicySyncFindings lists the findings of a sync (at most limit) and how many it has.
func (tx *TenantTx) PolicySyncFindings(syncID string, limit int) ([]*PolicySyncFinding, int, error) {
	fs, err := collect(tx, func(r scanner) (*PolicySyncFinding, error) {
		var f PolicySyncFinding
		var at string
		if err := r.Scan(&f.ID, &f.SyncID, &f.Kind, &f.Subject, &f.Predicted, &f.Observed, &at); err != nil {
			return nil, err
		}
		var err error
		f.RaisedAt, err = ParseRT(at)
		return &f, err
	}, policySyncFindingsOf, sql.Named("sync_id", syncID), sql.Named("limit", limit))
	if err != nil {
		return nil, 0, err
	}
	n, err := tx.count(policySyncFindingsCount, sql.Named("sync_id", syncID))
	return fs, n, err
}
