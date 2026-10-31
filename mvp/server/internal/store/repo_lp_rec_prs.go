package store

import (
	"database/sql"
	"errors"
	"time"
)

// The pull request opened for each right-sizing recommendation (schema/0958_lp_rec_prs.sql, issue #665, LP-9).
// Every statement binds the tenant.

// LP recommendation pull request states.
const (
	LPRecPROpen   = "open"
	LPRecPRClosed = "closed"
)

// LPRecPR is the pull request of one recommendation on one repository.
type LPRecPR struct {
	RecID      string
	Repo       string
	Branch     string
	PullNumber int
	HeadSHA    string
	RoleKey    string
	BodySHA256 string
	State      string
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

var (
	lpRecPRGet = tq("lp_rec_prs.get", `
		SELECT p.branch, p.pull_number, p.head_sha, p.role_key, p.body_sha256, p.state, p.created_by, p.created_at, p.updated_at
		FROM lp_rec_prs p WHERE p.tenant_id = @tenant AND p.rec_id = @rec_id AND p.repo = @repo`)
	lpRecPRPut = tq("lp_rec_prs.put", `
		INSERT INTO lp_rec_prs (tenant_id, rec_id, repo, branch, pull_number, head_sha, role_key, body_sha256, state, created_by, created_at, updated_at)
		VALUES (@tenant, @rec_id, @repo, @branch, @pull_number, @head_sha, @role_key, @body_sha256, @state, @created_by, @now, @now)
		ON CONFLICT (tenant_id, rec_id, repo) DO UPDATE SET branch = excluded.branch, pull_number = excluded.pull_number,
			head_sha = excluded.head_sha, role_key = excluded.role_key, body_sha256 = excluded.body_sha256,
			state = excluded.state, updated_at = excluded.updated_at`)
	lpRecPRLock = tq("lp_rec_prs.lock_attempts", `
		UPDATE github_app_settings SET updated_at = updated_at WHERE tenant_id = @tenant`)
	lpRecPRAttempts = tq("lp_rec_pr_attempts.since", `
		SELECT COUNT(*) FROM lp_rec_pr_attempts a WHERE a.tenant_id = @tenant AND a.created_at >= @since`)
	lpRecPRAttemptIns = tq("lp_rec_pr_attempts.insert", `
		INSERT INTO lp_rec_pr_attempts (tenant_id, id, rec_id, repo, created_by, created_at)
		VALUES (@tenant, @id, @rec_id, @repo, @created_by, @created_at)`)
	lpRecPRAttemptDel = tq("lp_rec_pr_attempts.delete", `
		DELETE FROM lp_rec_pr_attempts WHERE tenant_id = @tenant AND id = @id`)
)

// LPRecPR returns the pull request recorded for the recommendation on the repository, or nil when there is none.
func (tx *TenantTx) LPRecPR(recID, repo string) (*LPRecPR, error) {
	p, err := one(tx, func(r scanner) (*LPRecPR, error) {
		p := LPRecPR{RecID: recID, Repo: repo}
		var created, updated string
		if err := r.Scan(&p.Branch, &p.PullNumber, &p.HeadSHA, &p.RoleKey, &p.BodySHA256, &p.State, &p.CreatedBy, &created, &updated); err != nil {
			return nil, err
		}
		var err error
		if p.CreatedAt, err = ParseRT(created); err != nil {
			return nil, err
		}
		p.UpdatedAt, err = ParseRT(updated)
		return &p, err
	}, lpRecPRGet, sql.Named("rec_id", recID), sql.Named("repo", repo))
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// PutLPRecPR records the pull request of a recommendation. A row that exists keeps its creator and creation time.
func (tx *TenantTx) PutLPRecPR(p *LPRecPR, now time.Time) error {
	_, err := tx.exec(lpRecPRPut, sql.Named("rec_id", p.RecID), sql.Named("repo", p.Repo), sql.Named("branch", p.Branch),
		sql.Named("pull_number", p.PullNumber), sql.Named("head_sha", p.HeadSHA), sql.Named("role_key", p.RoleKey),
		sql.Named("body_sha256", p.BodySHA256), sql.Named("state", p.State), sql.Named("created_by", p.CreatedBy), sql.Named("now", RT(now)))
	return err
}

// LPRecPRAttemptsSince counts the attempts reserved at or after since (the hourly cap).
func (tx *TenantTx) LPRecPRAttemptsSince(since time.Time) (int, error) {
	return tx.count(lpRecPRAttempts, sql.Named("since", RT(since)))
}

// ReserveLPRecPRAttempt takes one of the limit attempts allowed since the window start, or reports false when they are
// used. It locks the tenant's GitHub App settings row first (a no-op update), so two concurrent reservations of one tenant
// run one after the other even on Postgres, and the count sees the earlier insert.
func (tx *TenantTx) ReserveLPRecPRAttempt(recID, repo, by string, now, windowStart time.Time, limit int) (bool, error) {
	_, ok, err := tx.ReserveLPRecPRAttemptID(recID, repo, by, now, windowStart, limit)
	return ok, err
}

// ReserveLPRecPRAttemptID is ReserveLPRecPRAttempt that also returns the reserved attempt's id, for ReleaseLPRecPRAttempt.
func (tx *TenantTx) ReserveLPRecPRAttemptID(recID, repo, by string, now, windowStart time.Time, limit int) (string, bool, error) {
	if _, err := tx.exec(lpRecPRLock); err != nil {
		return "", false, err
	}
	n, err := tx.LPRecPRAttemptsSince(windowStart)
	if err != nil || n >= limit {
		return "", false, err
	}
	id := NewID()
	_, err = tx.exec(lpRecPRAttemptIns, sql.Named("id", id), sql.Named("rec_id", recID), sql.Named("repo", repo),
		sql.Named("created_by", by), sql.Named("created_at", RT(now)))
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}

// ReleaseLPRecPRAttempt gives back an attempt that was reserved but refused before anything was written to the repository.
// Releasing only lowers the count, so it cannot let the cap be exceeded.
func (tx *TenantTx) ReleaseLPRecPRAttempt(id string) error {
	_, err := tx.exec(lpRecPRAttemptDel, sql.Named("id", id))
	return err
}
