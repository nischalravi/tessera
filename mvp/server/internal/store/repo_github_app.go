package store

import (
	"database/sql"
	"errors"
	"time"
)

// The GitHub App settings and the checks posted on pull requests (schema/0957_github_app.sql, issue #656, AC-10).
// Every statement binds the tenant.

// GitHubAppSettings is a tenant's GitHub App: the App id, the installation, the one repository, and the sealed private
// key. A tenant with no row has the feature off. KeyEnc is never returned by the API.
type GitHubAppSettings struct {
	Enabled        bool
	AppID          string
	InstallationID int64
	Repo           string // "owner/name"
	KeyEnc         []byte
	// KeyFingerprint is the SHA-256 fingerprint of the private key (not secret); KeySetAt when it was last set.
	KeyFingerprint string
	KeySetAt       string
	UpdatedBy      string
	UpdatedAt      time.Time
}

// GitHubPRCheck is what was last posted on a pull request: the commit, the check run, the comment and the verdict.
type GitHubPRCheck struct {
	Repo       string
	PullNumber int
	HeadSHA    string
	CheckRunID int64
	CommentID  int64
	Conclusion string
	DiffSHA256 string
	UpdatedAt  time.Time
}

var (
	ghAppGet = tq("github_app_settings.get", `
		SELECT s.enabled, s.app_id, s.installation_id, s.repo, s.key_enc, s.key_fingerprint, s.key_set_at, s.updated_by, s.updated_at
		FROM github_app_settings s WHERE s.tenant_id = @tenant`)
	ghAppPut = tq("github_app_settings.put", `
		INSERT INTO github_app_settings (tenant_id, enabled, app_id, installation_id, repo, key_enc, key_fingerprint, key_set_at, updated_by, updated_at)
		VALUES (@tenant, @enabled, @app_id, @installation_id, @repo, @key_enc, @key_fingerprint, @key_set_at, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, app_id = excluded.app_id,
			installation_id = excluded.installation_id, repo = excluded.repo, key_enc = excluded.key_enc,
			key_fingerprint = excluded.key_fingerprint, key_set_at = excluded.key_set_at,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	ghCheckGet = tq("github_pr_checks.get", `
		SELECT c.head_sha, c.check_run_id, c.comment_id, c.conclusion, c.diff_sha256, c.updated_at
		FROM github_pr_checks c WHERE c.tenant_id = @tenant AND c.repo = @repo AND c.pull_number = @pull_number`)
	ghCheckPut = tq("github_pr_checks.put", `
		INSERT INTO github_pr_checks (tenant_id, repo, pull_number, head_sha, check_run_id, comment_id, conclusion, diff_sha256, updated_at)
		VALUES (@tenant, @repo, @pull_number, @head_sha, @check_run_id, @comment_id, @conclusion, @diff_sha256, @updated_at)
		ON CONFLICT (tenant_id, repo, pull_number) DO UPDATE SET head_sha = excluded.head_sha,
			check_run_id = excluded.check_run_id, comment_id = excluded.comment_id, conclusion = excluded.conclusion,
			diff_sha256 = excluded.diff_sha256, updated_at = excluded.updated_at`)
	ghClaimExpire = tq("github_pr_check_claims.expire", `
		DELETE FROM github_pr_check_claims WHERE tenant_id = @tenant AND repo = @repo AND pull_number = @pull_number AND claimed_at < @stale`)
	ghClaimIns = tq("github_pr_check_claims.insert", `
		INSERT INTO github_pr_check_claims (tenant_id, repo, pull_number, claimed_at)
		VALUES (@tenant, @repo, @pull_number, @claimed_at)
		ON CONFLICT (tenant_id, repo, pull_number) DO NOTHING`)
	ghClaimDel = tq("github_pr_check_claims.delete", `
		DELETE FROM github_pr_check_claims WHERE tenant_id = @tenant AND repo = @repo AND pull_number = @pull_number`)
)

// GitHubAppSettings returns the tenant's settings; a tenant that never set them gets the zero value (off, no key).
func (tx *TenantTx) GitHubAppSettings() (*GitHubAppSettings, error) {
	s, err := one(tx, func(r scanner) (*GitHubAppSettings, error) {
		var s GitHubAppSettings
		var enabled int
		var at string
		if err := r.Scan(&enabled, &s.AppID, &s.InstallationID, &s.Repo, &s.KeyEnc, &s.KeyFingerprint, &s.KeySetAt, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		var err error
		s.UpdatedAt, err = ParseRT(at)
		return &s, err
	}, ghAppGet)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return &GitHubAppSettings{}, nil
	}
	return s, err
}

// PutGitHubAppSettings replaces the tenant's settings.
func (tx *TenantTx) PutGitHubAppSettings(s *GitHubAppSettings, now time.Time) error {
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	_, err := tx.exec(ghAppPut, sql.Named("enabled", enabled), sql.Named("app_id", s.AppID), sql.Named("installation_id", s.InstallationID),
		sql.Named("repo", s.Repo), sql.Named("key_enc", s.KeyEnc), sql.Named("key_fingerprint", s.KeyFingerprint),
		sql.Named("key_set_at", s.KeySetAt), sql.Named("updated_by", s.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// GitHubPRCheck returns what was last posted on the pull request, or nil when nothing was.
func (tx *TenantTx) GitHubPRCheck(repo string, number int) (*GitHubPRCheck, error) {
	c, err := one(tx, func(r scanner) (*GitHubPRCheck, error) {
		c := GitHubPRCheck{Repo: repo, PullNumber: number}
		var at string
		if err := r.Scan(&c.HeadSHA, &c.CheckRunID, &c.CommentID, &c.Conclusion, &c.DiffSHA256, &at); err != nil {
			return nil, err
		}
		var err error
		c.UpdatedAt, err = ParseRT(at)
		return &c, err
	}, ghCheckGet, sql.Named("repo", repo), sql.Named("pull_number", number))
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// PutGitHubPRCheck records what was posted on the pull request, replacing the earlier record.
func (tx *TenantTx) PutGitHubPRCheck(c *GitHubPRCheck, now time.Time) error {
	_, err := tx.exec(ghCheckPut, sql.Named("repo", c.Repo), sql.Named("pull_number", c.PullNumber), sql.Named("head_sha", c.HeadSHA),
		sql.Named("check_run_id", c.CheckRunID), sql.Named("comment_id", c.CommentID), sql.Named("conclusion", c.Conclusion),
		sql.Named("diff_sha256", c.DiffSHA256), sql.Named("updated_at", RT(now)))
	return err
}

// ClaimGitHubPRCheck takes the claim on a pull request before GitHub is called, or reports false when another request
// holds it. A claim older than ttl (a request that died) is replaced. Release it with ReleaseGitHubPRCheck, or record
// the outcome in the same transaction that releases it.
func (tx *TenantTx) ClaimGitHubPRCheck(repo string, number int, now time.Time, ttl time.Duration) (bool, error) {
	if _, err := tx.exec(ghClaimExpire, sql.Named("repo", repo), sql.Named("pull_number", number), sql.Named("stale", RT(now.Add(-ttl)))); err != nil {
		return false, err
	}
	res, err := tx.exec(ghClaimIns, sql.Named("repo", repo), sql.Named("pull_number", number), sql.Named("claimed_at", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReleaseGitHubPRCheck gives up the claim on a pull request.
func (tx *TenantTx) ReleaseGitHubPRCheck(repo string, number int) error {
	_, err := tx.exec(ghClaimDel, sql.Named("repo", repo), sql.Named("pull_number", number))
	return err
}
