package store

import (
	"database/sql"
	"errors"
	"time"
)

// The access-diff pull request comment settings (schema/0321_aws_integration.sql).
// One row per tenant; a tenant with no row has the feature off.

var (
	awsPRGet = tq("aws_pr_comment_settings.get", `
		SELECT s.enabled, s.repo, s.token_enc, s.updated_by, s.updated_at
		FROM aws_pr_comment_settings s WHERE s.tenant_id = @tenant`)
	awsPRPut = tq("aws_pr_comment_settings.put", `
		INSERT INTO aws_pr_comment_settings (tenant_id, enabled, repo, token_enc, updated_by, updated_at)
		VALUES (@tenant, @enabled, @repo, @token_enc, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, repo = excluded.repo,
			token_enc = excluded.token_enc, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// AWSPRCommentSettings returns the tenant's settings. A tenant that never set
// them gets the zero value (disabled, no token) and no error.
func (tx *TenantTx) AWSPRCommentSettings() (*AWSPRCommentSettings, error) {
	s, err := one(tx, func(r scanner) (*AWSPRCommentSettings, error) {
		var s AWSPRCommentSettings
		var enabled int
		var at string
		if err := r.Scan(&enabled, &s.Repo, &s.TokenEnc, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		var err error
		s.UpdatedAt, err = ParseRT(at)
		return &s, err
	}, awsPRGet)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return &AWSPRCommentSettings{}, nil
	}
	return s, err
}

// PutAWSPRCommentSettings replaces the tenant's settings.
func (tx *TenantTx) PutAWSPRCommentSettings(s *AWSPRCommentSettings, now time.Time) error {
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	_, err := tx.exec(awsPRPut, sql.Named("enabled", enabled), sql.Named("repo", s.Repo),
		sql.Named("token_enc", s.TokenEnc), sql.Named("updated_by", s.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}
