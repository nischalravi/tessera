package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// GitHub and CI token inventory (schema/0710_github_tokens.sql, issue #476).
// Only metadata is held: a token or secret value is never read. The risk of a
// token is computed by internal/ghtokens when it is listed.

// GitHub token kinds and statuses.
const (
	GHClassicPAT     = "classic_pat"
	GHFineGrainedPAT = "fine_grained_pat"
	GHOAuthAppToken  = "oauth_app_token" // #nosec G101 -- the name of a token kind, not a credential
	GHActionsSecret  = "actions_secret"  // #nosec G101 -- the name of a secret kind, not a credential
	GHTokenActive    = "active"
	GHTokenRemoved   = "removed"
)

// GitHubToken is one credential of a GitHub organization.
type GitHubToken struct {
	ID              string
	Key             string // stable per credential at GitHub; the upsert key
	Kind            string
	Name            string
	OwnerLogin      string
	OwnerIdentityID *int64
	Scopes          []string // scopes, or permissions as "name:level"
	Visibility      string   // Actions secrets: all, private or selected
	CreatedAt       *time.Time
	RotatedAt       *time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time
	FirstSeen       time.Time
	LastSeen        time.Time
	Status          string
}

const githubTokenCols = /* #nosec G101 -- column names, not credentials */ `t.id, t.token_key, t.kind, t.name, t.owner_login, t.owner_identity_id, t.scopes, t.visibility,
	t.created_at, t.rotated_at, t.expires_at, t.last_used_at, t.first_seen, t.last_seen, t.status`

var (
	githubTokensUpsert = tq("github_tokens.upsert", `
		INSERT INTO github_tokens (id, tenant_id, token_key, kind, name, owner_login, owner_identity_id, scopes, visibility,
			created_at, rotated_at, expires_at, last_used_at, first_seen, last_seen)
		VALUES (@id, @tenant, @token_key, @kind, @name, @owner_login, @owner_identity_id, @scopes, @visibility,
			@created_at, @rotated_at, @expires_at, @last_used_at, @now, @now)
		ON CONFLICT (tenant_id, token_key) DO UPDATE SET kind = excluded.kind, name = excluded.name,
			owner_login = excluded.owner_login, owner_identity_id = excluded.owner_identity_id, scopes = excluded.scopes,
			visibility = excluded.visibility, created_at = excluded.created_at, rotated_at = excluded.rotated_at,
			expires_at = excluded.expires_at, last_used_at = COALESCE(excluded.last_used_at, github_tokens.last_used_at),
			last_seen = excluded.last_seen, status = 'active'`)
	githubTokensList = tq("github_tokens.list", `
		SELECT `+githubTokenCols+` FROM github_tokens t WHERE t.tenant_id = @tenant ORDER BY t.kind, t.name, t.id`)
	githubTokensRemove = tq("github_tokens.mark_removed", `
		UPDATE github_tokens SET status = 'removed'
		WHERE tenant_id = @tenant AND status = 'active' AND last_seen < @before`)
)

func scanGitHubToken(s scanner) (*GitHubToken, error) {
	var t GitHubToken
	var ident sql.NullInt64
	var scopes, first, last string
	var created, rotated, expires, used sql.NullString
	if err := s.Scan(&t.ID, &t.Key, &t.Kind, &t.Name, &t.OwnerLogin, &ident, &scopes, &t.Visibility,
		&created, &rotated, &expires, &used, &first, &last, &t.Status); err != nil {
		return nil, err
	}
	var err error
	t.OwnerIdentityID = intp(ident)
	for _, f := range []struct {
		n sql.NullString
		d **time.Time
	}{{created, &t.CreatedAt}, {rotated, &t.RotatedAt}, {expires, &t.ExpiresAt}, {used, &t.LastUsedAt}} {
		if *f.d, err = rtp(f.n); err != nil {
			return nil, err
		}
	}
	if t.FirstSeen, err = ParseRT(first); err != nil {
		return nil, err
	}
	if t.LastSeen, err = ParseRT(last); err != nil {
		return nil, err
	}
	t.Scopes = []string{}
	if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
		return nil, err
	}
	return &t, nil
}

// UpsertGitHubToken inserts the credential, or refreshes the one with the same
// key (seen again: it is active again). It sets t.ID.
func (tx *TenantTx) UpsertGitHubToken(t *GitHubToken, now time.Time) error {
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	sj, err := JSON(t.Scopes)
	if err != nil {
		return err
	}
	if _, err := tx.exec(githubTokensUpsert, sql.Named("id", NewID()), sql.Named("token_key", t.Key), sql.Named("kind", t.Kind),
		sql.Named("name", t.Name), sql.Named("owner_login", t.OwnerLogin), sql.Named("owner_identity_id", t.OwnerIdentityID),
		sql.Named("scopes", sj), sql.Named("visibility", t.Visibility), sql.Named("created_at", RTP(t.CreatedAt)),
		sql.Named("rotated_at", RTP(t.RotatedAt)), sql.Named("expires_at", RTP(t.ExpiresAt)),
		sql.Named("last_used_at", RTP(t.LastUsedAt)), sql.Named("now", RT(now))); err != nil {
		return err
	}
	return nil
}

// GitHubTokens lists the tenant's credentials, removed ones included.
func (tx *TenantTx) GitHubTokens() ([]*GitHubToken, error) {
	return collect(tx, scanGitHubToken, githubTokensList)
}

// RemoveUnseenGitHubTokens marks the active credentials last seen before
// `before` as removed (a full successful read did not list them).
func (tx *TenantTx) RemoveUnseenGitHubTokens(before time.Time) error {
	_, err := tx.exec(githubTokensRemove, sql.Named("before", RT(before)))
	return err
}
