package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Credentials, permissions and owners of OAuth apps, and the changes detected
// between two syncs (schema/0680_oauth_app_changes.sql, issue #474). What
// counts as a change is decided by internal/oauthapps; the store holds it.

// OAuth app fact kinds.
const (
	OAuthFactBaseline    = "baseline"
	OAuthFactSecret      = "secret"
	OAuthFactCertificate = "certificate"
	OAuthFactOwner       = "owner"
)

// OAuth app change kinds and statuses.
const (
	OAuthChangeCredential = "credential_added" // #nosec G101 -- the name of a change kind, not a credential
	OAuthChangePermission = "permission_granted"
	OAuthChangeOwner      = "owner_changed"
	OAuthChangeOpen       = "open"
	OAuthChangeResolved   = "resolved"
)

// OAuthFact is something an app holds that a sync compares: a secret, a
// certificate or an owner (or the baseline marker of the app).
type OAuthFact struct {
	ID          string
	AppID       string
	Kind        string
	Key         string
	Label       string
	ProviderRef string // what a removal names at the provider
	AddedAt     *time.Time
	FirstSeen   time.Time
	LastSeen    time.Time
	Status      string // active, removed
}

// OAuthChange is one detected change of an app.
type OAuthChange struct {
	ID         string
	AppID      string
	Kind       string
	Subject    string
	Summary    string
	Detail     json.RawMessage
	DetectedAt time.Time
	Status     string // open, resolved
	ResolvedAt *time.Time
	Resolution string
}

const oauthFactCols = `f.id, f.app_id, f.kind, f.fact_key, f.label, f.provider_ref, f.added_at, f.first_seen, f.last_seen, f.status`

const oauthChangeCols = `c.id, c.app_id, c.kind, c.subject, c.summary, c.detail, c.detected_at, c.status, c.resolved_at, c.resolution`

var (
	oauthFactsInsert = tq("oauth_app_facts.insert", `
		INSERT INTO oauth_app_facts (id, tenant_id, app_id, kind, fact_key, label, provider_ref, added_at, first_seen, last_seen)
		VALUES (@id, @tenant, @app_id, @kind, @fact_key, @label, @provider_ref, @added_at, @now, @now)`)
	oauthFactsTouch = tq("oauth_app_facts.touch", `
		UPDATE oauth_app_facts SET label = @label, provider_ref = @provider_ref, last_seen = @now, status = 'active'
		WHERE tenant_id = @tenant AND id = @id`)
	oauthFactsByKey = tq("oauth_app_facts.by_key", `
		SELECT `+oauthFactCols+` FROM oauth_app_facts f
		WHERE f.tenant_id = @tenant AND f.app_id = @app_id AND f.kind = @kind AND f.fact_key = @fact_key`)
	oauthFactsGet = tq("oauth_app_facts.get", `
		SELECT `+oauthFactCols+` FROM oauth_app_facts f WHERE f.tenant_id = @tenant AND f.id = @id`)
	oauthFactsByApp = tq("oauth_app_facts.by_app", `
		SELECT `+oauthFactCols+` FROM oauth_app_facts f WHERE f.tenant_id = @tenant AND f.app_id = @app_id
		ORDER BY f.kind, f.fact_key, f.id`)
	oauthFactsRemove = tq("oauth_app_facts.mark_removed", `
		UPDATE oauth_app_facts SET status = 'removed'
		WHERE oauth_app_facts.tenant_id = @tenant AND status = 'active' AND kind <> 'baseline' AND last_seen < @before
			AND app_id IN (SELECT a.id FROM oauth_apps a WHERE a.tenant_id = @tenant AND a.provider = @provider)`)
	oauthFactsSetStatus = tq("oauth_app_facts.set_status", `
		UPDATE oauth_app_facts SET status = @status WHERE tenant_id = @tenant AND id = @id`)

	oauthChangesInsert = tq("oauth_app_changes.insert", `
		INSERT INTO oauth_app_changes (id, tenant_id, app_id, kind, subject, summary, detail, detected_at)
		VALUES (@id, @tenant, @app_id, @kind, @subject, @summary, @detail, @now)
		ON CONFLICT (tenant_id, app_id, kind, subject) DO NOTHING`)
	oauthChangesGet = tq("oauth_app_changes.get", `
		SELECT `+oauthChangeCols+` FROM oauth_app_changes c WHERE c.tenant_id = @tenant AND c.id = @id`)
	oauthChangesByApp = tq("oauth_app_changes.by_app", `
		SELECT `+oauthChangeCols+` FROM oauth_app_changes c WHERE c.tenant_id = @tenant AND c.app_id = @app_id
		ORDER BY c.detected_at DESC, c.id`)
	oauthChangesOpen = tq("oauth_app_changes.open", `
		SELECT `+oauthChangeCols+` FROM oauth_app_changes c WHERE c.tenant_id = @tenant AND c.status = 'open'
		ORDER BY c.detected_at DESC, c.id`)
	oauthChangesResolve = tq("oauth_app_changes.resolve", `
		UPDATE oauth_app_changes SET status = 'resolved', resolved_at = @now, resolution = @resolution
		WHERE tenant_id = @tenant AND status = 'open' AND app_id = @app_id AND kind = @kind AND subject = @subject`)
	oauthChangesResolveID = tq("oauth_app_changes.resolve_id", `
		UPDATE oauth_app_changes SET status = 'resolved', resolved_at = @now, resolution = @resolution
		WHERE tenant_id = @tenant AND status = 'open' AND id = @id`)
)

func scanOAuthFact(s scanner) (*OAuthFact, error) {
	var f OAuthFact
	var added sql.NullString
	var first, last string
	if err := s.Scan(&f.ID, &f.AppID, &f.Kind, &f.Key, &f.Label, &f.ProviderRef, &added, &first, &last, &f.Status); err != nil {
		return nil, err
	}
	var err error
	if f.AddedAt, err = rtp(added); err != nil {
		return nil, err
	}
	if f.FirstSeen, err = ParseRT(first); err != nil {
		return nil, err
	}
	f.LastSeen, err = ParseRT(last)
	return &f, err
}

func scanOAuthChange(s scanner) (*OAuthChange, error) {
	var c OAuthChange
	var detail, detected string
	var resolved sql.NullString
	if err := s.Scan(&c.ID, &c.AppID, &c.Kind, &c.Subject, &c.Summary, &detail, &detected, &c.Status, &resolved, &c.Resolution); err != nil {
		return nil, err
	}
	var err error
	c.Detail = json.RawMessage(detail)
	if c.DetectedAt, err = ParseRT(detected); err != nil {
		return nil, err
	}
	c.ResolvedAt, err = rtp(resolved)
	return &c, err
}

// UpsertOAuthFact inserts the fact, or refreshes the fact with the same app,
// kind and key (seen again: it is active again). It reports whether the fact
// is new (or came back after it was marked removed), and sets f.ID.
func (tx *TenantTx) UpsertOAuthFact(f *OAuthFact, now time.Time) (bool, error) {
	got, err := one(tx, scanOAuthFact, oauthFactsByKey, sql.Named("app_id", f.AppID), sql.Named("kind", f.Kind), sql.Named("fact_key", f.Key))
	switch {
	case err == nil:
		if _, err := tx.exec(oauthFactsTouch, sql.Named("id", got.ID), sql.Named("label", f.Label),
			sql.Named("provider_ref", f.ProviderRef), sql.Named("now", RT(now))); err != nil {
			return false, err
		}
		f.ID = got.ID
		return got.Status == "removed", nil
	case !errors.Is(err, ErrNotFound):
		return false, err
	}
	f.ID = NewID()
	_, err = tx.exec(oauthFactsInsert, sql.Named("id", f.ID), sql.Named("app_id", f.AppID), sql.Named("kind", f.Kind),
		sql.Named("fact_key", f.Key), sql.Named("label", f.Label), sql.Named("provider_ref", f.ProviderRef),
		sql.Named("added_at", RTP(f.AddedAt)), sql.Named("now", RT(now)))
	return true, err
}

// OAuthFact returns one fact or ErrNotFound.
func (tx *TenantTx) OAuthFact(id string) (*OAuthFact, error) {
	return one(tx, scanOAuthFact, oauthFactsGet, sql.Named("id", id))
}

// OAuthFactsOf lists an app's facts.
func (tx *TenantTx) OAuthFactsOf(appID string) ([]*OAuthFact, error) {
	return collect(tx, scanOAuthFact, oauthFactsByApp, sql.Named("app_id", appID))
}

// RemoveUnseenOAuthFacts marks the active facts of the provider's apps last
// seen before `before` as removed (a full successful sync did not list them).
func (tx *TenantTx) RemoveUnseenOAuthFacts(provider string, before time.Time) error {
	_, err := tx.exec(oauthFactsRemove, sql.Named("provider", provider), sql.Named("before", RT(before)))
	return err
}

// SetOAuthFactStatus sets a fact active or removed.
func (tx *TenantTx) SetOAuthFactStatus(id, status string) error {
	return tx.execOne(oauthFactsSetStatus, sql.Named("id", id), sql.Named("status", status))
}

// InsertOAuthChange records a change. A change with the same app, kind and
// subject is recorded once: it reports false when it already exists.
func (tx *TenantTx) InsertOAuthChange(c *OAuthChange) (bool, error) {
	if c.Detail == nil {
		c.Detail = json.RawMessage(`{}`)
	}
	c.ID = NewID()
	res, err := tx.exec(oauthChangesInsert, sql.Named("id", c.ID), sql.Named("app_id", c.AppID), sql.Named("kind", c.Kind),
		sql.Named("subject", c.Subject), sql.Named("summary", c.Summary), sql.Named("detail", string(c.Detail)),
		sql.Named("now", RT(c.DetectedAt)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// OAuthChange returns one change or ErrNotFound.
func (tx *TenantTx) OAuthChange(id string) (*OAuthChange, error) {
	return one(tx, scanOAuthChange, oauthChangesGet, sql.Named("id", id))
}

// OAuthChangesOf lists an app's changes, newest first.
func (tx *TenantTx) OAuthChangesOf(appID string) ([]*OAuthChange, error) {
	return collect(tx, scanOAuthChange, oauthChangesByApp, sql.Named("app_id", appID))
}

// OpenOAuthChanges lists the tenant's open changes, newest first.
func (tx *TenantTx) OpenOAuthChanges() ([]*OAuthChange, error) {
	return collect(tx, scanOAuthChange, oauthChangesOpen)
}

// ResolveOAuthChange closes the open change of an app with this kind and subject.
func (tx *TenantTx) ResolveOAuthChange(appID, kind, subject, resolution string, now time.Time) error {
	_, err := tx.exec(oauthChangesResolve, sql.Named("app_id", appID), sql.Named("kind", kind), sql.Named("subject", subject),
		sql.Named("resolution", resolution), sql.Named("now", RT(now)))
	return err
}

// ResolveOAuthChangeID closes one open change; ErrNotFound when it is not open.
func (tx *TenantTx) ResolveOAuthChangeID(id, resolution string, now time.Time) error {
	return tx.execOne(oauthChangesResolveID, sql.Named("id", id), sql.Named("resolution", resolution), sql.Named("now", RT(now)))
}
