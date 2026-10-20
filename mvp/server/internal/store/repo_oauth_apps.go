package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Third-party OAuth app inventory (schema/0361_oauth_apps.sql). The risk
// score and the reasons are computed by internal/oauthapps; the store only
// holds them.

// OAuth providers.
const (
	OAuthGoogle     = "google"
	OAuthEntra      = "entra"
	OAuthSalesforce = "salesforce"
	OAuthGitHub     = "github"
)

// OAuth app and grant statuses.
const (
	OAuthActive       = "active"
	OAuthRevoked      = "revoked"
	OAuthRemoved      = "removed"
	OAuthRevokeFailed = "revoke_failed"
)

// OAuthApp is one third-party app at one provider.
type OAuthApp struct {
	ID              string
	Provider        string
	ClientID        string
	Name            string
	Publisher       string
	Verified        bool
	FirstSeen       time.Time
	LastSeen        time.Time
	LastUsed        *time.Time
	OwnerIdentityID *int64
	RiskScore       int
	RiskReasons     []string
	Status          string // active, revoked, removed
	RevokedAt       *time.Time
	RevokedBy       *string
}

// OAuthGrant is one grant an app holds.
type OAuthGrant struct {
	ID           string
	AppID        string
	Provider     string
	GrantKey     string // stable per grant at the provider; with AppID it is the upsert key
	ProviderRef  string // what the revoke call names (a grant id, a token id, a user)
	Kind         string // token, delegated, app_role, installation, credential
	IdentityID   *int64
	AccountID    *int64
	UserRef      string
	GranterAdmin bool
	Scopes       []string
	ConsentType  string // user, admin
	GrantedAt    *time.Time
	LastUsed     *time.Time
	FirstSeen    time.Time
	LastSeen     time.Time
	Status       string // active, removed, revoked, revoke_failed
	RevokedAt    *time.Time
	RevokedBy    *string
	RevokeError  string
}

// OAuthSyncState is the last sync of one provider.
type OAuthSyncState struct {
	Provider    string
	Status      string // ok, failed
	AttemptedAt time.Time
	SucceededAt *time.Time
	Apps        int
	Grants      int
	Removed     int
	Error       string
}

const oauthAppCols = `a.id, a.provider, a.client_id, a.name, a.publisher, a.verified, a.first_seen, a.last_seen, a.last_used,
	a.owner_identity_id, a.risk_score, a.risk_reasons, a.status, a.revoked_at, a.revoked_by`

const oauthGrantCols = `g.id, g.app_id, g.provider, g.grant_key, g.provider_ref, g.kind, g.identity_id, g.account_id, g.user_ref,
	g.granter_admin, g.scopes, g.consent_type, g.granted_at, g.last_used, g.first_seen, g.last_seen, g.status,
	g.revoked_at, g.revoked_by, g.revoke_error`

var (
	oauthAppsUpsert = tq("oauth_apps.upsert", `
		INSERT INTO oauth_apps (id, tenant_id, provider, client_id, name, publisher, verified, first_seen, last_seen, last_used)
		VALUES (@id, @tenant, @provider, @client_id, @name, @publisher, @verified, @now, @now, @last_used)
		ON CONFLICT (tenant_id, provider, client_id) DO UPDATE SET name = excluded.name, publisher = excluded.publisher,
			verified = excluded.verified, last_seen = excluded.last_seen,
			last_used = COALESCE(excluded.last_used, oauth_apps.last_used)`)
	oauthAppsByKey = tq("oauth_apps.by_key", `
		SELECT `+oauthAppCols+` FROM oauth_apps a
		WHERE a.tenant_id = @tenant AND a.provider = @provider AND a.client_id = @client_id`)
	oauthAppsGet = tq("oauth_apps.get", `
		SELECT `+oauthAppCols+` FROM oauth_apps a WHERE a.tenant_id = @tenant AND a.id = @id`)
	oauthAppsList = tq("oauth_apps.list", `
		SELECT `+oauthAppCols+` FROM oauth_apps a WHERE a.tenant_id = @tenant
		ORDER BY a.risk_score DESC, a.name, a.id`)
	oauthAppsCount = tq("oauth_apps.count", `
		SELECT count(a.id) FROM oauth_apps a WHERE a.tenant_id = @tenant`)
	oauthAppsSetRisk = tq("oauth_apps.set_risk", `
		UPDATE oauth_apps SET risk_score = @risk_score, risk_reasons = @risk_reasons, last_used = @last_used,
			status = CASE WHEN status = 'revoked' AND @status = 'removed' THEN 'revoked' ELSE @status END
		WHERE tenant_id = @tenant AND id = @id`)
	oauthAppsDefaultOwner = tq("oauth_apps.default_owner", `
		UPDATE oauth_apps SET owner_identity_id = @owner_identity_id
		WHERE tenant_id = @tenant AND id = @id AND owner_identity_id IS NULL`)
	oauthAppsSetOwner = tq("oauth_apps.set_owner", `
		UPDATE oauth_apps SET owner_identity_id = @owner_identity_id WHERE tenant_id = @tenant AND id = @id`)
	oauthAppsMarkRevoked = tq("oauth_apps.mark_revoked", `
		UPDATE oauth_apps SET status = 'revoked', revoked_at = @now, revoked_by = @by WHERE tenant_id = @tenant AND id = @id`)

	oauthGrantsUpsert = tq("oauth_grants.upsert", `
		INSERT INTO oauth_grants (id, tenant_id, app_id, provider, grant_key, provider_ref, kind, identity_id, account_id,
			user_ref, granter_admin, scopes, consent_type, granted_at, last_used, first_seen, last_seen)
		VALUES (@id, @tenant, @app_id, @provider, @grant_key, @provider_ref, @kind, @identity_id, @account_id,
			@user_ref, @granter_admin, @scopes, @consent_type, @granted_at, @last_used, @now, @now)
		ON CONFLICT (tenant_id, app_id, grant_key) DO UPDATE SET provider_ref = excluded.provider_ref, kind = excluded.kind,
			identity_id = excluded.identity_id, account_id = excluded.account_id, user_ref = excluded.user_ref,
			granter_admin = excluded.granter_admin, scopes = excluded.scopes, consent_type = excluded.consent_type,
			granted_at = COALESCE(excluded.granted_at, oauth_grants.granted_at),
			last_used = COALESCE(excluded.last_used, oauth_grants.last_used), last_seen = excluded.last_seen,
			status = CASE WHEN oauth_grants.status = 'revoke_failed' THEN 'revoke_failed' ELSE 'active' END,
			revoked_at = CASE WHEN oauth_grants.status = 'revoke_failed' THEN oauth_grants.revoked_at ELSE NULL END,
			revoked_by = CASE WHEN oauth_grants.status = 'revoke_failed' THEN oauth_grants.revoked_by ELSE NULL END,
			revoke_error = CASE WHEN oauth_grants.status = 'revoke_failed' THEN oauth_grants.revoke_error ELSE '' END`)
	oauthGrantsByKey = tq("oauth_grants.by_key", `
		SELECT `+oauthGrantCols+` FROM oauth_grants g
		WHERE g.tenant_id = @tenant AND g.app_id = @app_id AND g.grant_key = @grant_key`)
	oauthGrantsGet = tq("oauth_grants.get", `
		SELECT `+oauthGrantCols+` FROM oauth_grants g WHERE g.tenant_id = @tenant AND g.id = @id`)
	oauthGrantsByApp = tq("oauth_grants.by_app", `
		SELECT `+oauthGrantCols+` FROM oauth_grants g WHERE g.tenant_id = @tenant AND g.app_id = @app_id
		ORDER BY g.user_ref, g.grant_key, g.id`)
	oauthGrantsAll = tq("oauth_grants.list", `
		SELECT `+oauthGrantCols+` FROM oauth_grants g WHERE g.tenant_id = @tenant ORDER BY g.app_id, g.user_ref, g.grant_key, g.id`)
	oauthGrantsRemove = tq("oauth_grants.mark_removed", `
		UPDATE oauth_grants SET status = 'removed'
		WHERE tenant_id = @tenant AND provider = @provider AND status IN ('active','revoke_failed') AND last_seen < @before`)
	oauthGrantsSetStatus = tq("oauth_grants.set_status", `
		UPDATE oauth_grants SET status = @status, revoked_at = @revoked_at, revoked_by = @revoked_by, revoke_error = @revoke_error
		WHERE tenant_id = @tenant AND id = @id`)

	oauthSyncUpsert = tq("oauth_sync_state.upsert", `
		INSERT INTO oauth_sync_state (tenant_id, provider, status, attempted_at, succeeded_at, apps, grants, removed, error)
		VALUES (@tenant, @provider, @status, @attempted_at, @succeeded_at, @apps, @grants, @removed, @error)
		ON CONFLICT (tenant_id, provider) DO UPDATE SET status = excluded.status, attempted_at = excluded.attempted_at,
			succeeded_at = COALESCE(excluded.succeeded_at, oauth_sync_state.succeeded_at),
			apps = CASE WHEN excluded.status = 'ok' THEN excluded.apps ELSE oauth_sync_state.apps END,
			grants = CASE WHEN excluded.status = 'ok' THEN excluded.grants ELSE oauth_sync_state.grants END,
			removed = CASE WHEN excluded.status = 'ok' THEN excluded.removed ELSE oauth_sync_state.removed END,
			error = excluded.error`)
	oauthSyncList = tq("oauth_sync_state.list", `
		SELECT s.provider, s.status, s.attempted_at, s.succeeded_at, s.apps, s.grants, s.removed, s.error
		FROM oauth_sync_state s WHERE s.tenant_id = @tenant ORDER BY s.provider`)
)

func scanOAuthApp(s scanner) (*OAuthApp, error) {
	var a OAuthApp
	var verified int
	var first, last string
	var used, revoked, revokedBy sql.NullString
	var owner sql.NullInt64
	var reasons string
	if err := s.Scan(&a.ID, &a.Provider, &a.ClientID, &a.Name, &a.Publisher, &verified, &first, &last, &used, &owner,
		&a.RiskScore, &reasons, &a.Status, &revoked, &revokedBy); err != nil {
		return nil, err
	}
	var err error
	a.Verified = verified == 1
	if a.FirstSeen, err = ParseRT(first); err != nil {
		return nil, err
	}
	if a.LastSeen, err = ParseRT(last); err != nil {
		return nil, err
	}
	if a.LastUsed, err = rtp(used); err != nil {
		return nil, err
	}
	if a.RevokedAt, err = rtp(revoked); err != nil {
		return nil, err
	}
	a.OwnerIdentityID, a.RevokedBy = intp(owner), strp(revokedBy)
	a.RiskReasons = []string{}
	if err := json.Unmarshal([]byte(reasons), &a.RiskReasons); err != nil {
		return nil, err
	}
	return &a, nil
}

func scanOAuthGrant(s scanner) (*OAuthGrant, error) {
	var g OAuthGrant
	var admin int
	var ident, acct sql.NullInt64
	var scopes, first, last string
	var granted, used, revoked, revokedBy sql.NullString
	if err := s.Scan(&g.ID, &g.AppID, &g.Provider, &g.GrantKey, &g.ProviderRef, &g.Kind, &ident, &acct, &g.UserRef, &admin,
		&scopes, &g.ConsentType, &granted, &used, &first, &last, &g.Status, &revoked, &revokedBy, &g.RevokeError); err != nil {
		return nil, err
	}
	var err error
	g.GranterAdmin = admin == 1
	g.IdentityID, g.AccountID, g.RevokedBy = intp(ident), intp(acct), strp(revokedBy)
	if g.GrantedAt, err = rtp(granted); err != nil {
		return nil, err
	}
	if g.LastUsed, err = rtp(used); err != nil {
		return nil, err
	}
	if g.RevokedAt, err = rtp(revoked); err != nil {
		return nil, err
	}
	if g.FirstSeen, err = ParseRT(first); err != nil {
		return nil, err
	}
	if g.LastSeen, err = ParseRT(last); err != nil {
		return nil, err
	}
	g.Scopes = []string{}
	if err := json.Unmarshal([]byte(scopes), &g.Scopes); err != nil {
		return nil, err
	}
	return &g, nil
}

func scanOAuthSync(s scanner) (*OAuthSyncState, error) {
	var st OAuthSyncState
	var attempted string
	var succeeded sql.NullString
	if err := s.Scan(&st.Provider, &st.Status, &attempted, &succeeded, &st.Apps, &st.Grants, &st.Removed, &st.Error); err != nil {
		return nil, err
	}
	var err error
	if st.AttemptedAt, err = ParseRT(attempted); err != nil {
		return nil, err
	}
	st.SucceededAt, err = rtp(succeeded)
	return &st, err
}

// UpsertOAuthApp inserts the app, or refreshes name, publisher, verified,
// last_seen and last_used of the app with the same provider and client id. It
// sets a.ID (an existing app keeps its id). Risk, status and owner are set by
// SetOAuthAppRisk and the owner methods.
func (tx *TenantTx) UpsertOAuthApp(a *OAuthApp, now time.Time) error {
	if _, err := tx.exec(oauthAppsUpsert, sql.Named("id", NewID()), sql.Named("provider", a.Provider),
		sql.Named("client_id", a.ClientID), sql.Named("name", a.Name), sql.Named("publisher", a.Publisher),
		sql.Named("verified", B(a.Verified)), sql.Named("now", RT(now)), sql.Named("last_used", RTP(a.LastUsed))); err != nil {
		return err
	}
	got, err := tx.OAuthAppByKey(a.Provider, a.ClientID)
	if err != nil {
		return err
	}
	*a = *got
	return nil
}

// OAuthAppByKey returns the app of a provider and client id, or ErrNotFound.
func (tx *TenantTx) OAuthAppByKey(provider, clientID string) (*OAuthApp, error) {
	return one(tx, scanOAuthApp, oauthAppsByKey, sql.Named("provider", provider), sql.Named("client_id", clientID))
}

// OAuthApp returns one app or ErrNotFound.
func (tx *TenantTx) OAuthApp(id string) (*OAuthApp, error) {
	return one(tx, scanOAuthApp, oauthAppsGet, sql.Named("id", id))
}

// OAuthApps lists the tenant's apps, highest risk first.
func (tx *TenantTx) OAuthApps() ([]*OAuthApp, error) { return collect(tx, scanOAuthApp, oauthAppsList) }

// CountOAuthApps counts the tenant's apps.
func (tx *TenantTx) CountOAuthApps() (int, error) { return tx.count(oauthAppsCount) }

// SetOAuthAppRisk stores the computed risk and the app's status. A revoked
// app stays revoked when status says removed.
func (tx *TenantTx) SetOAuthAppRisk(id string, score int, reasons []string, lastUsed *time.Time, status string) error {
	rj, err := JSON(reasons)
	if err != nil {
		return err
	}
	return tx.execOne(oauthAppsSetRisk, sql.Named("id", id), sql.Named("risk_score", score), sql.Named("risk_reasons", rj),
		sql.Named("last_used", RTP(lastUsed)), sql.Named("status", status))
}

// DefaultOAuthAppOwner sets the owner of an app that has none.
func (tx *TenantTx) DefaultOAuthAppOwner(id string, owner int64) error {
	_, err := tx.exec(oauthAppsDefaultOwner, sql.Named("id", id), sql.Named("owner_identity_id", owner))
	return err
}

// SetOAuthAppOwner sets (or, with nil, clears) the owner of an app.
func (tx *TenantTx) SetOAuthAppOwner(id string, owner *int64) error {
	return tx.execOne(oauthAppsSetOwner, sql.Named("id", id), sql.Named("owner_identity_id", IP(owner)))
}

// MarkOAuthAppRevoked marks an app revoked across the tenant.
func (tx *TenantTx) MarkOAuthAppRevoked(id, by string, now time.Time) error {
	return tx.execOne(oauthAppsMarkRevoked, sql.Named("id", id), sql.Named("by", by), sql.Named("now", RT(now)))
}

// UpsertOAuthGrant inserts the grant, or refreshes the grant with the same app
// and grant key (seen again: it is active again, unless a revoke failed on
// it, which stays visible). It sets g.ID.
func (tx *TenantTx) UpsertOAuthGrant(g *OAuthGrant, now time.Time) error {
	scopes, err := JSON(g.Scopes)
	if err != nil {
		return err
	}
	if _, err := tx.exec(oauthGrantsUpsert, sql.Named("id", NewID()), sql.Named("app_id", g.AppID),
		sql.Named("provider", g.Provider), sql.Named("grant_key", g.GrantKey), sql.Named("provider_ref", g.ProviderRef),
		sql.Named("kind", g.Kind), sql.Named("identity_id", IP(g.IdentityID)), sql.Named("account_id", IP(g.AccountID)),
		sql.Named("user_ref", g.UserRef), sql.Named("granter_admin", B(g.GranterAdmin)), sql.Named("scopes", scopes),
		sql.Named("consent_type", g.ConsentType), sql.Named("granted_at", RTP(g.GrantedAt)),
		sql.Named("last_used", RTP(g.LastUsed)), sql.Named("now", RT(now))); err != nil {
		return err
	}
	got, err := one(tx, scanOAuthGrant, oauthGrantsByKey, sql.Named("app_id", g.AppID), sql.Named("grant_key", g.GrantKey))
	if err != nil {
		return err
	}
	*g = *got
	return nil
}

// OAuthGrant returns one grant or ErrNotFound.
func (tx *TenantTx) OAuthGrant(id string) (*OAuthGrant, error) {
	return one(tx, scanOAuthGrant, oauthGrantsGet, sql.Named("id", id))
}

// OAuthGrantsOf lists an app's grants.
func (tx *TenantTx) OAuthGrantsOf(appID string) ([]*OAuthGrant, error) {
	return collect(tx, scanOAuthGrant, oauthGrantsByApp, sql.Named("app_id", appID))
}

// OAuthGrants lists every grant of the tenant.
func (tx *TenantTx) OAuthGrants() ([]*OAuthGrant, error) {
	return collect(tx, scanOAuthGrant, oauthGrantsAll)
}

// RemoveUnseenOAuthGrants marks the provider's active grants last seen before
// `before` as removed (a full successful sync did not list them) and returns
// how many. Revoked grants keep their status.
func (tx *TenantTx) RemoveUnseenOAuthGrants(provider string, before time.Time) (int, error) {
	res, err := tx.exec(oauthGrantsRemove, sql.Named("provider", provider), sql.Named("before", RT(before)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// SetOAuthGrantStatus records the outcome of a revoke on a grant: revoked,
// revoke_failed (with the error) or active again.
func (tx *TenantTx) SetOAuthGrantStatus(id, status string, by *string, at *time.Time, revokeError string) error {
	return tx.execOne(oauthGrantsSetStatus, sql.Named("id", id), sql.Named("status", status), sql.Named("revoked_at", RTP(at)),
		sql.Named("revoked_by", SP(by)), sql.Named("revoke_error", revokeError))
}

// PutOAuthSyncState records the result of a provider's sync. A failed sync
// keeps the counts and the success time of the last good one.
func (tx *TenantTx) PutOAuthSyncState(st *OAuthSyncState) error {
	_, err := tx.exec(oauthSyncUpsert, sql.Named("provider", st.Provider), sql.Named("status", st.Status),
		sql.Named("attempted_at", RT(st.AttemptedAt)), sql.Named("succeeded_at", RTP(st.SucceededAt)),
		sql.Named("apps", st.Apps), sql.Named("grants", st.Grants), sql.Named("removed", st.Removed), sql.Named("error", st.Error))
	return err
}

// OAuthSyncStates lists the last sync of each provider.
func (tx *TenantTx) OAuthSyncStates() ([]*OAuthSyncState, error) {
	return collect(tx, scanOAuthSync, oauthSyncList)
}
