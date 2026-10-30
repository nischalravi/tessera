package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// The OAuth authorization server's repositories (design §7.4,
// schema/0358_oauth.sql). Every statement is tenant-scoped (tq).

// ---------------------------------------------------------------- api_clients

const clientCols = `c.id, c.tenant_id, c.client_id, c.name, c.kind, c.grant_types, c.token_endpoint_auth_method, c.jwks,
	c.dpop_required, c.allowed_scopes, c.roles, c.owner_user_id, c.status, c.created_at, c.last_used_at, c.approved_by`

var (
	clientsInsert = tq("api_clients.insert", `
		INSERT INTO api_clients (id, tenant_id, client_id, name, kind, grant_types, token_endpoint_auth_method, jwks,
			dpop_required, allowed_scopes, roles, owner_user_id, status, created_at, approved_by)
		VALUES (@id, @tenant, @client_id, @name, @kind, @grant_types, @token_endpoint_auth_method, @jwks,
			@dpop_required, @allowed_scopes, @roles, @owner_user_id, @status, @created_at, @approved_by)`)
	clientsByClientID = tq("api_clients.by_client_id", `
		SELECT `+clientCols+` FROM api_clients c WHERE c.tenant_id = @tenant AND c.client_id = @client_id`)
	clientsList = tq("api_clients.list", `
		SELECT `+clientCols+` FROM api_clients c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.rowid`)
	clientsSetKeys = tq("api_clients.set_keys", `
		UPDATE api_clients SET jwks = @jwks WHERE tenant_id = @tenant AND client_id = @client_id AND kind = 'machine'`)
	clientsSetApprover = tq("api_clients.set_approver", `
		UPDATE api_clients SET approved_by = @approved_by WHERE tenant_id = @tenant AND client_id = @client_id AND kind = 'machine'`)
	clientsSetStatus = tq("api_clients.set_status", `
		UPDATE api_clients SET status = @status WHERE tenant_id = @tenant AND client_id = @client_id AND kind = 'machine'`)
	clientsAddScope = tq("api_clients.add_scope", `
		UPDATE api_clients SET allowed_scopes = @allowed_scopes WHERE tenant_id = @tenant AND client_id = @client_id AND kind = 'machine'`)
	clientsTouch = tq("api_clients.touch", `
		UPDATE api_clients SET last_used_at = @at WHERE tenant_id = @tenant AND client_id = @client_id`)
)

func scanClient(s scanner) (*APIClient, error) {
	var x APIClient
	var id, tid, grants, scopes, roles, created string
	var jwks, owner, lastUsed sql.NullString
	var dpop int
	if err := s.Scan(&id, &tid, &x.ClientID, &x.Name, &x.Kind, &grants, &x.TokenEndpointAuthMethod, &jwks, &dpop, &scopes,
		&roles, &owner, &x.Status, &created, &lastUsed, &x.ApprovedBy); err != nil {
		return nil, err
	}
	var err error
	if x.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst *[]string
		src string
	}{{&x.GrantTypes, grants}, {&x.AllowedScopes, scopes}, {&x.Roles, roles}} {
		if err := json.Unmarshal([]byte(p.src), p.dst); err != nil {
			return nil, err
		}
	}
	if jwks.Valid {
		x.JWKS = []byte(jwks.String)
	}
	x.DPoPRequired = dpop == 1
	if owner.Valid {
		u, err := uuid.Parse(owner.String)
		if err != nil {
			return nil, err
		}
		x.OwnerUserID = &u
	}
	if x.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	x.LastUsedAt, err = rtp(lastUsed)
	return &x, err
}

// InsertAPIClient creates a client (a zero ID gets a fresh one; a zero
// Status is active). ErrDuplicate if the tenant already has the client_id.
func (tx *TenantTx) InsertAPIClient(x *APIClient) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	if x.Status == "" {
		x.Status = ClientActive
	}
	grants, err := jsonList(x.GrantTypes)
	if err != nil {
		return err
	}
	scopes, err := jsonList(x.AllowedScopes)
	if err != nil {
		return err
	}
	roles, err := jsonList(x.Roles)
	if err != nil {
		return err
	}
	var jwks any
	if len(x.JWKS) > 0 {
		jwks = string(x.JWKS)
	}
	_, err = tx.exec(clientsInsert, sql.Named("id", x.ID.String()), sql.Named("client_id", x.ClientID),
		sql.Named("name", x.Name), sql.Named("kind", x.Kind), sql.Named("grant_types", grants),
		sql.Named("token_endpoint_auth_method", x.TokenEndpointAuthMethod), sql.Named("jwks", jwks),
		sql.Named("dpop_required", B(x.DPoPRequired)), sql.Named("allowed_scopes", scopes), sql.Named("roles", roles),
		sql.Named("owner_user_id", uuidOrNil(x.OwnerUserID)), sql.Named("status", x.Status),
		sql.Named("created_at", RT(x.CreatedAt)), sql.Named("approved_by", x.ApprovedBy))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// APIClientByClientID returns this tenant's client (ErrNotFound otherwise).
func (tx *TenantTx) APIClientByClientID(clientID string) (*APIClient, error) {
	return one(tx, scanClient, clientsByClientID, sql.Named("client_id", clientID))
}

// APIClients lists this tenant's clients in creation order.
func (tx *TenantTx) APIClients() ([]*APIClient, error) { return collect(tx, scanClient, clientsList) }

// SetAPIClientKeys replaces the registered public key set (canonical JWKS JSON) of this tenant's machine client
// (ErrNotFound for another tenant's client, a missing one and the first-party CLI client).
func (tx *TenantTx) SetAPIClientKeys(clientID string, jwks []byte) error {
	return tx.execOne(clientsSetKeys, sql.Named("jwks", string(jwks)), sql.Named("client_id", clientID))
}

// SetAPIClientApprover records who vouched for the machine client's permissions now (ErrNotFound as for SetAPIClientKeys).
func (tx *TenantTx) SetAPIClientApprover(clientID, approvedBy string) error {
	return tx.execOne(clientsSetApprover, sql.Named("approved_by", approvedBy), sql.Named("client_id", clientID))
}

// SetAPIClientStatus enables or disables this tenant's machine client (ErrNotFound as for SetAPIClientKeys). A
// disabled client gets no new token, and the tokens it holds stop working at once.
func (tx *TenantTx) SetAPIClientStatus(clientID, status string) error {
	return tx.execOne(clientsSetStatus, sql.Named("status", status), sql.Named("client_id", clientID))
}

// SetAPIClientScopes replaces the scopes this tenant's machine client may be granted (ErrNotFound as for SetAPIClientKeys).
// Only internal/admin calls it (the two-admin config.propose grant, and SetClientScopes, which cancels proposals).
func (tx *TenantTx) SetAPIClientScopes(clientID string, scopes []string) error {
	list, err := jsonList(scopes)
	if err != nil {
		return err
	}
	return tx.execOne(clientsAddScope, sql.Named("allowed_scopes", list), sql.Named("client_id", clientID))
}

// TouchAPIClient records a use of the client.
func (tx *TenantTx) TouchAPIClient(clientID string, at time.Time) error {
	return tx.execOne(clientsTouch, sql.Named("at", RT(at)), sql.Named("client_id", clientID))
}

// ---------------------------------------------------------------- device_grants

const deviceCols = `g.id, g.tenant_id, g.client_id, g.device_code_hash, g.user_code_hash, g.scope, g.required_tessera_acr,
	g.max_age, g.status, g.request_ip, g.request_user_agent, g.poll_interval, g.last_polled_at, g.created_at, g.expires_at,
	g.approved_by_user_id, g.approved_authn_context_id, g.approved_at, g.session_id`

var (
	deviceInsert = tq("device_grants.insert", `
		INSERT INTO device_grants (id, tenant_id, client_id, device_code_hash, user_code_hash, scope, required_tessera_acr,
			max_age, status, request_ip, request_user_agent, poll_interval, created_at, expires_at)
		VALUES (@id, @tenant, @client_id, @device_code_hash, @user_code_hash, @scope, @required_tessera_acr,
			@max_age, 'pending', @request_ip, @request_user_agent, @poll_interval, @created_at, @expires_at)`)
	deviceGet = tq("device_grants.get", `
		SELECT `+deviceCols+` FROM device_grants g WHERE g.tenant_id = @tenant AND g.id = @id`)
	deviceByDeviceCode = tq("device_grants.by_device_code", `
		SELECT `+deviceCols+` FROM device_grants g WHERE g.tenant_id = @tenant AND g.device_code_hash = @hash`)
	devicePendingByUserCode = tq("device_grants.pending_by_user_code", `
		SELECT `+deviceCols+` FROM device_grants g
		WHERE g.tenant_id = @tenant AND g.user_code_hash = @hash AND g.status = 'pending' AND g.expires_at > @now`)
	deviceExpireStale = tq("device_grants.expire_stale", `
		UPDATE device_grants SET status = 'expired'
		WHERE tenant_id = @tenant AND status = 'pending' AND expires_at <= @now`)
	devicePoll = tq("device_grants.poll", `
		UPDATE device_grants SET last_polled_at = @at, poll_interval = @poll_interval
		WHERE tenant_id = @tenant AND id = @id`)
	deviceApprove = tq("device_grants.approve", `
		UPDATE device_grants SET status = 'approved', approved_by_user_id = @user_id, approved_authn_context_id = @ctx_id,
			approved_at = @at, session_id = @session_id
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending' AND expires_at > @at`)
	deviceDeny = tq("device_grants.deny", `
		UPDATE device_grants SET status = 'denied', approved_by_user_id = @user_id, approved_at = @at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending' AND expires_at > @at`)
	deviceExpire = tq("device_grants.expire", `
		UPDATE device_grants SET status = 'expired' WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
	deviceConsume = tq("device_grants.consume", `
		UPDATE device_grants SET status = 'consumed'
		WHERE tenant_id = @tenant AND id = @id AND status = 'approved' AND expires_at > @at`)
)

func scanDevice(s scanner) (*DeviceGrant, error) {
	var x DeviceGrant
	var id, tid, created, expires string
	var acr, ip, ua, polled, approvedBy, approvedCtx, approvedAt, sid sql.NullString
	var maxAge sql.NullInt64
	if err := s.Scan(&id, &tid, &x.ClientID, &x.DeviceCodeHash, &x.UserCodeHash, &x.Scope, &acr, &maxAge, &x.Status, &ip, &ua,
		&x.Interval, &polled, &created, &expires, &approvedBy, &approvedCtx, &approvedAt, &sid); err != nil {
		return nil, err
	}
	var err error
	if x.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	x.RequiredTesseraACR, x.RequestIP, x.RequestUserAgent = strp(acr), strp(ip), strp(ua)
	if maxAge.Valid {
		m := int(maxAge.Int64)
		x.MaxAge = &m
	}
	for _, p := range []struct {
		dst **uuid.UUID
		src sql.NullString
	}{{&x.ApprovedByUserID, approvedBy}, {&x.ApprovedAuthnContextID, approvedCtx}, {&x.SessionID, sid}} {
		if p.src.Valid {
			u, err := uuid.Parse(p.src.String)
			if err != nil {
				return nil, err
			}
			*p.dst = &u
		}
	}
	if x.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if x.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	if x.LastPolledAt, err = rtp(polled); err != nil {
		return nil, err
	}
	x.ApprovedAt, err = rtp(approvedAt)
	return &x, err
}

// InsertDeviceGrant creates a pending grant. ErrDuplicate means the user
// code is already pending in this tenant (the caller picks a new one).
func (tx *TenantTx) InsertDeviceGrant(x *DeviceGrant) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	x.Status = DevicePending
	var maxAge any
	if x.MaxAge != nil {
		maxAge = *x.MaxAge
	}
	_, err := tx.exec(deviceInsert, sql.Named("id", x.ID.String()), sql.Named("client_id", x.ClientID),
		sql.Named("device_code_hash", x.DeviceCodeHash), sql.Named("user_code_hash", x.UserCodeHash),
		sql.Named("scope", x.Scope), sql.Named("required_tessera_acr", SP(x.RequiredTesseraACR)),
		sql.Named("max_age", maxAge), sql.Named("request_ip", SP(x.RequestIP)),
		sql.Named("request_user_agent", SP(x.RequestUserAgent)), sql.Named("poll_interval", x.Interval),
		sql.Named("created_at", RT(x.CreatedAt)), sql.Named("expires_at", RT(x.ExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// DeviceGrant returns one of this tenant's grants (ErrNotFound otherwise).
func (tx *TenantTx) DeviceGrant(id uuid.UUID) (*DeviceGrant, error) {
	return one(tx, scanDevice, deviceGet, sql.Named("id", id.String()))
}

// DeviceGrantByDeviceCodeHash returns the grant with this device-code hash.
func (tx *TenantTx) DeviceGrantByDeviceCodeHash(hash string) (*DeviceGrant, error) {
	return one(tx, scanDevice, deviceByDeviceCode, sql.Named("hash", hash))
}

// PendingDeviceGrantByUserCodeHash returns the unexpired pending grant with
// this user-code hash (ErrNotFound otherwise).
func (tx *TenantTx) PendingDeviceGrantByUserCodeHash(hash string, now time.Time) (*DeviceGrant, error) {
	return one(tx, scanDevice, devicePendingByUserCode, sql.Named("hash", hash), sql.Named("now", RT(now)))
}

// ExpireStaleDeviceGrants marks pending grants past their expiry expired
// (frees their user codes) and returns how many.
func (tx *TenantTx) ExpireStaleDeviceGrants(now time.Time) (int64, error) {
	res, err := tx.exec(deviceExpireStale, sql.Named("now", RT(now)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PollDeviceGrant records a poll and the (possibly raised) interval.
func (tx *TenantTx) PollDeviceGrant(id uuid.UUID, at time.Time, interval int) error {
	return tx.execOne(devicePoll, sql.Named("at", RT(at)), sql.Named("poll_interval", interval), sql.Named("id", id.String()))
}

// ApproveDeviceGrant approves a pending, unexpired grant for a user with the
// authentication context that approved it and the CLI session created for it
// (ErrNotFound if the grant is not pending or has expired).
func (tx *TenantTx) ApproveDeviceGrant(id, userID, ctxID, sessionID uuid.UUID, at time.Time) error {
	return tx.execOne(deviceApprove, sql.Named("user_id", userID.String()), sql.Named("ctx_id", ctxID.String()),
		sql.Named("session_id", sessionID.String()), sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// DenyDeviceGrant denies a pending, unexpired grant.
func (tx *TenantTx) DenyDeviceGrant(id, userID uuid.UUID, at time.Time) error {
	return tx.execOne(deviceDeny, sql.Named("user_id", userID.String()), sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// ExpireDeviceGrant marks a pending grant expired.
func (tx *TenantTx) ExpireDeviceGrant(id uuid.UUID) error {
	return tx.execOne(deviceExpire, sql.Named("id", id.String()))
}

// ConsumeDeviceGrant marks an approved, unexpired grant consumed: the device
// code can be exchanged once (ErrNotFound if it was already).
func (tx *TenantTx) ConsumeDeviceGrant(id uuid.UUID, at time.Time) error {
	return tx.execOne(deviceConsume, sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// ---------------------------------------------------------------- refresh_tokens

const refreshCols = `r.id, r.tenant_id, r.token_hash, r.family_id, r.parent_id, r.session_id, r.user_id, r.client_id, r.dpop_jkt,
	r.scope, r.issued_at, r.expires_at, r.absolute_expires_at, r.used_at, r.revoked_at, r.revoked_reason`

var (
	refreshInsert = tq("refresh_tokens.insert", `
		INSERT INTO refresh_tokens (id, tenant_id, token_hash, family_id, parent_id, session_id, user_id, client_id, dpop_jkt,
			scope, issued_at, expires_at, absolute_expires_at)
		VALUES (@id, @tenant, @token_hash, @family_id, @parent_id, @session_id, @user_id, @client_id, @dpop_jkt,
			@scope, @issued_at, @expires_at, @absolute_expires_at)`)
	refreshByHash = tq("refresh_tokens.by_hash", `
		SELECT `+refreshCols+` FROM refresh_tokens r WHERE r.tenant_id = @tenant AND r.token_hash = @hash`)
	refreshByFamily = tq("refresh_tokens.by_family", `
		SELECT `+refreshCols+` FROM refresh_tokens r WHERE r.tenant_id = @tenant AND r.family_id = @family_id
		ORDER BY r.issued_at, r.rowid`)
	// rotation: only a token that is neither used nor revoked can be used
	refreshUse = tq("refresh_tokens.use", `
		UPDATE refresh_tokens SET used_at = @at
		WHERE tenant_id = @tenant AND id = @id AND used_at IS NULL AND revoked_at IS NULL`)
	refreshRevokeFamily = tq("refresh_tokens.revoke_family", `
		UPDATE refresh_tokens SET revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND family_id = @family_id AND revoked_at IS NULL`)
	refreshRevokeSession = tq("refresh_tokens.revoke_session", `
		UPDATE refresh_tokens SET revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND session_id = @session_id AND revoked_at IS NULL`)
	refreshRevokeUser = tq("refresh_tokens.revoke_user", `
		UPDATE refresh_tokens SET revoked_at = @at, revoked_reason = @reason
		WHERE refresh_tokens.tenant_id = @tenant AND refresh_tokens.user_id = @user_id AND refresh_tokens.revoked_at IS NULL`)
	refreshRevokeIdentity = tq("refresh_tokens.revoke_identity", `
		UPDATE refresh_tokens SET revoked_at = @at, revoked_reason = @reason
		WHERE refresh_tokens.tenant_id = @tenant AND refresh_tokens.revoked_at IS NULL AND refresh_tokens.user_id IN (
			SELECT u.id FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = @id)`)
)

func scanRefresh(s scanner) (*RefreshToken, error) {
	var x RefreshToken
	var id, tid, family, sid, uid, issued, expires, abs string
	var parent, used, revoked, reason sql.NullString
	if err := s.Scan(&id, &tid, &x.TokenHash, &family, &parent, &sid, &uid, &x.ClientID, &x.DPoPJKT, &x.Scope, &issued,
		&expires, &abs, &used, &revoked, &reason); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst *uuid.UUID
		src string
	}{{&x.ID, id}, {&x.FamilyID, family}, {&x.SessionID, sid}, {&x.UserID, uid}} {
		if *p.dst, err = uuid.Parse(p.src); err != nil {
			return nil, err
		}
	}
	if parent.Valid {
		u, err := uuid.Parse(parent.String)
		if err != nil {
			return nil, err
		}
		x.ParentID = &u
	}
	for _, p := range []struct {
		dst *time.Time
		src string
	}{{&x.IssuedAt, issued}, {&x.ExpiresAt, expires}, {&x.AbsoluteExpiresAt, abs}} {
		if *p.dst, err = ParseRT(p.src); err != nil {
			return nil, err
		}
	}
	if x.UsedAt, err = rtp(used); err != nil {
		return nil, err
	}
	x.RevokedReason = strp(reason)
	x.RevokedAt, err = rtp(revoked)
	return &x, err
}

// InsertRefreshToken stores a refresh token (by hash).
func (tx *TenantTx) InsertRefreshToken(x *RefreshToken) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	_, err := tx.exec(refreshInsert, sql.Named("id", x.ID.String()), sql.Named("token_hash", x.TokenHash),
		sql.Named("family_id", x.FamilyID.String()), sql.Named("parent_id", uuidOrNil(x.ParentID)),
		sql.Named("session_id", x.SessionID.String()), sql.Named("user_id", x.UserID.String()),
		sql.Named("client_id", x.ClientID), sql.Named("dpop_jkt", x.DPoPJKT), sql.Named("scope", x.Scope),
		sql.Named("issued_at", RT(x.IssuedAt)), sql.Named("expires_at", RT(x.ExpiresAt)),
		sql.Named("absolute_expires_at", RT(x.AbsoluteExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// RefreshTokenByHash returns this tenant's refresh token with the hash.
func (tx *TenantTx) RefreshTokenByHash(hash string) (*RefreshToken, error) {
	return one(tx, scanRefresh, refreshByHash, sql.Named("hash", hash))
}

// RefreshTokensByFamily lists a family's tokens, oldest first.
func (tx *TenantTx) RefreshTokensByFamily(family uuid.UUID) ([]*RefreshToken, error) {
	return collect(tx, scanRefresh, refreshByFamily, sql.Named("family_id", family.String()))
}

// UseRefreshToken marks a token used (rotated). ErrNotFound if it was
// already used or revoked: the caller treats that as reuse.
func (tx *TenantTx) UseRefreshToken(id uuid.UUID, at time.Time) error {
	return tx.execOne(refreshUse, sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// RevokeRefreshFamily revokes every unrevoked token of a family and returns
// how many.
func (tx *TenantTx) RevokeRefreshFamily(family uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(refreshRevokeFamily, sql.Named("at", RT(at)), sql.Named("reason", reason),
		sql.Named("family_id", family.String()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeSessionRefreshTokens revokes every unrevoked refresh token of a
// session and returns how many.
func (tx *TenantTx) RevokeSessionRefreshTokens(sessionID uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(refreshRevokeSession, sql.Named("at", RT(at)), sql.Named("reason", reason),
		sql.Named("session_id", sessionID.String()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeUserRefreshTokens revokes every unrevoked CLI refresh token of a user
// and returns how many (#345).
func (tx *TenantTx) RevokeUserRefreshTokens(userID uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(refreshRevokeUser, sql.Named("at", RT(at)), sql.Named("reason", reason),
		sql.Named("user_id", userID.String()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
