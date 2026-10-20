package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The auth core's repositories (design §7.4, schema/0005_auth.sql). Every
// statement is tenant-scoped (tq) and linted like the rest of the store,
// except the two hash lookups on SystemTx (lq, §14.2), which return only the
// (tenant, id) pair needed to open the right tenant transaction.

// ErrSessionInactive is returned by the session updates when the session is
// not active any more (revoked or expired concurrently).
var ErrSessionInactive = errors.New("store: session is not active")

// ---------------------------------------------------------------- idp_connections

const idpCols = `c.id, c.tenant_id, c.name, c.protocol, c.profile, c.status, c.is_default, c.verified_domains,
	c.issuer, c.discovery_url, c.client_id, c.client_auth_method, c.client_secret_enc, c.client_signing_kid,
	c.scopes, c.id_token_algs, c.step_up_request, c.idp_entity_id, c.idp_sso_url, c.idp_signing_certs,
	c.authorization_endpoint, c.token_endpoint, c.userinfo_endpoint,
	c.metadata_url, c.pin_certs, c.sp_key_enc, c.sp_cert_pem, c.subject_source, c.attribute_map, c.authn_mapping,
	c.assume_phishing_resistant, c.groups_claim, c.group_role_mapping, c.jit_provisioning, c.default_role,
	c.created_at, c.updated_at, c.last_change_request_id`

var (
	idpInsert = tq("idp_connections.insert", `
		INSERT INTO idp_connections (id, tenant_id, name, protocol, profile, status, is_default, verified_domains,
			issuer, discovery_url, client_id, client_auth_method, client_secret_enc, client_signing_kid, scopes,
			id_token_algs, step_up_request, idp_entity_id, idp_sso_url, idp_signing_certs, authorization_endpoint,
			token_endpoint, userinfo_endpoint, metadata_url, pin_certs,
			sp_key_enc, sp_cert_pem, subject_source, attribute_map, authn_mapping, assume_phishing_resistant,
			groups_claim, group_role_mapping, jit_provisioning, default_role, created_at, updated_at,
			last_change_request_id)
		VALUES (@id, @tenant, @name, @protocol, @profile, @status, @is_default, @verified_domains,
			@issuer, @discovery_url, @client_id, @client_auth_method, @client_secret_enc, @client_signing_kid, @scopes,
			@id_token_algs, @step_up_request, @idp_entity_id, @idp_sso_url, @idp_signing_certs, @authorization_endpoint,
			@token_endpoint, @userinfo_endpoint, @metadata_url, @pin_certs,
			@sp_key_enc, @sp_cert_pem, @subject_source, @attribute_map, @authn_mapping, @assume_phishing_resistant,
			@groups_claim, @group_role_mapping, @jit_provisioning, @default_role, @created_at, @updated_at,
			@last_change_request_id)`)
	idpGet = tq("idp_connections.get", `
		SELECT `+idpCols+` FROM idp_connections c WHERE c.tenant_id = @tenant AND c.id = @id`)
	idpList = tq("idp_connections.list", `
		SELECT `+idpCols+` FROM idp_connections c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.rowid`)
	idpCountProfile = tq("idp_connections.count_profile", `
		SELECT count(c.id) FROM idp_connections c WHERE c.tenant_id = @tenant AND c.profile = @profile`)
)

func jsonOr(r json.RawMessage, def string) string {
	if len(r) == 0 {
		return def
	}
	return string(r)
}

func scanIdP(s scanner) (*IdPConnection, error) {
	var c IdPConnection
	var id, tid, created, updated string
	var verified, scopes, algs, stepUp, certs, attrs, mapping, groupMap string
	var isDefault, pin, assume, jitProv int
	var issuer, disc, clientID, authMethod, kid, entity, sso, meta, spCert, groupsClaim, lastCR sql.NullString
	var authzEP, tokenEP, userinfoEP sql.NullString
	if err := s.Scan(&id, &tid, &c.Name, &c.Protocol, &c.Profile, &c.Status, &isDefault, &verified,
		&issuer, &disc, &clientID, &authMethod, &c.ClientSecretEnc, &kid,
		&scopes, &algs, &stepUp, &entity, &sso, &certs,
		&authzEP, &tokenEP, &userinfoEP,
		&meta, &pin, &c.SPKeyEnc, &spCert, &c.SubjectSource, &attrs, &mapping,
		&assume, &groupsClaim, &groupMap, &jitProv, &c.DefaultRole,
		&created, &updated, &lastCR); err != nil {
		return nil, err
	}
	var err error
	if c.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	c.IsDefault, c.PinCerts, c.AssumePhishingResistant, c.JITProvisioning = isDefault == 1, pin == 1, assume == 1, jitProv == 1
	c.VerifiedDomains, c.Scopes, c.IDTokenAlgs = json.RawMessage(verified), json.RawMessage(scopes), json.RawMessage(algs)
	c.StepUpRequest, c.IdPSigningCerts = json.RawMessage(stepUp), json.RawMessage(certs)
	c.AttributeMap, c.AuthnMapping, c.GroupRoleMapping = json.RawMessage(attrs), json.RawMessage(mapping), json.RawMessage(groupMap)
	c.Issuer, c.DiscoveryURL, c.ClientID, c.ClientAuthMethod = strp(issuer), strp(disc), strp(clientID), strp(authMethod)
	c.ClientSigningKID, c.IdPEntityID, c.IdPSSOURL, c.MetadataURL = strp(kid), strp(entity), strp(sso), strp(meta)
	c.SPCertPEM, c.GroupsClaim, c.LastChangeRequestID = strp(spCert), strp(groupsClaim), strp(lastCR)
	c.AuthorizationEndpoint, c.TokenEndpoint, c.UserinfoEndpoint = strp(authzEP), strp(tokenEP), strp(userinfoEP)
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = ParseRT(updated)
	return &c, err
}

// InsertIdPConnection adds an IdP connection (a zero ID gets a fresh one).
// ErrDuplicate when the tenant already has a connection with that name.
func (tx *TenantTx) InsertIdPConnection(c *IdPConnection) error {
	if err := tx.own(c.TenantID); err != nil {
		return err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.SubjectSource == "" {
		c.SubjectSource = "nameid_persistent"
	}
	if c.DefaultRole == "" {
		c.DefaultRole = RoleViewer
	}
	if c.Status == "" {
		c.Status = "pending"
	}
	_, err := tx.exec(idpInsert, sql.Named("id", c.ID.String()), sql.Named("name", c.Name),
		sql.Named("protocol", c.Protocol), sql.Named("profile", c.Profile), sql.Named("status", c.Status),
		sql.Named("is_default", B(c.IsDefault)), sql.Named("verified_domains", jsonOr(c.VerifiedDomains, "[]")),
		sql.Named("issuer", SP(c.Issuer)), sql.Named("discovery_url", SP(c.DiscoveryURL)),
		sql.Named("client_id", SP(c.ClientID)), sql.Named("client_auth_method", SP(c.ClientAuthMethod)),
		sql.Named("client_secret_enc", c.ClientSecretEnc), sql.Named("client_signing_kid", SP(c.ClientSigningKID)),
		sql.Named("scopes", jsonOr(c.Scopes, `["openid","email","profile"]`)),
		sql.Named("id_token_algs", jsonOr(c.IDTokenAlgs, `["RS256","ES256","PS256"]`)),
		sql.Named("step_up_request", jsonOr(c.StepUpRequest, "{}")), sql.Named("idp_entity_id", SP(c.IdPEntityID)),
		sql.Named("idp_sso_url", SP(c.IdPSSOURL)), sql.Named("idp_signing_certs", jsonOr(c.IdPSigningCerts, "[]")),
		sql.Named("authorization_endpoint", SP(c.AuthorizationEndpoint)), sql.Named("token_endpoint", SP(c.TokenEndpoint)),
		sql.Named("userinfo_endpoint", SP(c.UserinfoEndpoint)),
		sql.Named("metadata_url", SP(c.MetadataURL)), sql.Named("pin_certs", B(c.PinCerts)),
		sql.Named("sp_key_enc", c.SPKeyEnc), sql.Named("sp_cert_pem", SP(c.SPCertPEM)),
		sql.Named("subject_source", c.SubjectSource), sql.Named("attribute_map", jsonOr(c.AttributeMap, "{}")),
		sql.Named("authn_mapping", jsonOr(c.AuthnMapping, "{}")),
		sql.Named("assume_phishing_resistant", B(c.AssumePhishingResistant)), sql.Named("groups_claim", SP(c.GroupsClaim)),
		sql.Named("group_role_mapping", jsonOr(c.GroupRoleMapping, "{}")), sql.Named("jit_provisioning", B(c.JITProvisioning)),
		sql.Named("default_role", c.DefaultRole), sql.Named("created_at", RT(c.CreatedAt)),
		sql.Named("updated_at", RT(c.UpdatedAt)), sql.Named("last_change_request_id", SP(c.LastChangeRequestID)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// IdPConnection returns one of this tenant's connections (ErrNotFound
// otherwise, including for another tenant's id).
func (tx *TenantTx) IdPConnection(id uuid.UUID) (*IdPConnection, error) {
	return one(tx, scanIdP, idpGet, sql.Named("id", id.String()))
}

// IdPConnections lists this tenant's connections in creation order.
func (tx *TenantTx) IdPConnections() ([]*IdPConnection, error) {
	return collect(tx, scanIdP, idpList)
}

// CountIdPConnectionsByProfile counts this tenant's connections with profile
// (the production guard rail refuses any dev_mock connection, §18.4).
func (tx *TenantTx) CountIdPConnectionsByProfile(profile string) (int, error) {
	return tx.count(idpCountProfile, sql.Named("profile", profile))
}

// ---------------------------------------------------------------- platform_users

const userCols = `u.id, u.tenant_id, u.email, u.display_name, u.status, u.is_break_glass, u.identity_id, u.created_at,
	u.last_login_at, u.disabled_at, u.disabled_reason`

var (
	usersInsert = tq("platform_users.insert", `
		INSERT INTO platform_users (id, tenant_id, email, display_name, status, is_break_glass, identity_id, created_at)
		VALUES (@id, @tenant, @email, @display_name, @status, @is_break_glass, @identity_id, @created_at)`)
	usersGet = tq("platform_users.get", `
		SELECT `+userCols+` FROM platform_users u WHERE u.tenant_id = @tenant AND u.id = @id`)
	usersList = tq("platform_users.list", `
		SELECT `+userCols+` FROM platform_users u WHERE u.tenant_id = @tenant ORDER BY u.created_at, u.rowid`)
	usersSetLastLogin = tq("platform_users.set_last_login", `
		UPDATE platform_users SET last_login_at = @at WHERE tenant_id = @tenant AND id = @id`)
	usersDisable = tq("platform_users.disable", `
		UPDATE platform_users SET status = 'disabled', disabled_at = @at, disabled_reason = @reason
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
)

func scanUser(s scanner) (*PlatformUser, error) {
	var u PlatformUser
	var id, tid, created string
	var email, reason, lastLogin, disabled sql.NullString
	var identity sql.NullInt64
	var bg int
	if err := s.Scan(&id, &tid, &email, &u.DisplayName, &u.Status, &bg, &identity, &created,
		&lastLogin, &disabled, &reason); err != nil {
		return nil, err
	}
	var err error
	if u.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if u.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	u.Email, u.DisabledReason, u.IdentityID, u.IsBreakGlass = strp(email), strp(reason), intp(identity), bg == 1
	if u.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if u.LastLoginAt, err = rtp(lastLogin); err != nil {
		return nil, err
	}
	u.DisabledAt, err = rtp(disabled)
	return &u, err
}

// InsertPlatformUser adds a user (a zero ID gets a fresh one; status
// defaults to active).
func (tx *TenantTx) InsertPlatformUser(u *PlatformUser) error {
	if err := tx.own(u.TenantID); err != nil {
		return err
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Status == "" {
		u.Status = "active"
	}
	_, err := tx.exec(usersInsert, sql.Named("id", u.ID.String()), sql.Named("email", SP(u.Email)),
		sql.Named("display_name", u.DisplayName), sql.Named("status", u.Status),
		sql.Named("is_break_glass", B(u.IsBreakGlass)), sql.Named("identity_id", IP(u.IdentityID)),
		sql.Named("created_at", RT(u.CreatedAt)))
	return err
}

// PlatformUser returns one of this tenant's users (ErrNotFound otherwise).
func (tx *TenantTx) PlatformUser(id uuid.UUID) (*PlatformUser, error) {
	return one(tx, scanUser, usersGet, sql.Named("id", id.String()))
}

// PlatformUsers lists this tenant's users in creation order.
func (tx *TenantTx) PlatformUsers() ([]*PlatformUser, error) { return collect(tx, scanUser, usersList) }

// SetUserLastLogin records a successful sign-in.
func (tx *TenantTx) SetUserLastLogin(id uuid.UUID, at time.Time) error {
	return tx.execOne(usersSetLastLogin, sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// DisableUser disables an active user (ErrNotFound if there is no such
// active user in this tenant). The caller revokes the user's sessions in the
// same transaction (RevokeUserSessions).
func (tx *TenantTx) DisableUser(id uuid.UUID, reason string, at time.Time) error {
	return tx.execOne(usersDisable, sql.Named("at", RT(at)), sql.Named("reason", reason), sql.Named("id", id.String()))
}

// execOne runs an UPDATE that must change exactly one row (ErrNotFound otherwise).
func (tx *TenantTx) execOne(s tstmt, args ...sql.NamedArg) error {
	res, err := tx.exec(s, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- external_logins

const loginCols = `l.id, l.tenant_id, l.user_id, l.idp_connection_id, l.issuer, l.subject, l.email_at_last_login,
	l.created_at, l.last_seen_at`

var (
	loginsInsert = tq("external_logins.insert", `
		INSERT INTO external_logins (id, tenant_id, user_id, idp_connection_id, issuer, subject, email_at_last_login,
			created_at, last_seen_at)
		VALUES (@id, @tenant, @user_id, @idp_connection_id, @issuer, @subject, @email_at_last_login,
			@created_at, @last_seen_at)`)
	loginsBySubject = tq("external_logins.by_subject", `
		SELECT `+loginCols+` FROM external_logins l
		WHERE l.tenant_id = @tenant AND l.idp_connection_id = @idp_connection_id AND l.subject = @subject`)
	loginsForUser = tq("external_logins.for_user", `
		SELECT `+loginCols+` FROM external_logins l WHERE l.tenant_id = @tenant AND l.user_id = @user_id
		ORDER BY l.created_at, l.rowid`)
)

func scanLogin(s scanner) (*ExternalLogin, error) {
	var l ExternalLogin
	var id, tid, uid, cid, created string
	var email, seen sql.NullString
	if err := s.Scan(&id, &tid, &uid, &cid, &l.Issuer, &l.Subject, &email, &created, &seen); err != nil {
		return nil, err
	}
	var err error
	if l.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if l.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if l.UserID, err = uuid.Parse(uid); err != nil {
		return nil, err
	}
	if l.IdPConnectionID, err = uuid.Parse(cid); err != nil {
		return nil, err
	}
	l.EmailAtLastLogin = strp(email)
	if l.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	l.LastSeenAt, err = rtp(seen)
	return &l, err
}

// InsertExternalLogin links (connection, subject) to a user. ErrDuplicate if
// the subject is already linked through that connection.
func (tx *TenantTx) InsertExternalLogin(l *ExternalLogin) error {
	if err := tx.own(l.TenantID); err != nil {
		return err
	}
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	_, err := tx.exec(loginsInsert, sql.Named("id", l.ID.String()), sql.Named("user_id", l.UserID.String()),
		sql.Named("idp_connection_id", l.IdPConnectionID.String()), sql.Named("issuer", l.Issuer),
		sql.Named("subject", l.Subject), sql.Named("email_at_last_login", SP(l.EmailAtLastLogin)),
		sql.Named("created_at", RT(l.CreatedAt)), sql.Named("last_seen_at", RTP(l.LastSeenAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// ExternalLoginBySubject resolves (connection, subject) in this tenant.
func (tx *TenantTx) ExternalLoginBySubject(connectionID uuid.UUID, subject string) (*ExternalLogin, error) {
	return one(tx, scanLogin, loginsBySubject, sql.Named("idp_connection_id", connectionID.String()),
		sql.Named("subject", subject))
}

// ExternalLoginsForUser lists a user's linked logins.
func (tx *TenantTx) ExternalLoginsForUser(userID uuid.UUID) ([]*ExternalLogin, error) {
	return collect(tx, scanLogin, loginsForUser, sql.Named("user_id", userID.String()))
}

// ---------------------------------------------------------------- role_assignments

const roleCols = `a.id, a.tenant_id, a.user_id, a.role, a.source, a.granted_by_user_id, a.change_request_id,
	a.created_at, a.expires_at`

var (
	rolesInsert = tq("role_assignments.insert", `
		INSERT INTO role_assignments (id, tenant_id, user_id, role, source, granted_by_user_id, change_request_id,
			created_at, expires_at)
		VALUES (@id, @tenant, @user_id, @role, @source, @granted_by_user_id, @change_request_id, @created_at, @expires_at)`)
	rolesForUser = tq("role_assignments.for_user", `
		SELECT `+roleCols+` FROM role_assignments a WHERE a.tenant_id = @tenant AND a.user_id = @user_id
		ORDER BY a.created_at, a.rowid`)
	rolesDelete = tq("role_assignments.delete", `
		DELETE FROM role_assignments WHERE tenant_id = @tenant AND id = @id`)
)

func scanRole(s scanner) (*RoleAssignment, error) {
	var a RoleAssignment
	var id, tid, uid, created string
	var grantedBy, cr, expires sql.NullString
	if err := s.Scan(&id, &tid, &uid, &a.Role, &a.Source, &grantedBy, &cr, &created, &expires); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if a.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if a.UserID, err = uuid.Parse(uid); err != nil {
		return nil, err
	}
	if grantedBy.Valid {
		g, err := uuid.Parse(grantedBy.String)
		if err != nil {
			return nil, err
		}
		a.GrantedByUserID = &g
	}
	a.ChangeRequestID = strp(cr)
	if a.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	a.ExpiresAt, err = rtp(expires)
	return &a, err
}

// InsertRoleAssignment grants a role. The schema refuses an admin role from
// an IdP group (E1) and an admin role without a change request unless its
// source is bootstrap. ErrDuplicate if the user already holds the role from
// that source.
func (tx *TenantTx) InsertRoleAssignment(a *RoleAssignment) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	var grantedBy any
	if a.GrantedByUserID != nil {
		grantedBy = a.GrantedByUserID.String()
	}
	_, err := tx.exec(rolesInsert, sql.Named("id", a.ID.String()), sql.Named("user_id", a.UserID.String()),
		sql.Named("role", a.Role), sql.Named("source", a.Source), sql.Named("granted_by_user_id", grantedBy),
		sql.Named("change_request_id", SP(a.ChangeRequestID)), sql.Named("created_at", RT(a.CreatedAt)),
		sql.Named("expires_at", RTP(a.ExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// RoleAssignments lists a user's role assignments (expired ones included;
// internal/auth filters by expiry).
func (tx *TenantTx) RoleAssignments(userID uuid.UUID) ([]*RoleAssignment, error) {
	return collect(tx, scanRole, rolesForUser, sql.Named("user_id", userID.String()))
}

// DeleteRoleAssignment removes one assignment (ErrNotFound if it is not this
// tenant's). The caller revokes the user's sessions (design §15.6).
func (tx *TenantTx) DeleteRoleAssignment(id uuid.UUID) error {
	return tx.execOne(rolesDelete, sql.Named("id", id.String()))
}

// ---------------------------------------------------------------- authn_contexts

const ctxCols = `x.id, x.tenant_id, x.user_id, x.idp_connection_id, x.protocol, x.purpose, x.acr, x.amr, x.methods,
	x.aal, x.phishing_resistant, x.phr_basis, x.tessera_acr, x.auth_time, x.idp_session_id, x.ip, x.user_agent,
	x.mapping_profile, x.mapping_version, x.claims_sha256, x.created_at`

var (
	ctxInsert = tq("authn_contexts.insert", `
		INSERT INTO authn_contexts (id, tenant_id, user_id, idp_connection_id, protocol, purpose, acr, amr, methods,
			aal, phishing_resistant, phr_basis, tessera_acr, auth_time, idp_session_id, ip, user_agent,
			mapping_profile, mapping_version, claims_sha256, created_at)
		VALUES (@id, @tenant, @user_id, @idp_connection_id, @protocol, @purpose, @acr, @amr, @methods,
			@aal, @phishing_resistant, @phr_basis, @tessera_acr, @auth_time, @idp_session_id, @ip, @user_agent,
			@mapping_profile, @mapping_version, @claims_sha256, @created_at)`)
	ctxGet = tq("authn_contexts.get", `
		SELECT `+ctxCols+` FROM authn_contexts x WHERE x.tenant_id = @tenant AND x.id = @id`)
)

func scanCtx(s scanner) (*AuthnContextRecord, error) {
	var x AuthnContextRecord
	var id, tid, uid, amr, methods, authTime, created string
	var conn, acr, sid, ip, ua sql.NullString
	var phr int
	if err := s.Scan(&id, &tid, &uid, &conn, &x.Protocol, &x.Purpose, &acr, &amr, &methods,
		&x.AAL, &phr, &x.PhrBasis, &x.TesseraACR, &authTime, &sid, &ip, &ua,
		&x.MappingProfile, &x.MappingVersion, &x.ClaimsSHA256, &created); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if x.UserID, err = uuid.Parse(uid); err != nil {
		return nil, err
	}
	if conn.Valid {
		c, err := uuid.Parse(conn.String)
		if err != nil {
			return nil, err
		}
		x.IdPConnectionID = &c
	}
	if err := json.Unmarshal([]byte(amr), &x.AMR); err != nil {
		return nil, fmt.Errorf("store: authn_contexts.amr: %w", err)
	}
	if err := json.Unmarshal([]byte(methods), &x.Methods); err != nil {
		return nil, fmt.Errorf("store: authn_contexts.methods: %w", err)
	}
	x.ACR, x.IdPSessionID, x.IP, x.UserAgent, x.PhishingResistant = strp(acr), strp(sid), strp(ip), strp(ua), phr == 1
	if x.AuthTime, err = ParseRT(authTime); err != nil {
		return nil, err
	}
	x.CreatedAt, err = ParseRT(created)
	return &x, err
}

func jsonList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// InsertAuthnContext records an authentication. Records are immutable.
func (tx *TenantTx) InsertAuthnContext(x *AuthnContextRecord) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	amr, err := jsonList(x.AMR)
	if err != nil {
		return err
	}
	methods, err := jsonList(x.Methods)
	if err != nil {
		return err
	}
	var conn any
	if x.IdPConnectionID != nil {
		conn = x.IdPConnectionID.String()
	}
	_, err = tx.exec(ctxInsert, sql.Named("id", x.ID.String()), sql.Named("user_id", x.UserID.String()),
		sql.Named("idp_connection_id", conn), sql.Named("protocol", x.Protocol), sql.Named("purpose", x.Purpose),
		sql.Named("acr", SP(x.ACR)), sql.Named("amr", amr), sql.Named("methods", methods), sql.Named("aal", x.AAL),
		sql.Named("phishing_resistant", B(x.PhishingResistant)), sql.Named("phr_basis", x.PhrBasis),
		sql.Named("tessera_acr", x.TesseraACR), sql.Named("auth_time", RT(x.AuthTime)),
		sql.Named("idp_session_id", SP(x.IdPSessionID)), sql.Named("ip", SP(x.IP)), sql.Named("user_agent", SP(x.UserAgent)),
		sql.Named("mapping_profile", x.MappingProfile), sql.Named("mapping_version", x.MappingVersion),
		sql.Named("claims_sha256", x.ClaimsSHA256), sql.Named("created_at", RT(x.CreatedAt)))
	return crossTenant(err)
}

// AuthnContext returns one of this tenant's authentication records.
func (tx *TenantTx) AuthnContext(id uuid.UUID) (*AuthnContextRecord, error) {
	return one(tx, scanCtx, ctxGet, sql.Named("id", id.String()))
}

// ---------------------------------------------------------------- sessions

const sessionCols = `s.id, s.tenant_id, s.user_id, s.kind, s.secret_hash, s.csrf_secret, s.initial_authn_context_id,
	s.current_authn_context_id, s.client_id, s.created_at, s.last_activity_at, s.idle_expires_at,
	s.absolute_expires_at, s.status, s.revoked_at, s.revoked_reason, s.ip_first, s.user_agent_first`

var (
	sessionsInsert = tq("sessions.insert", `
		INSERT INTO sessions (id, tenant_id, user_id, kind, secret_hash, csrf_secret, initial_authn_context_id,
			current_authn_context_id, client_id, created_at, last_activity_at, idle_expires_at, absolute_expires_at,
			status, ip_first, user_agent_first)
		VALUES (@id, @tenant, @user_id, @kind, @secret_hash, @csrf_secret, @initial_authn_context_id,
			@current_authn_context_id, @client_id, @created_at, @last_activity_at, @idle_expires_at, @absolute_expires_at,
			'active', @ip_first, @user_agent_first)`)
	sessionsGet = tq("sessions.get", `
		SELECT `+sessionCols+` FROM sessions s WHERE s.tenant_id = @tenant AND s.id = @id`)
	sessionsForUser = tq("sessions.for_user", `
		SELECT `+sessionCols+` FROM sessions s WHERE s.tenant_id = @tenant AND s.user_id = @user_id
		ORDER BY s.created_at DESC, s.rowid`)
	sessionsTouch = tq("sessions.touch", `
		UPDATE sessions SET last_activity_at = @at, idle_expires_at = @idle_expires_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	sessionsRotate = tq("sessions.rotate", `
		UPDATE sessions SET secret_hash = @secret_hash, csrf_secret = @csrf_secret, last_activity_at = @at,
			idle_expires_at = @idle_expires_at, current_authn_context_id = @current_authn_context_id
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	sessionsRevoke = tq("sessions.revoke", `
		UPDATE sessions SET status = 'revoked', revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	sessionsRevokeUser = tq("sessions.revoke_user", `
		UPDATE sessions SET status = 'revoked', revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND user_id = @user_id AND status = 'active'`)
	sessionsExpire = tq("sessions.expire", `
		UPDATE sessions SET status = 'expired'
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	// the one read of a tenant table before the tenant is known (§14.2)
	sessionsLookup = lq("sessions.lookup_by_secret_hash", `
		SELECT s.tenant_id, s.id FROM sessions s WHERE s.secret_hash = @hash`)
)

func scanSession(s scanner) (*Session, error) {
	var x Session
	var id, tid, uid, initial, current, created, last, idle, abs string
	var hash, csrf, client, revokedAt, reason, ip, ua sql.NullString
	if err := s.Scan(&id, &tid, &uid, &x.Kind, &hash, &csrf, &initial, &current, &client, &created, &last, &idle, &abs,
		&x.Status, &revokedAt, &reason, &ip, &ua); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst *uuid.UUID
		src string
	}{{&x.ID, id}, {&x.UserID, uid}, {&x.InitialAuthnContextID, initial}, {&x.CurrentAuthnContextID, current}} {
		if *p.dst, err = uuid.Parse(p.src); err != nil {
			return nil, err
		}
	}
	x.SecretHash, x.CSRFSecret, x.ClientID = strp(hash), strp(csrf), strp(client)
	x.RevokedReason, x.IPFirst, x.UserAgentFirst = strp(reason), strp(ip), strp(ua)
	for _, p := range []struct {
		dst *time.Time
		src string
	}{{&x.CreatedAt, created}, {&x.LastActivityAt, last}, {&x.IdleExpiresAt, idle}, {&x.AbsoluteExpiresAt, abs}} {
		if *p.dst, err = ParseRT(p.src); err != nil {
			return nil, err
		}
	}
	x.RevokedAt, err = rtp(revokedAt)
	return &x, err
}

// InsertSession creates an active session (a zero ID gets a fresh one).
func (tx *TenantTx) InsertSession(x *Session) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	x.Status = SessionActive
	_, err := tx.exec(sessionsInsert, sql.Named("id", x.ID.String()), sql.Named("user_id", x.UserID.String()),
		sql.Named("kind", x.Kind), sql.Named("secret_hash", SP(x.SecretHash)), sql.Named("csrf_secret", SP(x.CSRFSecret)),
		sql.Named("initial_authn_context_id", x.InitialAuthnContextID.String()),
		sql.Named("current_authn_context_id", x.CurrentAuthnContextID.String()), sql.Named("client_id", SP(x.ClientID)),
		sql.Named("created_at", RT(x.CreatedAt)), sql.Named("last_activity_at", RT(x.LastActivityAt)),
		sql.Named("idle_expires_at", RT(x.IdleExpiresAt)), sql.Named("absolute_expires_at", RT(x.AbsoluteExpiresAt)),
		sql.Named("ip_first", SP(x.IPFirst)), sql.Named("user_agent_first", SP(x.UserAgentFirst)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// Session returns one of this tenant's sessions (ErrNotFound otherwise).
func (tx *TenantTx) Session(id uuid.UUID) (*Session, error) {
	return one(tx, scanSession, sessionsGet, sql.Named("id", id.String()))
}

// SessionsForUser lists a user's sessions, newest first, every status.
func (tx *TenantTx) SessionsForUser(userID uuid.UUID) ([]*Session, error) {
	return collect(tx, scanSession, sessionsForUser, sql.Named("user_id", userID.String()))
}

// sessionUpdate runs a compare-and-set on an active session.
func (tx *TenantTx) sessionUpdate(s tstmt, args ...sql.NamedArg) error {
	err := tx.execOne(s, args...)
	if errors.Is(err, ErrNotFound) {
		return ErrSessionInactive
	}
	return err
}

// TouchSession records activity on an active session and moves its idle
// expiry (ErrSessionInactive if it is no longer active).
func (tx *TenantTx) TouchSession(id uuid.UUID, at, idleExpires time.Time) error {
	return tx.sessionUpdate(sessionsTouch, sql.Named("at", RT(at)), sql.Named("idle_expires_at", RT(idleExpires)),
		sql.Named("id", id.String()))
}

// RotateSession replaces an active session's secret hash and CSRF secret in
// the same row (the sid stays, for audit continuity) and sets its current
// authentication context.
func (tx *TenantTx) RotateSession(id uuid.UUID, secretHash, csrfSecret string, ctxID uuid.UUID, at, idleExpires time.Time) error {
	return tx.sessionUpdate(sessionsRotate, sql.Named("secret_hash", secretHash), sql.Named("csrf_secret", csrfSecret),
		sql.Named("at", RT(at)), sql.Named("idle_expires_at", RT(idleExpires)),
		sql.Named("current_authn_context_id", ctxID.String()), sql.Named("id", id.String()))
}

// RevokeSession revokes an active session (ErrSessionInactive if it is not).
func (tx *TenantTx) RevokeSession(id uuid.UUID, reason string, at time.Time) error {
	return tx.sessionUpdate(sessionsRevoke, sql.Named("at", RT(at)), sql.Named("reason", reason),
		sql.Named("id", id.String()))
}

// RevokeUserSessions revokes every active session of a user, and the user's
// CLI refresh tokens with them (#345), and returns how many sessions.
func (tx *TenantTx) RevokeUserSessions(userID uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(sessionsRevokeUser, sql.Named("at", RT(at)), sql.Named("reason", reason),
		sql.Named("user_id", userID.String()))
	if err != nil {
		return 0, err
	}
	if _, err := tx.RevokeUserRefreshTokens(userID, reason, at); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ExpireSession marks an active session expired (idle or absolute timeout).
func (tx *TenantTx) ExpireSession(id uuid.UUID) error {
	return tx.sessionUpdate(sessionsExpire, sql.Named("id", id.String()))
}

// LookupSessionBySecretHash resolves a session cookie's hash to its tenant
// and session id (ErrNotFound if no session has that hash). It is one of the
// two reads of a tenant table outside a TenantTx (design §14.2): the caller
// then loads the row with InTenant/ReadTenant, which re-applies the tenant.
func (s *SystemTx) LookupSessionBySecretHash(hash string) (tenancy.ID, uuid.UUID, error) {
	return s.lookup(sessionsLookup, "session_hash", hash)
}

// lookup runs one of the two hash lookups. On Postgres it first sets
// app.lookup (transaction-local) to the lookup's name, which is what the
// narrow SELECT policy lookup_by_hash of rls.sql keys on.
func (s *SystemTx) lookup(st lstmt, setting, hash string) (tenancy.ID, uuid.UUID, error) {
	if len(hash) != 64 {
		return tenancy.ID{}, uuid.Nil, ErrNotFound
	}
	if s.tx.d == dialectPostgres {
		if _, err := s.tx.tx.ExecContext(s.ctx, pgSetLookup, setting); err != nil {
			return tenancy.ID{}, uuid.Nil, fmt.Errorf("store: set lookup: %w", err)
		}
	}
	var tid, id string
	err := s.db.queryRowIn(s.ctx, s.tx, st.sql, []any{sql.Named("hash", hash)}).Scan(&tid, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return tenancy.ID{}, uuid.Nil, ErrNotFound
	}
	if err != nil {
		return tenancy.ID{}, uuid.Nil, err
	}
	t, err := tenancy.Parse(tid)
	if err != nil {
		return tenancy.ID{}, uuid.Nil, err
	}
	u, err := uuid.Parse(id)
	return t, u, err
}

// ---------------------------------------------------------------- login_transactions

const txnCols = `t.id, t.tenant_id, t.cookie_hash, t.idp_connection_id, t.purpose, t.state_hash, t.nonce,
	t.pkce_verifier_enc, t.saml_request_id, t.required_tessera_acr, t.max_age, t.session_id,
	t.expected_external_login_id, t.bootstrap_invitation_id, t.return_to, t.created_at, t.expires_at, t.consumed_at`

var (
	txnInsert = tq("login_transactions.insert", `
		INSERT INTO login_transactions (id, tenant_id, cookie_hash, idp_connection_id, purpose, state_hash, nonce,
			pkce_verifier_enc, saml_request_id, required_tessera_acr, max_age, session_id, expected_external_login_id,
			bootstrap_invitation_id, return_to, created_at, expires_at)
		VALUES (@id, @tenant, @cookie_hash, @idp_connection_id, @purpose, @state_hash, @nonce,
			@pkce_verifier_enc, @saml_request_id, @required_tessera_acr, @max_age, @session_id, @expected_external_login_id,
			@bootstrap_invitation_id, @return_to, @created_at, @expires_at)`)
	txnGet = tq("login_transactions.get", `
		SELECT `+txnCols+` FROM login_transactions t WHERE t.tenant_id = @tenant AND t.id = @id`)
	// single use: only an unconsumed, unexpired transaction can be consumed
	txnConsume = tq("login_transactions.consume", `
		UPDATE login_transactions SET consumed_at = @at
		WHERE tenant_id = @tenant AND id = @id AND consumed_at IS NULL AND expires_at > @at`)
	txnLookup = lq("login_transactions.lookup_by_cookie_hash", `
		SELECT t.tenant_id, t.id FROM login_transactions t WHERE t.cookie_hash = @hash`)
)

func scanTxn(s scanner) (*LoginTransaction, error) {
	var x LoginTransaction
	var id, tid, conn, created, expires string
	var state, nonce, samlID, acr, sid, ext, inv, consumed sql.NullString
	var maxAge sql.NullInt64
	if err := s.Scan(&id, &tid, &x.CookieHash, &conn, &x.Purpose, &state, &nonce, &x.PKCEVerifierEnc, &samlID, &acr,
		&maxAge, &sid, &ext, &inv, &x.ReturnTo, &created, &expires, &consumed); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if x.IdPConnectionID, err = uuid.Parse(conn); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		dst **uuid.UUID
		src sql.NullString
	}{{&x.SessionID, sid}, {&x.ExpectedExternalLoginID, ext}, {&x.BootstrapInvitationID, inv}} {
		if p.src.Valid {
			u, err := uuid.Parse(p.src.String)
			if err != nil {
				return nil, err
			}
			*p.dst = &u
		}
	}
	x.StateHash, x.Nonce, x.SAMLRequestID, x.RequiredTesseraACR, x.MaxAge = strp(state), strp(nonce), strp(samlID), strp(acr), intp(maxAge)
	if x.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if x.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	x.ConsumedAt, err = rtp(consumed)
	return &x, err
}

func uuidOrNil(u *uuid.UUID) any {
	if u == nil {
		return nil
	}
	return u.String()
}

// ErrInvalidReturnTo refuses a login transaction's return_to that is not a
// same-site path.
var ErrInvalidReturnTo = errors.New("store: return_to must be a same-site path")

// MaxReturnToLen bounds return_to (the schema checks the same).
const MaxReturnToLen = 2048

// ValidReturnTo reports whether p is a safe post-login redirect target: a
// path on this site. It starts with exactly one "/", holds no backslash
// (browsers treat "/\host" as "//host"), no control character (C0, DEL or
// C1, which browsers strip or reinterpret), is valid UTF-8 and parses as a
// URL reference with no scheme, host or user info. The schema enforces the
// first three in SQL as well.
func ValidReturnTo(p string) bool {
	if p == "" || len(p) > MaxReturnToLen || p[0] != '/' || strings.HasPrefix(p, "//") || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r == '\\' || r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil && !u.ForceQuery && strings.HasPrefix(u.Path, "/")
}

// InsertLoginTransaction stores a login transaction. ReturnTo must be a
// same-site path (ValidReturnTo; the schema refuses the rest too), else
// ErrInvalidReturnTo. Empty means "/".
func (tx *TenantTx) InsertLoginTransaction(x *LoginTransaction) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	if x.ID == uuid.Nil {
		x.ID = uuid.New()
	}
	if x.ReturnTo == "" {
		x.ReturnTo = "/"
	}
	if !ValidReturnTo(x.ReturnTo) {
		return ErrInvalidReturnTo
	}
	_, err := tx.exec(txnInsert, sql.Named("id", x.ID.String()), sql.Named("cookie_hash", x.CookieHash),
		sql.Named("idp_connection_id", x.IdPConnectionID.String()), sql.Named("purpose", x.Purpose),
		sql.Named("state_hash", SP(x.StateHash)), sql.Named("nonce", SP(x.Nonce)),
		sql.Named("pkce_verifier_enc", x.PKCEVerifierEnc), sql.Named("saml_request_id", SP(x.SAMLRequestID)),
		sql.Named("required_tessera_acr", SP(x.RequiredTesseraACR)), sql.Named("max_age", IP(x.MaxAge)),
		sql.Named("session_id", uuidOrNil(x.SessionID)),
		sql.Named("expected_external_login_id", uuidOrNil(x.ExpectedExternalLoginID)),
		sql.Named("bootstrap_invitation_id", uuidOrNil(x.BootstrapInvitationID)),
		sql.Named("return_to", x.ReturnTo), sql.Named("created_at", RT(x.CreatedAt)),
		sql.Named("expires_at", RT(x.ExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// LoginTransaction returns one of this tenant's login transactions.
func (tx *TenantTx) LoginTransaction(id uuid.UUID) (*LoginTransaction, error) {
	return one(tx, scanTxn, txnGet, sql.Named("id", id.String()))
}

// ConsumeLoginTransaction marks a transaction used. It succeeds once, and
// only before the transaction expires (ErrNotFound otherwise).
func (tx *TenantTx) ConsumeLoginTransaction(id uuid.UUID, at time.Time) error {
	return tx.execOne(txnConsume, sql.Named("at", RT(at)), sql.Named("id", id.String()))
}

// LookupLoginTxnByCookieHash resolves a login cookie's hash to its tenant and
// transaction id (the second §14.2 lookup).
func (s *SystemTx) LookupLoginTxnByCookieHash(hash string) (tenancy.ID, uuid.UUID, error) {
	return s.lookup(txnLookup, "login_cookie_hash", hash)
}
