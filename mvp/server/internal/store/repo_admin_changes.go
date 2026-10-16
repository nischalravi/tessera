package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Admin change requests, admin notifications and operator recoveries
// (schema/0008_admin_changes.sql, design §15). Every statement is
// tenant-scoped (tq) except the narrow own-tenant updates of the tenants row
// at the end, which are system statements bound to this transaction's own
// tenant and cannot name another.

// ErrAdminChangeState is returned by the admin-change transitions when the
// row is not in the state the transition needs (another request moved it
// first, or the guard in the statement refused it).
var ErrAdminChangeState = errors.New("store: admin change is not in the expected state")

// Admin change request statuses (design §15.2 state machine).
const (
	ChangePendingApproval = "pending_approval"
	ChangeCoolingOff      = "cooling_off"
	ChangeApplied         = "applied"
	ChangeRejected        = "rejected"
	ChangeCancelled       = "cancelled"
	ChangeExpired         = "expired"
	ChangeFailed          = "failed"
)

// AdminChange is one admin change request. Payload is the canonical JSON of
// the typed payload and PayloadHash its SHA-256 hex. SecretEnc is the sealed
// client secret of an idp_connection.create (cleared on every terminal
// transition) and is never serialized.
type AdminChange struct {
	ID                uuid.UUID
	TenantID          tenancy.ID
	Type              string
	Payload           json.RawMessage
	PayloadHash       string
	SecretEnc         []byte `json:"-"`
	TargetID          string
	Status            string
	TwoPerson         bool
	CoolingOffSeconds int64
	RequestedBy       uuid.UUID
	RequestedAt       time.Time
	ExpiresAt         time.Time
	ApprovedBy        *uuid.UUID
	ApprovedAt        *time.Time
	EffectiveAt       *time.Time
	DecidedBy         *uuid.UUID
	DecidedAt         *time.Time
	AppliedAt         *time.Time
	Failure           string
	TestLoginAt       *time.Time
}

const adminChangeCols = `r.id, r.tenant_id, r.type, r.payload, r.payload_hash, r.secret_enc, r.target_id, r.status,
	r.two_person, r.cooling_off_seconds, r.requested_by_user_id, r.requested_at, r.expires_at, r.approved_by_user_id,
	r.approved_at, r.effective_at, r.decided_by_user_id, r.decided_at, r.applied_at, r.failure, r.test_login_at`

var (
	adminChangeInsert = tq("admin_change_requests.insert", `
		INSERT INTO admin_change_requests (id, tenant_id, type, payload, payload_hash, secret_enc, target_id, status,
			two_person, cooling_off_seconds, requested_by_user_id, requested_at, expires_at, approved_by_user_id,
			approved_at, effective_at)
		VALUES (@id, @tenant, @type, @payload, @payload_hash, @secret_enc, @target_id, @status, @two_person,
			@cooling_off_seconds, @requested_by_user_id, @requested_at, @expires_at, NULL, NULL, @effective_at)`)
	adminChangeGet = tq("admin_change_requests.get", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r WHERE r.tenant_id = @tenant AND r.id = @id`)
	adminChangeList = tq("admin_change_requests.list", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r WHERE r.tenant_id = @tenant
		ORDER BY r.requested_at DESC, r.rowid DESC LIMIT 200`)
	adminChangeOpen = tq("admin_change_requests.open", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r
		WHERE r.tenant_id = @tenant AND r.status IN ('pending_approval','cooling_off')
		ORDER BY r.requested_at, r.rowid`)
	adminChangeDue = tq("admin_change_requests.due", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r
		WHERE r.tenant_id = @tenant AND r.status = 'cooling_off' AND r.effective_at <= @now
		ORDER BY r.effective_at, r.rowid LIMIT 100`)
	adminChangeExpirable = tq("admin_change_requests.expirable", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r
		WHERE r.tenant_id = @tenant AND r.status = 'pending_approval' AND r.expires_at <= @now
		ORDER BY r.expires_at, r.rowid LIMIT 100`)
	adminChangeCreateFor = tq("admin_change_requests.create_for_connection", `
		SELECT `+adminChangeCols+` FROM admin_change_requests r
		WHERE r.tenant_id = @tenant AND r.type = 'idp_connection.create' AND r.target_id = @target
			AND r.status = 'applied' ORDER BY r.requested_at DESC, r.rowid DESC LIMIT 1`)
	// the approver is not the requester and the request has not expired: both
	// are checked in Go for a precise error and again here against a race
	adminChangeApprove = tq("admin_change_requests.approve", `
		UPDATE admin_change_requests SET status = 'cooling_off', approved_by_user_id = @by, approved_at = @at,
			effective_at = @effective_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending_approval' AND requested_by_user_id <> @by
			AND expires_at > @at`)
	adminChangeReject = tq("admin_change_requests.reject", `
		UPDATE admin_change_requests SET status = 'rejected', decided_by_user_id = @by, decided_at = @at, secret_enc = NULL
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending_approval'`)
	adminChangeCancel = tq("admin_change_requests.cancel", `
		UPDATE admin_change_requests SET status = 'cancelled', decided_by_user_id = @by, decided_at = @at, secret_enc = NULL
		WHERE tenant_id = @tenant AND id = @id AND status IN ('pending_approval','cooling_off')`)
	adminChangeExpire = tq("admin_change_requests.expire", `
		UPDATE admin_change_requests SET status = 'expired', secret_enc = NULL
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending_approval' AND expires_at <= @at`)
	adminChangeApplied = tq("admin_change_requests.applied", `
		UPDATE admin_change_requests SET status = 'applied', applied_at = @at, failure = NULL, secret_enc = NULL
		WHERE tenant_id = @tenant AND id = @id AND status = 'cooling_off' AND effective_at <= @at`)
	adminChangeFailed = tq("admin_change_requests.failed", `
		UPDATE admin_change_requests SET status = 'failed', failure = @failure, secret_enc = NULL
		WHERE tenant_id = @tenant AND id = @id AND status = 'cooling_off'`)
	adminChangeTestLogin = tq("admin_change_requests.test_login", `
		UPDATE admin_change_requests SET test_login_at = @at
		WHERE tenant_id = @tenant AND type = 'idp_connection.create' AND status = 'applied' AND target_id = @target
			AND requested_by_user_id = @user_id AND test_login_at IS NULL`)
)

func scanAdminChange(s scanner) (*AdminChange, error) {
	var c AdminChange
	var id, tid, payload, requestedBy, requestedAt, expiresAt string
	var secret []byte
	var target, approvedBy, approvedAt, effective, decidedBy, decidedAt, applied, failure, testLogin sql.NullString
	var two int
	if err := s.Scan(&id, &tid, &c.Type, &payload, &c.PayloadHash, &secret, &target, &c.Status, &two,
		&c.CoolingOffSeconds, &requestedBy, &requestedAt, &expiresAt, &approvedBy, &approvedAt, &effective, &decidedBy,
		&decidedAt, &applied, &failure, &testLogin); err != nil {
		return nil, err
	}
	var err error
	if c.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if c.RequestedBy, err = uuid.Parse(requestedBy); err != nil {
		return nil, err
	}
	c.Payload, c.SecretEnc, c.TwoPerson = json.RawMessage(payload), secret, two == 1
	c.TargetID, c.Failure = target.String, failure.String
	if c.RequestedAt, err = ParseRT(requestedAt); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = ParseRT(expiresAt); err != nil {
		return nil, err
	}
	if c.ApprovedBy, err = uuidp(approvedBy); err != nil {
		return nil, err
	}
	if c.DecidedBy, err = uuidp(decidedBy); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		in  sql.NullString
		out **time.Time
	}{{approvedAt, &c.ApprovedAt}, {effective, &c.EffectiveAt}, {decidedAt, &c.DecidedAt}, {applied, &c.AppliedAt},
		{testLogin, &c.TestLoginAt}} {
		if *f.out, err = rtp(f.in); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// InsertAdminChange stores a new request (a zero ID gets a fresh one). Status
// is pending_approval, or cooling_off for a change that needs no approver
// (EffectiveAt then says when it may be applied). The caller has validated
// the payload and computed its hash.
func (tx *TenantTx) InsertAdminChange(c *AdminChange) error {
	if err := tx.own(c.TenantID); err != nil {
		return err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	var secret any
	if len(c.SecretEnc) > 0 {
		secret = c.SecretEnc
	}
	var target any
	if c.TargetID != "" {
		target = c.TargetID
	}
	_, err := tx.exec(adminChangeInsert, sql.Named("id", c.ID.String()), sql.Named("type", c.Type),
		sql.Named("payload", string(c.Payload)), sql.Named("payload_hash", c.PayloadHash), sql.Named("secret_enc", secret),
		sql.Named("target_id", target), sql.Named("status", c.Status), sql.Named("two_person", B(c.TwoPerson)),
		sql.Named("cooling_off_seconds", c.CoolingOffSeconds), sql.Named("requested_by_user_id", c.RequestedBy.String()),
		sql.Named("requested_at", RT(c.RequestedAt)), sql.Named("expires_at", RT(c.ExpiresAt)),
		sql.Named("effective_at", RTP(c.EffectiveAt)))
	return crossTenant(err)
}

// AdminChange returns one of this tenant's requests (ErrNotFound otherwise,
// including for another tenant's id).
func (tx *TenantTx) AdminChange(id uuid.UUID) (*AdminChange, error) {
	return one(tx, scanAdminChange, adminChangeGet, sql.Named("id", id.String()))
}

// AdminChanges lists the tenant's most recent requests (at most 200), newest first.
func (tx *TenantTx) AdminChanges() ([]*AdminChange, error) {
	return collect(tx, scanAdminChange, adminChangeList)
}

// OpenAdminChanges lists the requests awaiting approval or cooling off, oldest first.
func (tx *TenantTx) OpenAdminChanges() ([]*AdminChange, error) {
	return collect(tx, scanAdminChange, adminChangeOpen)
}

// DueAdminChanges lists the cooling-off requests whose effective_at has
// passed at now (at most 100).
func (tx *TenantTx) DueAdminChanges(now time.Time) ([]*AdminChange, error) {
	return collect(tx, scanAdminChange, adminChangeDue, sql.Named("now", RT(now)))
}

// ExpirableAdminChanges lists the pending requests whose 72 h expired at now
// (at most 100).
func (tx *TenantTx) ExpirableAdminChanges(now time.Time) ([]*AdminChange, error) {
	return collect(tx, scanAdminChange, adminChangeExpirable, sql.Named("now", RT(now)))
}

// AppliedConnectionCreate returns the applied idp_connection.create request
// that created connection id (ErrNotFound if the connection was not created
// by one).
func (tx *TenantTx) AppliedConnectionCreate(connectionID uuid.UUID) (*AdminChange, error) {
	return one(tx, scanAdminChange, adminChangeCreateFor, sql.Named("target", connectionID.String()))
}

func (tx *TenantTx) adminTransition(s tstmt, args ...sql.NamedArg) error {
	res, err := tx.exec(s, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAdminChangeState
	}
	return nil
}

// ApproveAdminChange moves a pending request to cooling_off: by is not the
// requester and the request has not expired at, or ErrAdminChangeState.
func (tx *TenantTx) ApproveAdminChange(id, by uuid.UUID, at, effective time.Time) error {
	return tx.adminTransition(adminChangeApprove, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("at", RT(at)), sql.Named("effective_at", RT(effective)))
}

// RejectAdminChange rejects a pending request.
func (tx *TenantTx) RejectAdminChange(id, by uuid.UUID, at time.Time) error {
	return tx.adminTransition(adminChangeReject, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("at", RT(at)))
}

// CancelAdminChange cancels a pending or cooling-off request.
func (tx *TenantTx) CancelAdminChange(id, by uuid.UUID, at time.Time) error {
	return tx.adminTransition(adminChangeCancel, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("at", RT(at)))
}

// ExpireAdminChange expires a pending request whose expires_at has passed at at.
func (tx *TenantTx) ExpireAdminChange(id uuid.UUID, at time.Time) error {
	return tx.adminTransition(adminChangeExpire, sql.Named("id", id.String()), sql.Named("at", RT(at)))
}

// MarkAdminChangeApplied records that a cooling-off request was applied at
// at (effective_at must have passed).
func (tx *TenantTx) MarkAdminChangeApplied(id uuid.UUID, at time.Time) error {
	return tx.adminTransition(adminChangeApplied, sql.Named("id", id.String()), sql.Named("at", RT(at)))
}

// MarkAdminChangeFailed records that the applier of a cooling-off request failed.
func (tx *TenantTx) MarkAdminChangeFailed(id uuid.UUID, failure string) error {
	return tx.adminTransition(adminChangeFailed, sql.Named("id", id.String()), sql.Named("failure", failure))
}

// RecordConnectionTestLogin records the requester's successful test login on
// the applied idp_connection.create request of connection id (ErrNotFound if
// there is none for that user, or the login was already recorded).
func (tx *TenantTx) RecordConnectionTestLogin(connectionID, userID uuid.UUID, at time.Time) error {
	return tx.execOne(adminChangeTestLogin, sql.Named("target", connectionID.String()),
		sql.Named("user_id", userID.String()), sql.Named("at", RT(at)))
}

// ---------------------------------------------------------------- idp_connections (admin changes)

var (
	idpSetStatus = tq("idp_connections.set_status", `
		UPDATE idp_connections SET status = @to, updated_at = @at, last_change_request_id = @change
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)
	idpUpdateTrust = tq("idp_connections.update_trust", `
		UPDATE idp_connections SET issuer = @issuer, discovery_url = @discovery_url, client_id = @client_id,
			idp_entity_id = @idp_entity_id, idp_sso_url = @idp_sso_url, idp_signing_certs = @idp_signing_certs,
			metadata_url = @metadata_url, authorization_endpoint = @authorization_endpoint,
			token_endpoint = @token_endpoint, userinfo_endpoint = @userinfo_endpoint, subject_source = @subject_source,
			assume_phishing_resistant = @assume_phishing_resistant, authn_mapping = @authn_mapping,
			step_up_request = @step_up_request, group_role_mapping = @group_role_mapping, updated_at = @at,
			last_change_request_id = @change
		WHERE tenant_id = @tenant AND id = @id`)
	idpUpdateCosmetic = tq("idp_connections.update_cosmetic", `
		UPDATE idp_connections SET name = @name, verified_domains = @verified_domains, is_default = @is_default,
			updated_at = @at, last_change_request_id = @change
		WHERE tenant_id = @tenant AND id = @id`)
	idpClearDefault = tq("idp_connections.clear_default", `
		UPDATE idp_connections SET is_default = 0, updated_at = @at
		WHERE tenant_id = @tenant AND id <> @id AND is_default = 1`)
	sessionsRevokeConnection = tq("sessions.revoke_connection", `
		UPDATE sessions SET status = 'revoked', revoked_at = @at, revoked_reason = @reason
		WHERE sessions.tenant_id = @tenant AND sessions.status = 'active' AND EXISTS
			(SELECT 1 FROM authn_contexts a WHERE a.tenant_id = @tenant AND a.id = sessions.initial_authn_context_id
				AND a.idp_connection_id = @connection_id)`)
)

// SetIdPConnectionStatus moves a connection from one status to another
// (ErrNotFound if it is not this tenant's or not in status from), recording
// the change request that did it.
func (tx *TenantTx) SetIdPConnectionStatus(id uuid.UUID, from, to string, at time.Time, change *string) error {
	return tx.execOne(idpSetStatus, sql.Named("id", id.String()), sql.Named("from", from), sql.Named("to", to),
		sql.Named("at", RT(at)), sql.Named("change", SP(change)))
}

// UpdateIdPConnectionTrust writes the trust-bearing fields of c (§15.2
// idp_connection.update_trust): issuer, discovery, client id, SAML entity,
// SSO URL and signing certificates, metadata URL, OAuth 2.0 endpoints,
// subject source, phishing-resistance assumption, authentication mapping,
// step-up request and group-role mapping.
func (tx *TenantTx) UpdateIdPConnectionTrust(c *IdPConnection, at time.Time, change *string) error {
	return tx.execOne(idpUpdateTrust, sql.Named("id", c.ID.String()), sql.Named("issuer", SP(c.Issuer)),
		sql.Named("discovery_url", SP(c.DiscoveryURL)), sql.Named("client_id", SP(c.ClientID)),
		sql.Named("idp_entity_id", SP(c.IdPEntityID)), sql.Named("idp_sso_url", SP(c.IdPSSOURL)),
		sql.Named("idp_signing_certs", jsonOr(c.IdPSigningCerts, "[]")), sql.Named("metadata_url", SP(c.MetadataURL)),
		sql.Named("authorization_endpoint", SP(c.AuthorizationEndpoint)), sql.Named("token_endpoint", SP(c.TokenEndpoint)),
		sql.Named("userinfo_endpoint", SP(c.UserinfoEndpoint)), sql.Named("subject_source", c.SubjectSource),
		sql.Named("assume_phishing_resistant", B(c.AssumePhishingResistant)),
		sql.Named("authn_mapping", jsonOr(c.AuthnMapping, "{}")), sql.Named("step_up_request", jsonOr(c.StepUpRequest, "{}")),
		sql.Named("group_role_mapping", jsonOr(c.GroupRoleMapping, "{}")), sql.Named("at", RT(at)),
		sql.Named("change", SP(change)))
}

// UpdateIdPConnectionCosmetic writes the name, verified domains and default
// flag of c (§15.2 idp_connection.update_cosmetic). Making c the default
// clears the flag on the tenant's other connections. ErrDuplicate when the
// name is taken.
func (tx *TenantTx) UpdateIdPConnectionCosmetic(c *IdPConnection, at time.Time, change *string) error {
	err := tx.execOne(idpUpdateCosmetic, sql.Named("id", c.ID.String()), sql.Named("name", c.Name),
		sql.Named("verified_domains", jsonOr(c.VerifiedDomains, "[]")), sql.Named("is_default", B(c.IsDefault)),
		sql.Named("at", RT(at)), sql.Named("change", SP(change)))
	if isUnique(err) {
		return ErrDuplicate
	}
	if err != nil || !c.IsDefault {
		return err
	}
	_, err = tx.exec(idpClearDefault, sql.Named("id", c.ID.String()), sql.Named("at", RT(at)))
	return err
}

// RevokeConnectionSessions revokes every active session whose initial
// authentication context came through connection id (design §15.6) and
// returns how many.
func (tx *TenantTx) RevokeConnectionSessions(connectionID uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(sessionsRevokeConnection, sql.Named("connection_id", connectionID.String()),
		sql.Named("reason", reason), sql.Named("at", RT(at)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- platform users and roles (admin changes)

var (
	usersActiveAdmins = tq("platform_users.active_admins", `
		SELECT `+userCols+` FROM platform_users u
		WHERE u.tenant_id = @tenant AND u.status = 'active' AND EXISTS
			(SELECT 1 FROM role_assignments r WHERE r.tenant_id = @tenant AND r.user_id = u.id
				AND r.role = 'tenant_admin' AND (r.expires_at IS NULL OR r.expires_at > @now))
		ORDER BY u.created_at, u.rowid`)
	rolesAll = tq("role_assignments.all", `
		SELECT `+roleCols+` FROM role_assignments a WHERE a.tenant_id = @tenant ORDER BY a.created_at, a.rowid`)
)

// ActiveAdminUsers lists the active users holding an unexpired tenant_admin
// assignment at now (the admins the min_admins floor counts and the people
// admin notifications go to).
func (tx *TenantTx) ActiveAdminUsers(now time.Time) ([]*PlatformUser, error) {
	return collect(tx, scanUser, usersActiveAdmins, sql.Named("now", RT(now)))
}

// AllRoleAssignments lists every role assignment of the tenant.
func (tx *TenantTx) AllRoleAssignments() ([]*RoleAssignment, error) {
	return collect(tx, scanRole, rolesAll)
}

// ---------------------------------------------------------------- admin_notifications

// Admin notification recipient types.
const (
	NotifyAdmin    = "admin"
	NotifyContact  = "contact"
	NotifyOperator = "operator"
)

// AdminNotification is one queued admin notification (one per recipient).
type AdminNotification struct {
	ID               uuid.UUID
	TenantID         tenancy.ID
	ChangeRequestID  *uuid.UUID
	RecoveryID       *uuid.UUID
	Kind             string
	RecipientType    string
	RecipientUserID  *uuid.UUID
	RecipientAddress string
	Subject          string
	Body             string
	DedupeKey        string
	CreatedAt        time.Time
	DeliveredAt      *time.Time
}

const notifCols = `n.id, n.tenant_id, n.change_request_id, n.recovery_id, n.kind, n.recipient_type, n.recipient_user_id,
	n.recipient_address, n.subject, n.body, n.dedupe_key, n.created_at, n.delivered_at`

var (
	notifInsert = tq("admin_notifications.insert", `
		INSERT INTO admin_notifications (id, tenant_id, change_request_id, recovery_id, kind, recipient_type,
			recipient_user_id, recipient_address, subject, body, dedupe_key, created_at)
		VALUES (@id, @tenant, @change_request_id, @recovery_id, @kind, @recipient_type, @recipient_user_id,
			@recipient_address, @subject, @body, @dedupe_key, @created_at)
		ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`)
	notifList = tq("admin_notifications.list", `
		SELECT `+notifCols+` FROM admin_notifications n WHERE n.tenant_id = @tenant
		ORDER BY n.created_at DESC, n.rowid DESC LIMIT 200`)
	notifForChange = tq("admin_notifications.for_change", `
		SELECT `+notifCols+` FROM admin_notifications n WHERE n.tenant_id = @tenant AND n.change_request_id = @change
		ORDER BY n.created_at, n.rowid`)
	notifForRecovery = tq("admin_notifications.for_recovery", `
		SELECT `+notifCols+` FROM admin_notifications n WHERE n.tenant_id = @tenant AND n.recovery_id = @recovery
		ORDER BY n.created_at, n.rowid`)
)

func scanNotif(s scanner) (*AdminNotification, error) {
	var n AdminNotification
	var id, tid, created string
	var change, recovery, user, addr, delivered sql.NullString
	if err := s.Scan(&id, &tid, &change, &recovery, &n.Kind, &n.RecipientType, &user, &addr, &n.Subject, &n.Body,
		&n.DedupeKey, &created, &delivered); err != nil {
		return nil, err
	}
	var err error
	if n.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if n.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if n.ChangeRequestID, err = uuidp(change); err != nil {
		return nil, err
	}
	if n.RecoveryID, err = uuidp(recovery); err != nil {
		return nil, err
	}
	if n.RecipientUserID, err = uuidp(user); err != nil {
		return nil, err
	}
	n.RecipientAddress = addr.String
	if n.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	n.DeliveredAt, err = rtp(delivered)
	return &n, err
}

func uuidArg(u *uuid.UUID) any {
	if u == nil {
		return nil
	}
	return u.String()
}

// InsertAdminNotification queues a notification. A second one with the same
// DedupeKey is ignored (a retried transition never notifies twice) and
// reported as false.
func (tx *TenantTx) InsertAdminNotification(n *AdminNotification) (bool, error) {
	if err := tx.own(n.TenantID); err != nil {
		return false, err
	}
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}
	var addr any
	if n.RecipientAddress != "" {
		addr = n.RecipientAddress
	}
	res, err := tx.exec(notifInsert, sql.Named("id", n.ID.String()), sql.Named("change_request_id", uuidArg(n.ChangeRequestID)),
		sql.Named("recovery_id", uuidArg(n.RecoveryID)), sql.Named("kind", n.Kind),
		sql.Named("recipient_type", n.RecipientType), sql.Named("recipient_user_id", uuidArg(n.RecipientUserID)),
		sql.Named("recipient_address", addr), sql.Named("subject", n.Subject), sql.Named("body", n.Body),
		sql.Named("dedupe_key", n.DedupeKey), sql.Named("created_at", RT(n.CreatedAt)))
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows == 1, err
}

// AdminNotifications lists the tenant's most recent notifications (at most 200), newest first.
func (tx *TenantTx) AdminNotifications() ([]*AdminNotification, error) {
	return collect(tx, scanNotif, notifList)
}

// AdminNotificationsForChange lists the notifications of one change request.
func (tx *TenantTx) AdminNotificationsForChange(change uuid.UUID) ([]*AdminNotification, error) {
	return collect(tx, scanNotif, notifForChange, sql.Named("change", change.String()))
}

// AdminNotificationsForRecovery lists the notifications of one recovery.
func (tx *TenantTx) AdminNotificationsForRecovery(recovery uuid.UUID) ([]*AdminNotification, error) {
	return collect(tx, scanNotif, notifForRecovery, sql.Named("recovery", recovery.String()))
}

// ---------------------------------------------------------------- tenant_recoveries

// Recovery statuses.
const (
	RecoveryPending   = "pending"
	RecoveryCancelled = "cancelled"
	RecoveryCompleted = "completed"
)

// TenantRecovery is one operator-assisted recovery (design §15.5).
type TenantRecovery struct {
	ID           uuid.UUID
	TenantID     tenancy.ID
	InvitationID uuid.UUID
	Operator     string
	CoOperator   string
	Ticket       string
	Status       string
	NotBefore    time.Time
	CreatedAt    time.Time
	CancelledBy  *uuid.UUID
	CancelledAt  *time.Time
	CompletedBy  *uuid.UUID
	CompletedAt  *time.Time
}

const recoveryCols = `v.id, v.tenant_id, v.invitation_id, v.operator, v.co_operator, v.ticket, v.status, v.not_before,
	v.created_at, v.cancelled_by_user_id, v.cancelled_at, v.completed_by_user_id, v.completed_at`

var (
	recoveryInsert = tq("tenant_recoveries.insert", `
		INSERT INTO tenant_recoveries (id, tenant_id, invitation_id, operator, co_operator, ticket, status, not_before,
			created_at)
		VALUES (@id, @tenant, @invitation_id, @operator, @co_operator, @ticket, 'pending', @not_before, @created_at)`)
	recoveryGet = tq("tenant_recoveries.get", `
		SELECT `+recoveryCols+` FROM tenant_recoveries v WHERE v.tenant_id = @tenant AND v.id = @id`)
	recoveryByInvitation = tq("tenant_recoveries.by_invitation", `
		SELECT `+recoveryCols+` FROM tenant_recoveries v WHERE v.tenant_id = @tenant AND v.invitation_id = @invitation_id`)
	recoveryPending = tq("tenant_recoveries.pending", `
		SELECT `+recoveryCols+` FROM tenant_recoveries v WHERE v.tenant_id = @tenant AND v.status = 'pending'`)
	recoveryList = tq("tenant_recoveries.list", `
		SELECT `+recoveryCols+` FROM tenant_recoveries v WHERE v.tenant_id = @tenant
		ORDER BY v.created_at DESC, v.rowid DESC LIMIT 20`)
	recoveryCancel = tq("tenant_recoveries.cancel", `
		UPDATE tenant_recoveries SET status = 'cancelled', cancelled_by_user_id = @by, cancelled_at = @at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
	recoveryComplete = tq("tenant_recoveries.complete", `
		UPDATE tenant_recoveries SET status = 'completed', completed_by_user_id = @by, completed_at = @at
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
)

func scanRecovery(s scanner) (*TenantRecovery, error) {
	var r TenantRecovery
	var id, tid, inv, notBefore, created string
	var cancelledBy, cancelledAt, completedBy, completedAt sql.NullString
	if err := s.Scan(&id, &tid, &inv, &r.Operator, &r.CoOperator, &r.Ticket, &r.Status, &notBefore, &created,
		&cancelledBy, &cancelledAt, &completedBy, &completedAt); err != nil {
		return nil, err
	}
	var err error
	if r.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if r.InvitationID, err = uuid.Parse(inv); err != nil {
		return nil, err
	}
	if r.NotBefore, err = ParseRT(notBefore); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if r.CancelledBy, err = uuidp(cancelledBy); err != nil {
		return nil, err
	}
	if r.CompletedBy, err = uuidp(completedBy); err != nil {
		return nil, err
	}
	if r.CancelledAt, err = rtp(cancelledAt); err != nil {
		return nil, err
	}
	r.CompletedAt, err = rtp(completedAt)
	return &r, err
}

// InsertTenantRecovery stores a pending recovery for an invitation of this
// tenant. ErrDuplicate when the tenant already has a pending recovery (or
// the invitation already has one).
func (tx *TenantTx) InsertTenantRecovery(r *TenantRecovery) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.Status = RecoveryPending
	_, err := tx.exec(recoveryInsert, sql.Named("id", r.ID.String()), sql.Named("invitation_id", r.InvitationID.String()),
		sql.Named("operator", r.Operator), sql.Named("co_operator", r.CoOperator), sql.Named("ticket", r.Ticket),
		sql.Named("not_before", RT(r.NotBefore)), sql.Named("created_at", RT(r.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// TenantRecovery returns one of this tenant's recoveries (ErrNotFound otherwise).
func (tx *TenantTx) TenantRecovery(id uuid.UUID) (*TenantRecovery, error) {
	return one(tx, scanRecovery, recoveryGet, sql.Named("id", id.String()))
}

// TenantRecoveryByInvitation returns the recovery an invitation belongs to
// (ErrNotFound for an ordinary bootstrap invitation).
func (tx *TenantTx) TenantRecoveryByInvitation(invitation uuid.UUID) (*TenantRecovery, error) {
	return one(tx, scanRecovery, recoveryByInvitation, sql.Named("invitation_id", invitation.String()))
}

// PendingTenantRecovery returns the tenant's pending recovery (ErrNotFound if none).
func (tx *TenantTx) PendingTenantRecovery() (*TenantRecovery, error) {
	return one(tx, scanRecovery, recoveryPending)
}

// TenantRecoveries lists the tenant's most recent recoveries (at most 20), newest first.
func (tx *TenantTx) TenantRecoveries() ([]*TenantRecovery, error) {
	return collect(tx, scanRecovery, recoveryList)
}

// CancelTenantRecovery cancels a pending recovery (ErrAdminChangeState if it
// is not pending).
func (tx *TenantTx) CancelTenantRecovery(id, by uuid.UUID, at time.Time) error {
	return tx.adminTransition(recoveryCancel, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("at", RT(at)))
}

// CompleteTenantRecovery completes a pending recovery (ErrAdminChangeState if
// it is not pending).
func (tx *TenantTx) CompleteTenantRecovery(id, by uuid.UUID, at time.Time) error {
	return tx.adminTransition(recoveryComplete, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("at", RT(at)))
}

// ---------------------------------------------------------------- the transaction's own tenant row

// The tenants table is global, so a tenant statement cannot name it. These
// methods run system statements bound to this transaction's own tenant id:
// a caller cannot name another tenant, and the change commits atomically with
// the rest of the transaction (the admin change that caused it).
var (
	tenantsSetMinAdmins = sq("tenants.set_min_admins", `
		UPDATE tenants SET min_admins = @min_admins WHERE id = @id AND slug != '_platform' AND @min_admins >= 2`)
	tenantsSetContacts = sq("tenants.set_security_contacts", `
		UPDATE tenants SET security_contacts = @contacts WHERE id = @id AND slug != '_platform'
			AND json_valid(@contacts) AND json_type(@contacts) = 'array'`)
	tenantsSetStatus = sq("tenants.set_status", `
		UPDATE tenants SET status = @status WHERE id = @id AND slug != '_platform'
			AND status IN ('active','recovery') AND @status IN ('active','recovery')`)
)

func (tx *TenantTx) execOwnTenant(s sstmt, args ...sql.NamedArg) error {
	if tx.readOnly {
		return ErrReadOnly
	}
	a := make([]any, 0, len(args)+1)
	for _, x := range args {
		a = append(a, x)
	}
	a = append(a, sql.Named("id", tx.tenant.String()))
	res, err := tx.tx.ExecContext(tx.ctx, s.sql, a...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TenantRecord returns this transaction's own tenant row (settings, min_admins,
// security contacts, status).
func (tx *TenantTx) TenantRecord() (Tenant, error) {
	t, err := scanTenant(tx.tx.QueryRowContext(tx.ctx, tenantsByID.sql, sql.Named("id", tx.tenant.String())))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

// UpdateTenantSettings replaces this tenant's settings (a JSON object).
func (tx *TenantTx) UpdateTenantSettings(settings string) error {
	return tx.execOwnTenant(tenantsSetSettings, sql.Named("settings", settings))
}

// UpdateTenantMinAdmins sets this tenant's min_admins floor (at least 2).
func (tx *TenantTx) UpdateTenantMinAdmins(n int) error {
	return tx.execOwnTenant(tenantsSetMinAdmins, sql.Named("min_admins", n))
}

// UpdateTenantSecurityContacts replaces this tenant's security contacts (a JSON array).
func (tx *TenantTx) UpdateTenantSecurityContacts(contacts string) error {
	return tx.execOwnTenant(tenantsSetContacts, sql.Named("contacts", contacts))
}

// UpdateTenantStatus moves this tenant between active and recovery (§15.5);
// suspended tenants and the platform tenant are never touched.
func (tx *TenantTx) UpdateTenantStatus(status string) error {
	return tx.execOwnTenant(tenantsSetStatus, sql.Named("status", status))
}
