package store

import (
	"database/sql"
	"time"
)

// Restore on denial (schema/0922_lp_denials.sql, issue #662, LP-6). Every statement binds the tenant. What a denial
// means (is the action one the revocation removed, is it restored) is decided by internal/lp and the API; this
// file only keeps the rows.

// Sources and outcomes of a denial event.
const (
	LPDenialCloudTrail = "cloudtrail"
	LPDenialIdP        = "idp"

	LPDenialRestoreRequested = "restore_requested"
	LPDenialActionNotRemoved = "action_not_removed"
)

// LPDenialHook is the tenant's receiver credential: the digest of the secret the EventBridge API destination sends.
type LPDenialHook struct {
	SecretSHA256 string
	CreatedBy    string
	CreatedAt    time.Time
	RotatedAt    time.Time
}

// LPDenial is a denial event that named a principal with a revoked grant.
type LPDenial struct {
	ID           string
	Source       string
	EventID      string
	Principal    string
	Action       string
	Resource     string
	OccurredAt   *time.Time
	ArrivedAt    time.Time
	Outcome      string
	RevocationID string
	Detail       string
}

var (
	lpHookGet = tq("lp_denial_hooks.get", `
		SELECT h.secret_sha256, h.created_by, h.created_at, h.rotated_at FROM lp_denial_hooks h WHERE h.tenant_id = @tenant`)
	lpHookPut = tq("lp_denial_hooks.put", `
		INSERT INTO lp_denial_hooks (tenant_id, secret_sha256, created_by, created_at, rotated_at)
		VALUES (@tenant, @secret_sha256, @created_by, @created_at, @rotated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET secret_sha256 = excluded.secret_sha256, rotated_at = excluded.rotated_at`)

	lpDenialInsert = tq("lp_denials.insert", `
		INSERT INTO lp_denials (tenant_id, id, source, event_id, principal_arn, action, resource, occurred_at, arrived_at, outcome, revocation_id, detail)
		VALUES (@tenant, @id, @source, @event_id, @principal_arn, @action, @resource, @occurred_at, @arrived_at, @outcome, @revocation_id, @detail)`)
	lpDenialSeen = tq("lp_denials.seen", `
		SELECT COUNT(*) FROM lp_denials d WHERE d.tenant_id = @tenant AND d.source = @source AND d.event_id = @event_id`)
	lpDenialList = tq("lp_denials.list", `
		SELECT d.id, d.source, d.event_id, d.principal_arn, d.action, d.resource, d.occurred_at, d.arrived_at, d.outcome, d.revocation_id, d.detail
		FROM lp_denials d WHERE d.tenant_id = @tenant ORDER BY d.arrived_at DESC, d.id LIMIT @limit`)
	lpRevRevokedFor = tq("lp_revocations.revoked_for_principal", `
		SELECT `+lpRevCols+` FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.state = 'revoked' AND r.principal_arn = @principal ORDER BY r.created_at, r.id LIMIT 50`)
)

// LPDenialHook returns the tenant's receiver credential, or ErrNotFound when none was created.
func (tx *TenantTx) LPDenialHook() (*LPDenialHook, error) {
	return one(tx, func(s scanner) (*LPDenialHook, error) {
		var h LPDenialHook
		var created, rotated string
		if err := s.Scan(&h.SecretSHA256, &h.CreatedBy, &created, &rotated); err != nil {
			return nil, err
		}
		var err error
		if h.CreatedAt, err = ParseRT(created); err != nil {
			return nil, err
		}
		h.RotatedAt, err = ParseRT(rotated)
		return &h, err
	}, lpHookGet)
}

// PutLPDenialHook creates the credential or replaces its secret digest (a rotation keeps created_at and created_by).
func (tx *TenantTx) PutLPDenialHook(h *LPDenialHook) error {
	_, err := tx.exec(lpHookPut, sql.Named("secret_sha256", h.SecretSHA256), sql.Named("created_by", h.CreatedBy),
		sql.Named("created_at", RT(h.CreatedAt)), sql.Named("rotated_at", RT(h.RotatedAt)))
	return err
}

// LPDenialSeen reports whether this event was recorded already (a redelivery).
func (tx *TenantTx) LPDenialSeen(source, eventID string) (bool, error) {
	n, err := tx.count(lpDenialSeen, sql.Named("source", source), sql.Named("event_id", eventID))
	return n > 0, err
}

// InsertLPDenial records a denial event. ErrDuplicate: the same event arrived twice.
func (tx *TenantTx) InsertLPDenial(d *LPDenial) error {
	if d.ID == "" {
		d.ID = NewID()
	}
	_, err := tx.exec(lpDenialInsert, sql.Named("id", d.ID), sql.Named("source", d.Source), sql.Named("event_id", d.EventID),
		sql.Named("principal_arn", d.Principal), sql.Named("action", d.Action), sql.Named("resource", d.Resource), sql.Named("occurred_at", RTP(d.OccurredAt)),
		sql.Named("arrived_at", RT(d.ArrivedAt)), sql.Named("outcome", d.Outcome), sql.Named("revocation_id", d.RevocationID),
		sql.Named("detail", d.Detail))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// LPDenials lists denial events, newest arrival first; limit <= 0 or above 500 is 100.
func (tx *TenantTx) LPDenials(limit int) ([]*LPDenial, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, func(s scanner) (*LPDenial, error) {
		var d LPDenial
		var occurred sql.NullString
		var arrived string
		if err := s.Scan(&d.ID, &d.Source, &d.EventID, &d.Principal, &d.Action, &d.Resource, &occurred, &arrived, &d.Outcome, &d.RevocationID, &d.Detail); err != nil {
			return nil, err
		}
		var err error
		if d.OccurredAt, err = rtp(occurred); err != nil {
			return nil, err
		}
		d.ArrivedAt, err = ParseRT(arrived)
		return &d, err
	}, lpDenialList, sql.Named("limit", limit))
}

// LPRevokedForPrincipal lists the revoked (not yet final) revocations of one principal: the ones a denial can restore.
func (tx *TenantTx) LPRevokedForPrincipal(principal string) ([]*LPRevocation, error) {
	return collect(tx, scanLPRevocation, lpRevRevokedFor, sql.Named("principal", principal))
}
