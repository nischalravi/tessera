package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Break-glass credentials, WebAuthn challenges and uses
// (schema/0009_breakglass.sql, design §9.6 and §15.4). Every statement is
// tenant-scoped (tq).

// ErrBreakGlassState is returned when a break-glass transition finds its row
// not in the state it needs: a challenge already consumed or expired, a use
// already answered, or a sign count that did not rise (a cloned key).
var ErrBreakGlassState = errors.New("store: break-glass row is not in the expected state")

// Break-glass challenge purposes.
const (
	BreakGlassRegistration = "registration"
	BreakGlassAssertion    = "assertion"
)

// BreakGlassCredential is one registered hardware key (design §7.4).
type BreakGlassCredential struct {
	ID              uuid.UUID
	TenantID        tenancy.ID
	UserID          uuid.UUID // the is_break_glass user it signs in
	ChangeRequestID uuid.UUID // the applied breakglass.register request
	CredentialID    []byte    // the authenticator's credential id
	PublicKey       []byte    // COSE key
	SignCount       uint32
	AAGUID          string // canonical UUID text
	// AttestationFormat is the WebAuthn attestation format ("packed", ...);
	// never "none".
	AttestationFormat string
	// AttestationTrust: basic (signature valid, chain not anchored) | attca |
	// mds_verified.
	AttestationTrust string
	BackupEligible   bool // always false: synced passkeys are refused
	Transports       []string
	Label            string // "Safe A, key 1"
	Custodian        string
	CreatedAt        time.Time
	LastUsedAt       *time.Time
	RevokedAt        *time.Time
}

// BreakGlassChallenge is the stored side of one WebAuthn ceremony.
type BreakGlassChallenge struct {
	ID              uuid.UUID
	TenantID        tenancy.ID
	Purpose         string // registration | assertion
	ChallengeHash   string // SHA-256 hex of the challenge the client echoes
	SessionData     json.RawMessage
	ChangeRequestID *uuid.UUID // registration
	UserID          *uuid.UUID // registration: the key's user
	CreatedBy       *uuid.UUID // registration: the requester
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
}

// BreakGlassUse is one break-glass sign-in and, once answered, the reason it
// was used.
type BreakGlassUse struct {
	ID           uuid.UUID
	TenantID     tenancy.ID
	CredentialID uuid.UUID // BreakGlassCredential.ID
	UserID       uuid.UUID
	SessionID    uuid.UUID
	UsedAt       time.Time
	IP           *string
	UserAgent    *string
	AnsweredAt   *time.Time
	AnsweredBy   *uuid.UUID
	Reason       *string
}

// #nosec G101 -- a column list, not a credential
const bgCredCols = `c.id, c.tenant_id, c.user_id, c.change_request_id, c.credential_id, c.public_key, c.sign_count, c.aaguid,
	c.attestation_format, c.attestation_trust, c.backup_eligible, c.transports, c.label, c.custodian, c.created_at,
	c.last_used_at, c.revoked_at`

const bgChallengeCols = `h.id, h.tenant_id, h.purpose, h.challenge_hash, h.session_data, h.change_request_id, h.user_id,
	h.created_by_user_id, h.created_at, h.expires_at, h.consumed_at`

const bgUseCols = `u.id, u.tenant_id, u.credential_row_id, u.user_id, u.session_id, u.used_at, u.ip, u.user_agent,
	u.answered_at, u.answered_by_user_id, u.reason`

var (
	bgCredInsert = tq("break_glass_credentials.insert", `
		INSERT INTO break_glass_credentials (id, tenant_id, user_id, change_request_id, credential_id, public_key, sign_count,
			aaguid, attestation_format, attestation_trust, backup_eligible, transports, label, custodian, created_at)
		VALUES (@id, @tenant, @user_id, @change_request_id, @credential_id, @public_key, @sign_count, @aaguid,
			@attestation_format, @attestation_trust, @backup_eligible, @transports, @label, @custodian, @created_at)`)
	bgCredGet = tq("break_glass_credentials.get", `
		SELECT `+bgCredCols+` FROM break_glass_credentials c WHERE c.tenant_id = @tenant AND c.id = @id`)
	bgCredByRawID = tq("break_glass_credentials.by_credential_id", `
		SELECT `+bgCredCols+` FROM break_glass_credentials c
		WHERE c.tenant_id = @tenant AND c.credential_id = @credential_id AND c.revoked_at IS NULL`)
	bgCredForChange = tq("break_glass_credentials.for_change", `
		SELECT `+bgCredCols+` FROM break_glass_credentials c
		WHERE c.tenant_id = @tenant AND c.change_request_id = @change_request_id`)
	bgCredList = tq("break_glass_credentials.list", `
		SELECT `+bgCredCols+` FROM break_glass_credentials c WHERE c.tenant_id = @tenant ORDER BY c.created_at, c.rowid`)
	bgCredRevoke = tq("break_glass_credentials.revoke", `
		UPDATE break_glass_credentials SET revoked_at = @at
		WHERE tenant_id = @tenant AND id = @id AND revoked_at IS NULL`)
	// The count only rises: a presented count that is not above the stored one
	// is a cloned authenticator, except an authenticator that has no counter
	// (it reports 0 every time).
	bgCredUse = tq("break_glass_credentials.use", `
		UPDATE break_glass_credentials SET sign_count = @sign_count, last_used_at = @at
		WHERE tenant_id = @tenant AND id = @id AND revoked_at IS NULL
			AND (sign_count < @sign_count OR (sign_count = 0 AND @sign_count = 0))`)

	bgChallengeInsert = tq("break_glass_challenges.insert", `
		INSERT INTO break_glass_challenges (id, tenant_id, purpose, challenge_hash, session_data, change_request_id, user_id,
			created_by_user_id, created_at, expires_at)
		VALUES (@id, @tenant, @purpose, @challenge_hash, @session_data, @change_request_id, @user_id, @created_by_user_id,
			@created_at, @expires_at)`)
	bgChallengeByHash = tq("break_glass_challenges.by_hash", `
		SELECT `+bgChallengeCols+` FROM break_glass_challenges h
		WHERE h.tenant_id = @tenant AND h.purpose = @purpose AND h.challenge_hash = @challenge_hash`)
	bgChallengeConsume = tq("break_glass_challenges.consume", `
		UPDATE break_glass_challenges SET consumed_at = @at
		WHERE tenant_id = @tenant AND id = @id AND consumed_at IS NULL AND expires_at > @at`)
	bgChallengeOpen = tq("break_glass_challenges.count_open", `
		SELECT count(*) FROM break_glass_challenges
		WHERE tenant_id = @tenant AND purpose = @purpose AND consumed_at IS NULL AND expires_at > @now`)
	bgChallengePurge = tq("break_glass_challenges.purge", `
		DELETE FROM break_glass_challenges WHERE tenant_id = @tenant AND expires_at <= @before`)

	bgUseInsert = tq("break_glass_uses.insert", `
		INSERT INTO break_glass_uses (id, tenant_id, credential_row_id, user_id, session_id, used_at, ip, user_agent)
		VALUES (@id, @tenant, @credential_row_id, @user_id, @session_id, @used_at, @ip, @user_agent)`)
	bgUseGet = tq("break_glass_uses.get", `
		SELECT `+bgUseCols+` FROM break_glass_uses u WHERE u.tenant_id = @tenant AND u.id = @id`)
	bgUseRecent = tq("break_glass_uses.recent", `
		SELECT `+bgUseCols+` FROM break_glass_uses u
		WHERE u.tenant_id = @tenant AND (u.used_at >= @since OR u.answered_at IS NULL)
		ORDER BY u.used_at DESC, u.rowid DESC LIMIT 200`)
	bgUseAnswer = tq("break_glass_uses.answer", `
		UPDATE break_glass_uses SET answered_at = @at, answered_by_user_id = @by, reason = @reason
		WHERE tenant_id = @tenant AND id = @id AND answered_at IS NULL`)

	sessionsRevokeAllExcept = tq("sessions.revoke_all_except", `
		UPDATE sessions SET status = 'revoked', revoked_at = @at, revoked_reason = @reason
		WHERE tenant_id = @tenant AND status = 'active' AND id <> @except`)
)

func scanBGCredential(s scanner) (*BreakGlassCredential, error) {
	var c BreakGlassCredential
	var id, tid, user, change, transports, created string
	var sign int64
	var be int
	var lastUsed, revoked sql.NullString
	if err := s.Scan(&id, &tid, &user, &change, &c.CredentialID, &c.PublicKey, &sign, &c.AAGUID, &c.AttestationFormat,
		&c.AttestationTrust, &be, &transports, &c.Label, &c.Custodian, &created, &lastUsed, &revoked); err != nil {
		return nil, err
	}
	var err error
	if c.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if c.UserID, err = uuid.Parse(user); err != nil {
		return nil, err
	}
	if c.ChangeRequestID, err = uuid.Parse(change); err != nil {
		return nil, err
	}
	c.SignCount, c.BackupEligible = uint32(sign), be == 1 // #nosec G115 -- the column is CHECKed to 0..4294967295
	if err := json.Unmarshal([]byte(transports), &c.Transports); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if c.LastUsedAt, err = rtp(lastUsed); err != nil {
		return nil, err
	}
	c.RevokedAt, err = rtp(revoked)
	return &c, err
}

func scanBGChallenge(s scanner) (*BreakGlassChallenge, error) {
	var h BreakGlassChallenge
	var id, tid, data, created, expires string
	var change, user, by, consumed sql.NullString
	if err := s.Scan(&id, &tid, &h.Purpose, &h.ChallengeHash, &data, &change, &user, &by, &created, &expires, &consumed); err != nil {
		return nil, err
	}
	var err error
	if h.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if h.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	h.SessionData = json.RawMessage(data)
	if h.ChangeRequestID, err = uuidp(change); err != nil {
		return nil, err
	}
	if h.UserID, err = uuidp(user); err != nil {
		return nil, err
	}
	if h.CreatedBy, err = uuidp(by); err != nil {
		return nil, err
	}
	if h.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if h.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	h.ConsumedAt, err = rtp(consumed)
	return &h, err
}

func scanBGUse(s scanner) (*BreakGlassUse, error) {
	var u BreakGlassUse
	var id, tid, cred, user, session, used string
	var ip, ua, answered, by, reason sql.NullString
	if err := s.Scan(&id, &tid, &cred, &user, &session, &used, &ip, &ua, &answered, &by, &reason); err != nil {
		return nil, err
	}
	var err error
	if u.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if u.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if u.CredentialID, err = uuid.Parse(cred); err != nil {
		return nil, err
	}
	if u.UserID, err = uuid.Parse(user); err != nil {
		return nil, err
	}
	if u.SessionID, err = uuid.Parse(session); err != nil {
		return nil, err
	}
	if u.UsedAt, err = ParseRT(used); err != nil {
		return nil, err
	}
	u.IP, u.UserAgent, u.Reason = strp(ip), strp(ua), strp(reason)
	if u.AnsweredAt, err = rtp(answered); err != nil {
		return nil, err
	}
	u.AnsweredBy, err = uuidp(by)
	return &u, err
}

func (tx *TenantTx) bgTransition(s tstmt, args ...sql.NamedArg) error {
	res, err := tx.exec(s, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBreakGlassState
	}
	return nil
}

// ---------------------------------------------------------------- credentials

// InsertBreakGlassCredential stores a registered key (a zero ID gets a fresh
// one). ErrDuplicate when the credential id, or the enrolment request, is
// already used in this tenant.
func (tx *TenantTx) InsertBreakGlassCredential(c *BreakGlassCredential) error {
	if err := tx.own(c.TenantID); err != nil {
		return err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	transports, err := json.Marshal(append([]string{}, c.Transports...))
	if err != nil {
		return err
	}
	_, err = tx.exec(bgCredInsert, sql.Named("id", c.ID.String()), sql.Named("user_id", c.UserID.String()),
		sql.Named("change_request_id", c.ChangeRequestID.String()), sql.Named("credential_id", c.CredentialID),
		sql.Named("public_key", c.PublicKey), sql.Named("sign_count", int64(c.SignCount)), sql.Named("aaguid", c.AAGUID),
		sql.Named("attestation_format", c.AttestationFormat), sql.Named("attestation_trust", c.AttestationTrust),
		sql.Named("backup_eligible", B(c.BackupEligible)), sql.Named("transports", string(transports)),
		sql.Named("label", c.Label), sql.Named("custodian", c.Custodian), sql.Named("created_at", RT(c.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// BreakGlassCredential returns one of this tenant's keys (ErrNotFound otherwise).
func (tx *TenantTx) BreakGlassCredential(id uuid.UUID) (*BreakGlassCredential, error) {
	return one(tx, scanBGCredential, bgCredGet, sql.Named("id", id.String()))
}

// BreakGlassCredentialByCredentialID returns the tenant's active (not
// revoked) key whose authenticator credential id is credentialID.
func (tx *TenantTx) BreakGlassCredentialByCredentialID(credentialID []byte) (*BreakGlassCredential, error) {
	return one(tx, scanBGCredential, bgCredByRawID, sql.Named("credential_id", credentialID))
}

// BreakGlassCredentialForChange returns the key registered under an
// enrolment request (ErrNotFound while it has none).
func (tx *TenantTx) BreakGlassCredentialForChange(changeID uuid.UUID) (*BreakGlassCredential, error) {
	return one(tx, scanBGCredential, bgCredForChange, sql.Named("change_request_id", changeID.String()))
}

// BreakGlassCredentials lists the tenant's keys, revoked ones included, oldest first.
func (tx *TenantTx) BreakGlassCredentials() ([]*BreakGlassCredential, error) {
	return collect(tx, scanBGCredential, bgCredList)
}

// RevokeBreakGlassCredential revokes an active key (ErrNotFound if it is not
// this tenant's or already revoked).
func (tx *TenantTx) RevokeBreakGlassCredential(id uuid.UUID, at time.Time) error {
	return tx.execOne(bgCredRevoke, sql.Named("id", id.String()), sql.Named("at", RT(at)))
}

// UseBreakGlassCredential records a successful assertion: the new sign count
// and the time. It is ErrBreakGlassState when the count did not rise (and is
// not the constant 0 of an authenticator without a counter), or the key was
// revoked.
func (tx *TenantTx) UseBreakGlassCredential(id uuid.UUID, signCount uint32, at time.Time) error {
	return tx.bgTransition(bgCredUse, sql.Named("id", id.String()), sql.Named("sign_count", int64(signCount)),
		sql.Named("at", RT(at)))
}

// ---------------------------------------------------------------- challenges

// InsertBreakGlassChallenge stores a ceremony's challenge (a zero ID gets a fresh one).
func (tx *TenantTx) InsertBreakGlassChallenge(h *BreakGlassChallenge) error {
	if err := tx.own(h.TenantID); err != nil {
		return err
	}
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	_, err := tx.exec(bgChallengeInsert, sql.Named("id", h.ID.String()), sql.Named("purpose", h.Purpose),
		sql.Named("challenge_hash", h.ChallengeHash), sql.Named("session_data", string(h.SessionData)),
		sql.Named("change_request_id", uuidArg(h.ChangeRequestID)), sql.Named("user_id", uuidArg(h.UserID)),
		sql.Named("created_by_user_id", uuidArg(h.CreatedBy)), sql.Named("created_at", RT(h.CreatedAt)),
		sql.Named("expires_at", RT(h.ExpiresAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// BreakGlassChallengeByHash returns this tenant's challenge of purpose whose
// SHA-256 is hash (ErrNotFound otherwise).
func (tx *TenantTx) BreakGlassChallengeByHash(purpose, hash string) (*BreakGlassChallenge, error) {
	return one(tx, scanBGChallenge, bgChallengeByHash, sql.Named("purpose", purpose), sql.Named("challenge_hash", hash))
}

// ConsumeBreakGlassChallenge marks a challenge used, once: ErrBreakGlassState
// when it was already consumed or has expired at at.
func (tx *TenantTx) ConsumeBreakGlassChallenge(id uuid.UUID, at time.Time) error {
	return tx.bgTransition(bgChallengeConsume, sql.Named("id", id.String()), sql.Named("at", RT(at)))
}

// CountOpenBreakGlassChallenges counts the unconsumed, unexpired challenges
// of purpose (the cap on anonymous option requests).
func (tx *TenantTx) CountOpenBreakGlassChallenges(purpose string, now time.Time) (int, error) {
	return tx.count(bgChallengeOpen, sql.Named("purpose", purpose), sql.Named("now", RT(now)))
}

// PurgeBreakGlassChallenges deletes the tenant's challenges that expired before before.
func (tx *TenantTx) PurgeBreakGlassChallenges(before time.Time) error {
	_, err := tx.exec(bgChallengePurge, sql.Named("before", RT(before)))
	return err
}

// ---------------------------------------------------------------- uses

// InsertBreakGlassUse records a break-glass sign-in (a zero ID gets a fresh one).
func (tx *TenantTx) InsertBreakGlassUse(u *BreakGlassUse) error {
	if err := tx.own(u.TenantID); err != nil {
		return err
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	_, err := tx.exec(bgUseInsert, sql.Named("id", u.ID.String()), sql.Named("credential_row_id", u.CredentialID.String()),
		sql.Named("user_id", u.UserID.String()), sql.Named("session_id", u.SessionID.String()),
		sql.Named("used_at", RT(u.UsedAt)), sql.Named("ip", SP(u.IP)), sql.Named("user_agent", SP(u.UserAgent)))
	return err
}

// BreakGlassUse returns one of this tenant's uses (ErrNotFound otherwise).
func (tx *TenantTx) BreakGlassUse(id uuid.UUID) (*BreakGlassUse, error) {
	return one(tx, scanBGUse, bgUseGet, sql.Named("id", id.String()))
}

// RecentBreakGlassUses lists the uses since since, plus every use nobody has
// answered yet, newest first (at most 200).
func (tx *TenantTx) RecentBreakGlassUses(since time.Time) ([]*BreakGlassUse, error) {
	return collect(tx, scanBGUse, bgUseRecent, sql.Named("since", RT(since)))
}

// AnswerBreakGlassUse records why a use happened and who said so
// (ErrBreakGlassState when it was already answered or is not this tenant's).
func (tx *TenantTx) AnswerBreakGlassUse(id, by uuid.UUID, reason string, at time.Time) error {
	return tx.bgTransition(bgUseAnswer, sql.Named("id", id.String()), sql.Named("by", by.String()),
		sql.Named("reason", reason), sql.Named("at", RT(at)))
}

// RevokeAllSessionsExcept revokes every active session of the tenant except
// the one named (the break-glass session that asks, §15.4) and returns how
// many.
func (tx *TenantTx) RevokeAllSessionsExcept(except uuid.UUID, reason string, at time.Time) (int64, error) {
	res, err := tx.exec(sessionsRevokeAllExcept, sql.Named("except", except.String()), sql.Named("reason", reason),
		sql.Named("at", RT(at)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
