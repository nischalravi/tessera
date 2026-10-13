package store

import (
	"database/sql"
	"time"
)

// Guest claim tokens, sessions and confirmation codes
// (schema/0228_claim.sql, issue #69). Every statement binds @tenant. A token
// is only ever reached by the SHA-256 of its secret, a session only by the hash
// of its cookie and a code only through its session.

// Claim token statuses, kinds and purposes.
const (
	ClaimIssued   = "issued"
	ClaimConsumed = "consumed"
	ClaimRevoked  = "revoked"
	ClaimExpired  = "expired"
	ClaimLocked   = "locked"

	ClaimKindLink     = "link"
	ClaimPurposeClaim = "claim"
	ConfirmChanEmail  = "email"
)

// ClaimToken is one issued continuation secret (never the secret itself).
type ClaimToken struct {
	ID             string
	IntakeID       string
	IdentityID     int64
	Kind           string
	Purpose        string
	TokenHash      string
	EmailHMAC      string
	FailedAttempts int
	Status         string
	NotBefore      time.Time
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
	CreatedAt      time.Time
}

// ClaimSession is a consumed token's session, bound to the page's key.
type ClaimSession struct {
	IDHash            string
	TokenID           string
	IntakeID          string
	IdentityID        int64
	KeyJWK            string
	KeyJKT            string
	Nonce             string
	Step              string
	Verified          string // JSON object
	CredentialSubject *string
	LoginTxnID        *string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	CompletedAt       *time.Time
}

// ConfirmationCode is a code sent to a destination (only its hash is kept).
type ConfirmationCode struct {
	ID              string
	SessionIDHash   string
	Channel         string
	DestinationHMAC string
	CodeHash        string
	Attempts        int
	CreatedAt       time.Time
	ExpiresAt       time.Time
	UsedAt          *time.Time
	VoidedAt        *time.Time
}

const claimTokenCols = `t.id, t.intake_id, t.identity_id, t.kind, t.purpose, t.token_hash, t.email_hmac, t.failed_attempts,
	t.status, t.not_before, t.expires_at, t.consumed_at, t.created_at`

const claimSessionCols = `s.id_hash, s.token_id, s.intake_id, s.identity_id, s.key_jwk, s.key_jkt, s.nonce, s.step, s.verified,
	s.credential_subject, s.login_txn_id, s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, s.completed_at`

const confirmationCols = `c.id, c.session_id_hash, c.channel, c.destination_hmac, c.code_hash, c.attempts, c.created_at,
	c.expires_at, c.used_at, c.voided_at`

var (
	claimTokenInsert = tq("claim_tokens.insert", `
		INSERT INTO claim_tokens (id, tenant_id, intake_id, identity_id, kind, purpose, token_hash, email_hmac,
			failed_attempts, status, not_before, expires_at, consumed_at, created_at)
		VALUES (@id, @tenant, @intake_id, @identity_id, @kind, @purpose, @token_hash, @email_hmac, 0, @status,
			@not_before, @expires_at, NULL, @created_at)`)
	claimTokenByHash = tq("claim_tokens.by_hash", `
		SELECT `+claimTokenCols+` FROM claim_tokens t WHERE t.tenant_id = @tenant AND t.token_hash = @token_hash`)
	// single use: one UPDATE that only an issued, unexpired token can satisfy
	claimTokenConsume = tq("claim_tokens.consume", `
		UPDATE claim_tokens SET status = 'consumed', consumed_at = @now
		WHERE tenant_id = @tenant AND token_hash = @token_hash AND purpose = 'claim' AND status = 'issued'
			AND not_before <= @now AND expires_at > @now`)
	claimTokensRevoke = tq("claim_tokens.revoke_for_intake", `
		UPDATE claim_tokens SET status = 'revoked' WHERE tenant_id = @tenant AND intake_id = @intake_id
			AND purpose = 'claim' AND status = 'issued'`)
	claimTokensExpire = tq("claim_tokens.expire_due", `
		UPDATE claim_tokens SET status = 'expired' WHERE tenant_id = @tenant AND status = 'issued' AND expires_at <= @now`)
	claimTokensForIntake = tq("claim_tokens.for_intake", `
		SELECT `+claimTokenCols+` FROM claim_tokens t WHERE t.tenant_id = @tenant AND t.intake_id = @intake_id
		ORDER BY t.created_at DESC, t.id`)
	claimTokensByEmail = tq("claim_tokens.by_email", `
		SELECT `+claimTokenCols+` FROM claim_tokens t WHERE t.tenant_id = @tenant AND t.email_hmac = @email_hmac
			AND t.purpose = 'claim' ORDER BY t.created_at DESC, t.id LIMIT 5`)

	claimSessionInsert = tq("claim_sessions.insert", `
		INSERT INTO claim_sessions (id_hash, tenant_id, token_id, intake_id, identity_id, key_jwk, key_jkt, nonce, step,
			verified, credential_subject, login_txn_id, created_at, last_seen_at, expires_at, revoked_at, completed_at)
		VALUES (@id_hash, @tenant, @token_id, @intake_id, @identity_id, @key_jwk, @key_jkt, @nonce, @step, @verified,
			NULL, NULL, @created_at, @created_at, @expires_at, NULL, NULL)`)
	claimSessionGet = tq("claim_sessions.get", `
		SELECT `+claimSessionCols+` FROM claim_sessions s WHERE s.tenant_id = @tenant AND s.id_hash = @id_hash`)
	claimSessionByTxn = tq("claim_sessions.by_login_txn", `
		SELECT `+claimSessionCols+` FROM claim_sessions s WHERE s.tenant_id = @tenant AND s.login_txn_id = @login_txn_id`)
	claimSessionSave = tq("claim_sessions.save", `
		UPDATE claim_sessions SET step = @step, verified = @verified, credential_subject = @credential_subject,
			login_txn_id = @login_txn_id, last_seen_at = @last_seen_at, revoked_at = @revoked_at,
			completed_at = @completed_at
		WHERE tenant_id = @tenant AND id_hash = @id_hash`)
	claimSessionsRevoke = tq("claim_sessions.revoke_for_intake", `
		UPDATE claim_sessions SET revoked_at = @now WHERE tenant_id = @tenant AND intake_id = @intake_id
			AND revoked_at IS NULL AND completed_at IS NULL`)
	claimSessionsForIntake = tq("claim_sessions.for_intake", `
		SELECT `+claimSessionCols+` FROM claim_sessions s WHERE s.tenant_id = @tenant AND s.intake_id = @intake_id
		ORDER BY s.created_at DESC, s.id_hash`)

	confirmationInsert = tq("confirmation_codes.insert", `
		INSERT INTO confirmation_codes (id, tenant_id, session_id_hash, channel, destination_hmac, code_hash, attempts,
			created_at, expires_at, used_at, voided_at)
		VALUES (@id, @tenant, @session_id_hash, @channel, @destination_hmac, @code_hash, 0, @created_at, @expires_at,
			NULL, NULL)`)
	confirmationLive = tq("confirmation_codes.live_for_session", `
		SELECT `+confirmationCols+` FROM confirmation_codes c WHERE c.tenant_id = @tenant
			AND c.session_id_hash = @session_id_hash AND c.used_at IS NULL AND c.voided_at IS NULL
		ORDER BY c.created_at DESC, c.id LIMIT 1`)
	confirmationAttempt = tq("confirmation_codes.add_attempt", `
		UPDATE confirmation_codes SET attempts = attempts + 1 WHERE tenant_id = @tenant AND id = @id
			AND used_at IS NULL AND voided_at IS NULL`)
	confirmationVoid = tq("confirmation_codes.void", `
		UPDATE confirmation_codes SET voided_at = @now WHERE tenant_id = @tenant AND id = @id
			AND used_at IS NULL AND voided_at IS NULL`)
	confirmationVoidSession = tq("confirmation_codes.void_for_session", `
		UPDATE confirmation_codes SET voided_at = @now WHERE tenant_id = @tenant AND session_id_hash = @session_id_hash
			AND used_at IS NULL AND voided_at IS NULL`)
	confirmationUse = tq("confirmation_codes.use", `
		UPDATE confirmation_codes SET used_at = @now WHERE tenant_id = @tenant AND id = @id
			AND used_at IS NULL AND voided_at IS NULL AND expires_at > @now`)

	intakeInvitation = tq("intake_records.set_invitation", `
		UPDATE intake_records SET invitation_status = @status,
			claimed_at = CASE WHEN @status = 'claimed' THEN @at ELSE claimed_at END
		WHERE tenant_id = @tenant AND id = @id`)
	intakeExisting = tq("intake_records.set_existing_account", `
		UPDATE intake_records SET existing_account = @answer, existing_account_at = @at WHERE tenant_id = @tenant AND id = @id`)
	intakesByInvitation = tq("intake_records.by_invitation", `
		SELECT `+intakeCols+` FROM intake_records r WHERE r.tenant_id = @tenant AND r.invitation_status = @status
		ORDER BY r.created_at, r.id`)
	affiliationsActivate = tq("affiliations.activate", `
		UPDATE affiliations SET status = 'active' WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
)

func scanClaimToken(s scanner) (*ClaimToken, error) {
	var t ClaimToken
	var nb, exp, consumed, created nullTime
	if err := s.Scan(&t.ID, &t.IntakeID, &t.IdentityID, &t.Kind, &t.Purpose, &t.TokenHash, &t.EmailHMAC, &t.FailedAttempts,
		&t.Status, &nb, &exp, &consumed, &created); err != nil {
		return nil, err
	}
	var err error
	if t.NotBefore, err = nb.val(); err != nil {
		return nil, err
	}
	if t.ExpiresAt, err = exp.val(); err != nil {
		return nil, err
	}
	if t.ConsumedAt, err = consumed.ptr(); err != nil {
		return nil, err
	}
	t.CreatedAt, err = created.val()
	return &t, err
}

func scanClaimSession(s scanner) (*ClaimSession, error) {
	var x ClaimSession
	var subject, txn sql.NullString
	var created, seen, exp, revoked, completed nullTime
	if err := s.Scan(&x.IDHash, &x.TokenID, &x.IntakeID, &x.IdentityID, &x.KeyJWK, &x.KeyJKT, &x.Nonce, &x.Step, &x.Verified,
		&subject, &txn, &created, &seen, &exp, &revoked, &completed); err != nil {
		return nil, err
	}
	x.CredentialSubject, x.LoginTxnID = strp(subject), strp(txn)
	var err error
	if x.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if x.LastSeenAt, err = seen.val(); err != nil {
		return nil, err
	}
	if x.ExpiresAt, err = exp.val(); err != nil {
		return nil, err
	}
	if x.RevokedAt, err = revoked.ptr(); err != nil {
		return nil, err
	}
	x.CompletedAt, err = completed.ptr()
	return &x, err
}

func scanConfirmation(s scanner) (*ConfirmationCode, error) {
	var c ConfirmationCode
	var created, exp, used, voided nullTime
	if err := s.Scan(&c.ID, &c.SessionIDHash, &c.Channel, &c.DestinationHMAC, &c.CodeHash, &c.Attempts, &created, &exp,
		&used, &voided); err != nil {
		return nil, err
	}
	var err error
	if c.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if c.ExpiresAt, err = exp.val(); err != nil {
		return nil, err
	}
	if c.UsedAt, err = used.ptr(); err != nil {
		return nil, err
	}
	c.VoidedAt, err = voided.ptr()
	return &c, err
}

// InsertClaimToken records an issued token (by hash).
func (tx *TenantTx) InsertClaimToken(t *ClaimToken) error {
	_, err := tx.exec(claimTokenInsert, sql.Named("id", t.ID), sql.Named("intake_id", t.IntakeID),
		sql.Named("identity_id", t.IdentityID), sql.Named("kind", t.Kind), sql.Named("purpose", t.Purpose),
		sql.Named("token_hash", t.TokenHash), sql.Named("email_hmac", t.EmailHMAC), sql.Named("status", t.Status),
		sql.Named("not_before", T(t.NotBefore)), sql.Named("expires_at", T(t.ExpiresAt)), sql.Named("created_at", T(t.CreatedAt)))
	return err
}

// ClaimTokenByHash returns the token with this hash, or ErrNotFound.
func (tx *TenantTx) ClaimTokenByHash(hash string) (*ClaimToken, error) {
	return one(tx, scanClaimToken, claimTokenByHash, sql.Named("token_hash", hash))
}

// ConsumeClaimToken atomically moves the token with this hash from issued to
// consumed if it is within its lifetime at now, and returns it. A token that is
// unknown, expired, used or revoked is ErrNotFound: one UPDATE decides, so two
// concurrent starts cannot both win.
func (tx *TenantTx) ConsumeClaimToken(hash string, now time.Time) (*ClaimToken, error) {
	res, err := tx.exec(claimTokenConsume, sql.Named("token_hash", hash), sql.Named("now", T(now)))
	if err := affectedOne(res, err); err != nil {
		return nil, err
	}
	return tx.ClaimTokenByHash(hash)
}

// RevokeClaimTokens revokes every issued claim token of the intake and says how many.
func (tx *TenantTx) RevokeClaimTokens(intakeID string) (int, error) {
	res, err := tx.exec(claimTokensRevoke, sql.Named("intake_id", intakeID))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ExpireClaimTokens marks issued tokens past their lifetime expired and says how many.
func (tx *TenantTx) ExpireClaimTokens(now time.Time) (int, error) {
	res, err := tx.exec(claimTokensExpire, sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ClaimTokensForIntake lists an intake's tokens, newest first.
func (tx *TenantTx) ClaimTokensForIntake(intakeID string) ([]*ClaimToken, error) {
	return collect(tx, scanClaimToken, claimTokensForIntake, sql.Named("intake_id", intakeID))
}

// ClaimTokensByEmail lists the newest claim tokens bound to an invited email's hash.
func (tx *TenantTx) ClaimTokensByEmail(emailHMAC string) ([]*ClaimToken, error) {
	return collect(tx, scanClaimToken, claimTokensByEmail, sql.Named("email_hmac", emailHMAC))
}

// InsertClaimSession records a new session (the cookie's hash, never the cookie).
func (tx *TenantTx) InsertClaimSession(x *ClaimSession) error {
	_, err := tx.exec(claimSessionInsert, sql.Named("id_hash", x.IDHash), sql.Named("token_id", x.TokenID),
		sql.Named("intake_id", x.IntakeID), sql.Named("identity_id", x.IdentityID), sql.Named("key_jwk", x.KeyJWK),
		sql.Named("key_jkt", x.KeyJKT), sql.Named("nonce", x.Nonce), sql.Named("step", x.Step),
		sql.Named("verified", x.Verified), sql.Named("created_at", T(x.CreatedAt)), sql.Named("expires_at", T(x.ExpiresAt)))
	return err
}

// ClaimSession returns the session with this cookie hash, or ErrNotFound.
func (tx *TenantTx) ClaimSession(idHash string) (*ClaimSession, error) {
	return one(tx, scanClaimSession, claimSessionGet, sql.Named("id_hash", idHash))
}

// ClaimSessionByLoginTxn returns the session waiting for a login transaction, or ErrNotFound.
func (tx *TenantTx) ClaimSessionByLoginTxn(txn string) (*ClaimSession, error) {
	return one(tx, scanClaimSession, claimSessionByTxn, sql.Named("login_txn_id", txn))
}

// SaveClaimSession writes a session's changeable fields.
func (tx *TenantTx) SaveClaimSession(x *ClaimSession) error {
	res, err := tx.exec(claimSessionSave, sql.Named("id_hash", x.IDHash), sql.Named("step", x.Step),
		sql.Named("verified", x.Verified), sql.Named("credential_subject", optStr(x.CredentialSubject)),
		sql.Named("login_txn_id", optStr(x.LoginTxnID)), sql.Named("last_seen_at", T(x.LastSeenAt)),
		sql.Named("revoked_at", TP(x.RevokedAt)), sql.Named("completed_at", TP(x.CompletedAt)))
	return affectedOne(res, err)
}

// RevokeClaimSessions ends every open claim session of the intake.
func (tx *TenantTx) RevokeClaimSessions(intakeID string, now time.Time) error {
	_, err := tx.exec(claimSessionsRevoke, sql.Named("intake_id", intakeID), sql.Named("now", T(now)))
	return err
}

// ClaimSessionsForIntake lists an intake's sessions, newest first.
func (tx *TenantTx) ClaimSessionsForIntake(intakeID string) ([]*ClaimSession, error) {
	return collect(tx, scanClaimSession, claimSessionsForIntake, sql.Named("intake_id", intakeID))
}

// InsertConfirmationCode records a code sent to a destination (its hash only).
func (tx *TenantTx) InsertConfirmationCode(c *ConfirmationCode) error {
	_, err := tx.exec(confirmationInsert, sql.Named("id", c.ID), sql.Named("session_id_hash", c.SessionIDHash),
		sql.Named("channel", c.Channel), sql.Named("destination_hmac", c.DestinationHMAC),
		sql.Named("code_hash", c.CodeHash), sql.Named("created_at", T(c.CreatedAt)), sql.Named("expires_at", T(c.ExpiresAt)))
	return err
}

// LiveConfirmationCode returns the session's newest code that is neither used nor void, or ErrNotFound.
func (tx *TenantTx) LiveConfirmationCode(sessionIDHash string) (*ConfirmationCode, error) {
	return one(tx, scanConfirmation, confirmationLive, sql.Named("session_id_hash", sessionIDHash))
}

// AddConfirmationAttempt counts one wrong or right attempt against a live code.
func (tx *TenantTx) AddConfirmationAttempt(id string) error {
	res, err := tx.exec(confirmationAttempt, sql.Named("id", id))
	return affectedOne(res, err)
}

// VoidConfirmationCode voids a live code.
func (tx *TenantTx) VoidConfirmationCode(id string, now time.Time) error {
	res, err := tx.exec(confirmationVoid, sql.Named("id", id), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// VoidConfirmationCodes voids every live code of the session (a new code replaces them).
func (tx *TenantTx) VoidConfirmationCodes(sessionIDHash string, now time.Time) error {
	_, err := tx.exec(confirmationVoidSession, sql.Named("session_id_hash", sessionIDHash), sql.Named("now", T(now)))
	return err
}

// UseConfirmationCode marks a live, unexpired code used; ErrNotFound otherwise.
func (tx *TenantTx) UseConfirmationCode(id string, now time.Time) error {
	res, err := tx.exec(confirmationUse, sql.Named("id", id), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// SetIntakeInvitation moves an intake's invitation status (claimed_at is stamped for claimed).
func (tx *TenantTx) SetIntakeInvitation(id, status string, at time.Time) error {
	res, err := tx.exec(intakeInvitation, sql.Named("id", id), sql.Named("status", status), sql.Named("at", T(at)))
	return affectedOne(res, err)
}

// SetIntakeExistingAccount records the claimant's own answer ("yes" or "no")
// to "do you already have an account?"; it never links anything.
func (tx *TenantTx) SetIntakeExistingAccount(id, answer string, at time.Time) error {
	res, err := tx.exec(intakeExisting, sql.Named("id", id), sql.Named("answer", answer), sql.Named("at", T(at)))
	return affectedOne(res, err)
}

// ActivateAffiliation moves a pending affiliation to active (the guest claimed);
// ErrNotFound if it is unknown or not pending.
func (tx *TenantTx) ActivateAffiliation(id string) error {
	res, err := tx.exec(affiliationsActivate, sql.Named("id", id))
	return affectedOne(res, err)
}

// IntakesByInvitation lists the intake records whose invitation is in a status, oldest first.
func (tx *TenantTx) IntakesByInvitation(status string) ([]*IntakeRecord, error) {
	return collect(tx, scanIntake, intakesByInvitation, sql.Named("status", status))
}
