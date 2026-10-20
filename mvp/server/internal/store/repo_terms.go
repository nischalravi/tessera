package store

import (
	"database/sql"
	"time"
)

// Guest terms of use, attribute-release consent and account recovery
// (schema/0232_terms_recovery.sql, issue #73). Every statement binds @tenant.
// Recovery codes are only ever reached by their keyed hash.

// Recovery case statuses and the ways a recovery is issued.
const (
	RecoveryIssued     = "issued"
	RecoveryStarted    = "started"
	RecoveryCooling    = "cooling_off"
	RecoveryCompleted  = "completed"
	RecoveryCancelled  = "cancelled"
	RecoveryExpired    = "expired"
	RecoveryViaSponsor = "sponsor"
	RecoveryViaDesk    = "help_desk"

	ClaimPurposeRecovery = "recovery"

	TermsContextClaim    = "claim"
	TermsContextRecovery = "recovery"
	TermsContextSignin   = "signin"
)

// TermsDocument is one version of a terms document.
type TermsDocument struct {
	ID         string
	Key        string
	Version    int
	Title      string
	Body       string
	TextSHA256 string
	GraceDays  int
	CreatedBy  string
	CreatedAt  time.Time
}

// TermsAssignment applies a document (all versions) to a population or to a
// bundle (the group of a catalog item).
type TermsAssignment struct {
	ID         string
	Key        string
	Scope      string
	Population *string
	GroupID    *int64
	CreatedAt  time.Time
}

// TermsAcceptance is the record of one person accepting one version.
type TermsAcceptance struct {
	ID          string
	IdentityID  int64
	DocumentID  string
	Key         string
	Version     int
	TextSHA256  string
	Context     string
	SessionHash *string
	IPHash      string
	UAHash      string
	AcceptedAt  time.Time
}

// AttributeConsent is what a guest agreed to release at a federated sign-in.
type AttributeConsent struct {
	ID          string
	IdentityID  int64
	SessionHash string
	Authority   string
	Offered     string // JSON array
	Consented   string // JSON array
	ConsentedAt time.Time
}

// RecoveryCase is one account recovery.
type RecoveryCase struct {
	ID                  string
	IdentityID          int64
	IntakeID            string
	TokenID             string
	SessionHash         *string
	IssuedBy            string
	Via                 string
	Reason              string
	RequiredIAL         int
	Privileged          bool
	Status              string
	PendingConnectionID *string
	PendingIssuer       *string
	PendingSubject      *string
	PendingEmail        *string
	CoolingUntil        *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	CompletedAt         *time.Time
}

// RecoveryCode is one stored (hashed) recovery code.
type RecoveryCode struct {
	ID         string
	IdentityID int64
	Batch      string
	CodeHash   string
	CreatedAt  time.Time
	UsedAt     *time.Time
	VoidedAt   *time.Time
}

const termsDocCols = `d.id, d.document_key, d.version, d.title, d.body, d.text_sha256, d.grace_days, d.created_by, d.created_at`

const termsAssignCols = `a.id, a.document_key, a.scope, a.population, a.group_id, a.created_at`

const termsAcceptCols = `a.id, a.identity_id, a.document_id, a.document_key, a.version, a.text_sha256, a.context,
	a.claim_session_hash, a.ip_hash, a.ua_hash, a.accepted_at`

const recoveryCols = `r.id, r.identity_id, r.intake_id, r.token_id, r.session_id_hash, r.issued_by, r.via, r.reason, r.required_ial,
	r.privileged, r.status, r.pending_connection_id, r.pending_issuer, r.pending_subject, r.pending_email, r.cooling_until,
	r.created_at, r.updated_at, r.completed_at`

var (
	termsDocInsert = tq("terms_documents.insert", `
		INSERT INTO terms_documents (id, tenant_id, document_key, version, title, body, text_sha256, grace_days, created_by, created_at)
		VALUES (@id, @tenant, @document_key, @version, @title, @body, @text_sha256, @grace_days, @created_by, @created_at)`)
	termsDocGet = tq("terms_documents.get", `
		SELECT `+termsDocCols+` FROM terms_documents d WHERE d.tenant_id = @tenant AND d.id = @id`)
	termsDocList = tq("terms_documents.list", `
		SELECT `+termsDocCols+` FROM terms_documents d WHERE d.tenant_id = @tenant ORDER BY d.document_key, d.version`)
	termsDocAny = tq("terms_documents.any", `
		SELECT COUNT(*) FROM (SELECT 1 FROM terms_documents d WHERE d.tenant_id = @tenant LIMIT 1)`)

	termsAssignList = tq("terms_assignments.list", `
		SELECT `+termsAssignCols+` FROM terms_assignments a WHERE a.tenant_id = @tenant ORDER BY a.document_key, a.scope`)
	termsAssignClear = tq("terms_assignments.clear_for_key", `
		DELETE FROM terms_assignments WHERE tenant_id = @tenant AND document_key = @document_key`)
	termsAssignInsert = tq("terms_assignments.insert", `
		INSERT INTO terms_assignments (id, tenant_id, document_key, scope, population, group_id, created_at)
		VALUES (@id, @tenant, @document_key, @scope, @population, @group_id, @created_at)`)

	termsAcceptInsert = tq("terms_acceptances.insert", `
		INSERT INTO terms_acceptances (id, tenant_id, identity_id, document_id, document_key, version, text_sha256, context,
			claim_session_hash, ip_hash, ua_hash, accepted_at)
		VALUES (@id, @tenant, @identity_id, @document_id, @document_key, @version, @text_sha256, @context,
			@claim_session_hash, @ip_hash, @ua_hash, @accepted_at)
		ON CONFLICT (tenant_id, identity_id, document_id) DO NOTHING`)
	termsAcceptFor = tq("terms_acceptances.for_identity", `
		SELECT `+termsAcceptCols+` FROM terms_acceptances a WHERE a.tenant_id = @tenant AND a.identity_id = @identity_id
		ORDER BY a.accepted_at, a.id`)

	consentInsert = tq("attribute_consents.insert", `
		INSERT INTO attribute_consents (id, tenant_id, identity_id, claim_session_hash, authority, offered, consented, consented_at)
		VALUES (@id, @tenant, @identity_id, @claim_session_hash, @authority, @offered, @consented, @consented_at)
		ON CONFLICT (tenant_id, claim_session_hash) DO NOTHING`)
	consentBySession = tq("attribute_consents.by_session", `
		SELECT c.id, c.identity_id, c.claim_session_hash, c.authority, c.offered, c.consented, c.consented_at
		FROM attribute_consents c WHERE c.tenant_id = @tenant AND c.claim_session_hash = @claim_session_hash`)
	consentForIdentity = tq("attribute_consents.for_identity", `
		SELECT c.id, c.identity_id, c.claim_session_hash, c.authority, c.offered, c.consented, c.consented_at
		FROM attribute_consents c WHERE c.tenant_id = @tenant AND c.identity_id = @identity_id ORDER BY c.consented_at, c.id`)

	recoveryInsert = tq("recovery_cases.insert", `
		INSERT INTO recovery_cases (id, tenant_id, identity_id, intake_id, token_id, session_id_hash, issued_by, via, reason,
			required_ial, privileged, status, created_at, updated_at)
		VALUES (@id, @tenant, @identity_id, @intake_id, @token_id, NULL, @issued_by, @via, @reason, @required_ial, @privileged,
			'issued', @created_at, @created_at)`)
	recoveryGet = tq("recovery_cases.get", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.id = @id`)
	recoveryByToken = tq("recovery_cases.by_token", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.token_id = @token_id`)
	recoveryBySession = tq("recovery_cases.by_session", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.session_id_hash = @session_id_hash`)
	recoveryList = tq("recovery_cases.list", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant
			AND (@identity_id = 0 OR r.identity_id = @identity_id) AND (@status = '' OR r.status = @status)
		ORDER BY r.created_at DESC, r.id`)
	recoverySave = tq("recovery_cases.save", `
		UPDATE recovery_cases SET status = @status, session_id_hash = @session_id_hash, pending_connection_id = @pending_connection_id,
			pending_issuer = @pending_issuer, pending_subject = @pending_subject, pending_email = @pending_email,
			cooling_until = @cooling_until, updated_at = @updated_at, completed_at = @completed_at
		WHERE tenant_id = @tenant AND id = @id`)
	recoveryOpenFor = tq("recovery_cases.open_for_identity", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.identity_id = @identity_id
			AND r.status IN ('issued','started','cooling_off') ORDER BY r.created_at, r.id`)
	recoveryDue = tq("recovery_cases.due", `
		SELECT `+recoveryCols+` FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.status = 'cooling_off'
			AND r.cooling_until <= @now ORDER BY r.cooling_until, r.id`)
	recoveryAnyCooling = tq("recovery_cases.any_cooling", `
		SELECT COUNT(*) FROM (SELECT 1 FROM recovery_cases r WHERE r.tenant_id = @tenant AND r.status = 'cooling_off' LIMIT 1)`)

	// single use: one UPDATE that only an issued, unexpired recovery token can satisfy
	recoveryTokenConsume = tq("claim_tokens.consume_recovery", `
		UPDATE claim_tokens SET status = 'consumed', consumed_at = @now
		WHERE tenant_id = @tenant AND token_hash = @token_hash AND purpose = 'recovery' AND status = 'issued'
			AND not_before <= @now AND expires_at > @now`)
	recoveryTokensRevoke = tq("claim_tokens.revoke_recovery_for_identity", `
		UPDATE claim_tokens SET status = 'revoked' WHERE tenant_id = @tenant AND identity_id = @identity_id
			AND purpose = 'recovery' AND status = 'issued'`)

	recoveryCodeInsert = tq("recovery_codes.insert", `
		INSERT INTO recovery_codes (id, tenant_id, identity_id, batch, code_hash, created_at, used_at, voided_at)
		VALUES (@id, @tenant, @identity_id, @batch, @code_hash, @created_at, NULL, NULL)`)
	recoveryCodeVoid = tq("recovery_codes.void_for_identity", `
		UPDATE recovery_codes SET voided_at = @now WHERE tenant_id = @tenant AND identity_id = @identity_id
			AND used_at IS NULL AND voided_at IS NULL`)
	// single use: one UPDATE that only an unspent, unvoided code can satisfy
	recoveryCodeUse = tq("recovery_codes.use", `
		UPDATE recovery_codes SET used_at = @now WHERE tenant_id = @tenant AND identity_id = @identity_id
			AND code_hash = @code_hash AND used_at IS NULL AND voided_at IS NULL`)
	recoveryCodeList = tq("recovery_codes.for_identity", `
		SELECT c.id, c.identity_id, c.batch, c.code_hash, c.created_at, c.used_at, c.voided_at FROM recovery_codes c
		WHERE c.tenant_id = @tenant AND c.identity_id = @identity_id ORDER BY c.created_at, c.id`)
	recoveryCodeLive = tq("recovery_codes.count_live", `
		SELECT COUNT(*) FROM recovery_codes c WHERE c.tenant_id = @tenant AND c.identity_id = @identity_id
			AND c.used_at IS NULL AND c.voided_at IS NULL`)
)

func scanTermsDoc(s scanner) (*TermsDocument, error) {
	var d TermsDocument
	var created nullTime
	if err := s.Scan(&d.ID, &d.Key, &d.Version, &d.Title, &d.Body, &d.TextSHA256, &d.GraceDays, &d.CreatedBy, &created); err != nil {
		return nil, err
	}
	var err error
	d.CreatedAt, err = created.val()
	return &d, err
}

func scanTermsAssign(s scanner) (*TermsAssignment, error) {
	var a TermsAssignment
	var pop sql.NullString
	var group sql.NullInt64
	var created nullTime
	if err := s.Scan(&a.ID, &a.Key, &a.Scope, &pop, &group, &created); err != nil {
		return nil, err
	}
	a.Population = strp(pop)
	if group.Valid {
		g := group.Int64
		a.GroupID = &g
	}
	var err error
	a.CreatedAt, err = created.val()
	return &a, err
}

func scanTermsAccept(s scanner) (*TermsAcceptance, error) {
	var a TermsAcceptance
	var sess sql.NullString
	var at nullTime
	if err := s.Scan(&a.ID, &a.IdentityID, &a.DocumentID, &a.Key, &a.Version, &a.TextSHA256, &a.Context, &sess, &a.IPHash, &a.UAHash, &at); err != nil {
		return nil, err
	}
	a.SessionHash = strp(sess)
	var err error
	a.AcceptedAt, err = at.val()
	return &a, err
}

func scanConsent(s scanner) (*AttributeConsent, error) {
	var c AttributeConsent
	var at nullTime
	if err := s.Scan(&c.ID, &c.IdentityID, &c.SessionHash, &c.Authority, &c.Offered, &c.Consented, &at); err != nil {
		return nil, err
	}
	var err error
	c.ConsentedAt, err = at.val()
	return &c, err
}

func scanRecovery(s scanner) (*RecoveryCase, error) {
	var r RecoveryCase
	var sess, conn, issuer, subject, email sql.NullString
	var priv int
	var cool, completed, created, updated nullTime
	if err := s.Scan(&r.ID, &r.IdentityID, &r.IntakeID, &r.TokenID, &sess, &r.IssuedBy, &r.Via, &r.Reason, &r.RequiredIAL, &priv,
		&r.Status, &conn, &issuer, &subject, &email, &cool, &created, &updated, &completed); err != nil {
		return nil, err
	}
	r.SessionHash, r.PendingConnectionID, r.PendingIssuer, r.PendingSubject, r.PendingEmail = strp(sess), strp(conn), strp(issuer), strp(subject), strp(email)
	r.Privileged = priv != 0
	var err error
	if r.CoolingUntil, err = cool.ptr(); err != nil {
		return nil, err
	}
	if r.CompletedAt, err = completed.ptr(); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	r.UpdatedAt, err = updated.val()
	return &r, err
}

func scanRecoveryCode(s scanner) (*RecoveryCode, error) {
	var c RecoveryCode
	var created, used, voided nullTime
	if err := s.Scan(&c.ID, &c.IdentityID, &c.Batch, &c.CodeHash, &created, &used, &voided); err != nil {
		return nil, err
	}
	var err error
	if c.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if c.UsedAt, err = used.ptr(); err != nil {
		return nil, err
	}
	c.VoidedAt, err = voided.ptr()
	return &c, err
}

// ---------------------------------------------------------------- terms

// InsertTermsDocument records a new version.
func (tx *TenantTx) InsertTermsDocument(d *TermsDocument) error {
	_, err := tx.exec(termsDocInsert, sql.Named("id", d.ID), sql.Named("document_key", d.Key), sql.Named("version", d.Version),
		sql.Named("title", d.Title), sql.Named("body", d.Body), sql.Named("text_sha256", d.TextSHA256),
		sql.Named("grace_days", d.GraceDays), sql.Named("created_by", d.CreatedBy), sql.Named("created_at", T(d.CreatedAt)))
	return err
}

// TermsDocument returns a version by id, or ErrNotFound.
func (tx *TenantTx) TermsDocument(id string) (*TermsDocument, error) {
	return one(tx, scanTermsDoc, termsDocGet, sql.Named("id", id))
}

// TermsDocuments lists every version of every document, by key then version.
func (tx *TenantTx) TermsDocuments() ([]*TermsDocument, error) {
	return collect(tx, scanTermsDoc, termsDocList)
}

// HasTermsDocuments reports whether the tenant has published any terms.
func (tx *TenantTx) HasTermsDocuments() (bool, error) {
	n, err := tx.count(termsDocAny)
	return n > 0, err
}

// TermsAssignments lists every assignment.
func (tx *TenantTx) TermsAssignments() ([]*TermsAssignment, error) {
	return collect(tx, scanTermsAssign, termsAssignList)
}

// ReplaceTermsAssignments sets what a document applies to.
func (tx *TenantTx) ReplaceTermsAssignments(key string, as []*TermsAssignment) error {
	if _, err := tx.exec(termsAssignClear, sql.Named("document_key", key)); err != nil {
		return err
	}
	for _, a := range as {
		var pop any
		if a.Population != nil {
			pop = *a.Population
		}
		if _, err := tx.exec(termsAssignInsert, sql.Named("id", a.ID), sql.Named("document_key", key), sql.Named("scope", a.Scope),
			sql.Named("population", pop), sql.Named("group_id", IP(a.GroupID)), sql.Named("created_at", T(a.CreatedAt))); err != nil {
			return err
		}
	}
	return nil
}

// InsertTermsAcceptance records an acceptance; false when the person had
// already accepted that version (nothing is written).
func (tx *TenantTx) InsertTermsAcceptance(a *TermsAcceptance) (bool, error) {
	res, err := tx.exec(termsAcceptInsert, sql.Named("id", a.ID), sql.Named("identity_id", a.IdentityID),
		sql.Named("document_id", a.DocumentID), sql.Named("document_key", a.Key), sql.Named("version", a.Version),
		sql.Named("text_sha256", a.TextSHA256), sql.Named("context", a.Context), sql.Named("claim_session_hash", optStr(a.SessionHash)),
		sql.Named("ip_hash", a.IPHash), sql.Named("ua_hash", a.UAHash), sql.Named("accepted_at", T(a.AcceptedAt)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// TermsAcceptancesFor lists a person's acceptances, oldest first.
func (tx *TenantTx) TermsAcceptancesFor(identityID int64) ([]*TermsAcceptance, error) {
	return collect(tx, scanTermsAccept, termsAcceptFor, sql.Named("identity_id", identityID))
}

// InsertAttributeConsent records a consent; false when the session already
// recorded one.
func (tx *TenantTx) InsertAttributeConsent(c *AttributeConsent) (bool, error) {
	res, err := tx.exec(consentInsert, sql.Named("id", c.ID), sql.Named("identity_id", c.IdentityID),
		sql.Named("claim_session_hash", c.SessionHash), sql.Named("authority", c.Authority), sql.Named("offered", c.Offered),
		sql.Named("consented", c.Consented), sql.Named("consented_at", T(c.ConsentedAt)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// AttributeConsentFor returns the consent a claim session recorded, or ErrNotFound.
func (tx *TenantTx) AttributeConsentFor(sessionHash string) (*AttributeConsent, error) {
	return one(tx, scanConsent, consentBySession, sql.Named("claim_session_hash", sessionHash))
}

// AttributeConsentsFor lists a person's consents.
func (tx *TenantTx) AttributeConsentsFor(identityID int64) ([]*AttributeConsent, error) {
	return collect(tx, scanConsent, consentForIdentity, sql.Named("identity_id", identityID))
}

// ---------------------------------------------------------------- recovery

// InsertRecoveryCase records an issued recovery.
func (tx *TenantTx) InsertRecoveryCase(r *RecoveryCase) error {
	_, err := tx.exec(recoveryInsert, sql.Named("id", r.ID), sql.Named("identity_id", r.IdentityID), sql.Named("intake_id", r.IntakeID),
		sql.Named("token_id", r.TokenID), sql.Named("issued_by", r.IssuedBy), sql.Named("via", r.Via), sql.Named("reason", r.Reason),
		sql.Named("required_ial", r.RequiredIAL), sql.Named("privileged", B(r.Privileged)), sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// RecoveryCase returns a case by id, or ErrNotFound.
func (tx *TenantTx) RecoveryCase(id string) (*RecoveryCase, error) {
	return one(tx, scanRecovery, recoveryGet, sql.Named("id", id))
}

// RecoveryCaseByToken returns the case of a recovery token, or ErrNotFound.
func (tx *TenantTx) RecoveryCaseByToken(tokenID string) (*RecoveryCase, error) {
	return one(tx, scanRecovery, recoveryByToken, sql.Named("token_id", tokenID))
}

// RecoveryCaseBySession returns the case a claim session works on, or ErrNotFound.
func (tx *TenantTx) RecoveryCaseBySession(sessionHash string) (*RecoveryCase, error) {
	return one(tx, scanRecovery, recoveryBySession, sql.Named("session_id_hash", sessionHash))
}

// RecoveryCases lists cases, newest first, optionally of one person or status.
func (tx *TenantTx) RecoveryCases(identityID int64, status string) ([]*RecoveryCase, error) {
	return collect(tx, scanRecovery, recoveryList, sql.Named("identity_id", identityID), sql.Named("status", status))
}

// OpenRecoveryCases lists a person's cases that are not final.
func (tx *TenantTx) OpenRecoveryCases(identityID int64) ([]*RecoveryCase, error) {
	return collect(tx, scanRecovery, recoveryOpenFor, sql.Named("identity_id", identityID))
}

// DueRecoveries lists the cases whose cooling-off has ended at now.
func (tx *TenantTx) DueRecoveries(now time.Time) ([]*RecoveryCase, error) {
	return collect(tx, scanRecovery, recoveryDue, sql.Named("now", T(now)))
}

// HasCoolingRecoveries reports whether any case is in its cooling-off (the sweeper has work).
func (tx *TenantTx) HasCoolingRecoveries() (bool, error) {
	n, err := tx.count(recoveryAnyCooling)
	return n > 0, err
}

// SaveRecoveryCase writes a case's changeable fields; ErrNotFound for an
// unknown case or one that is already final.
func (tx *TenantTx) SaveRecoveryCase(r *RecoveryCase) error {
	res, err := tx.exec(recoverySave, sql.Named("id", r.ID), sql.Named("status", r.Status), sql.Named("session_id_hash", optStr(r.SessionHash)),
		sql.Named("pending_connection_id", optStr(r.PendingConnectionID)), sql.Named("pending_issuer", optStr(r.PendingIssuer)),
		sql.Named("pending_subject", optStr(r.PendingSubject)), sql.Named("pending_email", optStr(r.PendingEmail)),
		sql.Named("cooling_until", TP(r.CoolingUntil)), sql.Named("updated_at", T(r.UpdatedAt)), sql.Named("completed_at", TP(r.CompletedAt)))
	return affectedOne(res, err)
}

// ConsumeRecoveryToken atomically moves the purpose=recovery token with this
// hash from issued to consumed if it is within its lifetime at now, and
// returns it. A token that is unknown, expired, used or revoked is ErrNotFound.
func (tx *TenantTx) ConsumeRecoveryToken(hash string, now time.Time) (*ClaimToken, error) {
	res, err := tx.exec(recoveryTokenConsume, sql.Named("token_hash", hash), sql.Named("now", T(now)))
	if err := affectedOne(res, err); err != nil {
		return nil, err
	}
	return tx.ClaimTokenByHash(hash)
}

// RevokeRecoveryTokens revokes a person's issued recovery tokens and says how many.
func (tx *TenantTx) RevokeRecoveryTokens(identityID int64) (int, error) {
	res, err := tx.exec(recoveryTokensRevoke, sql.Named("identity_id", identityID))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// InsertRecoveryCode stores one code's hash.
func (tx *TenantTx) InsertRecoveryCode(c *RecoveryCode) error {
	_, err := tx.exec(recoveryCodeInsert, sql.Named("id", c.ID), sql.Named("identity_id", c.IdentityID), sql.Named("batch", c.Batch),
		sql.Named("code_hash", c.CodeHash), sql.Named("created_at", T(c.CreatedAt)))
	return err
}

// VoidRecoveryCodes voids a person's unspent codes and says how many.
func (tx *TenantTx) VoidRecoveryCodes(identityID int64, now time.Time) (int, error) {
	res, err := tx.exec(recoveryCodeVoid, sql.Named("identity_id", identityID), sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// UseRecoveryCode atomically spends the person's code with this hash; ErrNotFound
// if there is none, or it was spent or voided.
func (tx *TenantTx) UseRecoveryCode(identityID int64, codeHash string, now time.Time) error {
	res, err := tx.exec(recoveryCodeUse, sql.Named("identity_id", identityID), sql.Named("code_hash", codeHash), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// RecoveryCodesFor lists a person's stored codes (hashes), oldest first.
func (tx *TenantTx) RecoveryCodesFor(identityID int64) ([]*RecoveryCode, error) {
	return collect(tx, scanRecoveryCode, recoveryCodeList, sql.Named("identity_id", identityID))
}

// CountLiveRecoveryCodes says how many unspent, unvoided codes a person has.
func (tx *TenantTx) CountLiveRecoveryCodes(identityID int64) (int, error) {
	return tx.count(recoveryCodeLive, sql.Named("identity_id", identityID))
}
