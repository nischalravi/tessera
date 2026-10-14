package store

import (
	"database/sql"
	"strings"
	"time"
)

// Guest self-registration requests and sponsor codes
// (schema/0240_guest_registration.sql, issue #66). Every statement binds
// @tenant. A registration holds a visitor's name, address and purpose until the
// sponsor decides; a sponsor code is only ever reached by its keyed hash.

// Registration statuses and ways of naming the sponsor.
const (
	RegPending  = "pending"
	RegApproved = "approved"
	RegDenied   = "denied"
	RegExpired  = "expired"

	RegViaSearch = "search"
	RegViaCode   = "code"

	SponsorCodeActive  = "active"
	SponsorCodeRevoked = "revoked"
)

// Registration is a visitor's request to be sponsored. The personal fields are
// nil once the request was reduced (RedactedAt is set).
type Registration struct {
	ID                string
	SponsorIdentityID int64
	Via               string
	GivenName         *string
	FamilyName        *string
	Email             *string
	Purpose           *string
	EmailHMAC         string
	StartsAt          time.Time
	EndsAt            time.Time
	Status            string
	ExpiresAt         time.Time
	DecidedBy         *string
	DecidedAt         *time.Time
	IdentityID        *int64
	IntakeID          *string
	RedactAfter       *time.Time
	RedactedAt        *time.Time
	CreatedAt         time.Time
}

// SponsorCode is a code a sponsor shares (only its hash is kept).
type SponsorCode struct {
	ID                string
	SponsorIdentityID int64
	CodeHash          string
	Status            string
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

const registrationCols = `r.id, r.sponsor_identity_id, r.via, r.given_name, r.family_name, r.email, r.purpose, r.email_hmac,
	r.starts_at, r.ends_at, r.status, r.expires_at, r.decided_by, r.decided_at, r.identity_id, r.intake_id, r.redact_after,
	r.redacted_at, r.created_at`

var (
	regInsert = tq("guest_registrations.insert", `
		INSERT INTO guest_registrations (id, tenant_id, sponsor_identity_id, via, given_name, family_name, email, purpose,
			email_hmac, starts_at, ends_at, status, expires_at, decided_by, decided_at, identity_id, intake_id,
			redact_after, redacted_at, created_at)
		VALUES (@id, @tenant, @sponsor_identity_id, @via, @given_name, @family_name, @email, @purpose, @email_hmac,
			@starts_at, @ends_at, 'pending', @expires_at, NULL, NULL, NULL, NULL, NULL, NULL, @created_at)`)
	regGet = tq("guest_registrations.get", `
		SELECT `+registrationCols+` FROM guest_registrations r WHERE r.tenant_id = @tenant AND r.id = @id`)
	regForSponsor = tq("guest_registrations.for_sponsor", `
		SELECT `+registrationCols+` FROM guest_registrations r WHERE r.tenant_id = @tenant
			AND r.sponsor_identity_id = @sponsor_identity_id AND (@status = '' OR r.status = @status)
		ORDER BY r.created_at, r.id`)
	regHasPending = tq("guest_registrations.has_pending", `
		SELECT count(*) FROM guest_registrations r WHERE r.tenant_id = @tenant AND r.status = 'pending'
			AND r.sponsor_identity_id = @sponsor_identity_id AND r.email_hmac = @email_hmac`)
	regDue = tq("guest_registrations.due", `
		SELECT `+registrationCols+` FROM guest_registrations r WHERE r.tenant_id = @tenant AND r.status = 'pending'
			AND r.expires_at <= @now ORDER BY r.expires_at, r.id`)
	regDecide = tq("guest_registrations.decide", `
		UPDATE guest_registrations SET status = @status, decided_by = @decided_by, decided_at = @now,
			identity_id = @identity_id, intake_id = @intake_id, redact_after = @redact_after
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)
	regRedact = tq("guest_registrations.redact", `
		UPDATE guest_registrations SET given_name = NULL, family_name = NULL, email = NULL, purpose = NULL, redacted_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status <> 'pending' AND redacted_at IS NULL`)
	regRedactDue = tq("guest_registrations.redact_due", `
		UPDATE guest_registrations SET given_name = NULL, family_name = NULL, email = NULL, purpose = NULL, redacted_at = @now
		WHERE tenant_id = @tenant AND status <> 'pending' AND redacted_at IS NULL AND redact_after <= @now`)
	regHoldingData = tq("guest_registrations.holding_data", `
		SELECT count(*) FROM guest_registrations r WHERE r.tenant_id = @tenant AND (r.status = 'pending'
			OR (r.status <> 'pending' AND r.redacted_at IS NULL))`)

	codeInsert = tq("guest_sponsor_codes.insert", `
		INSERT INTO guest_sponsor_codes (id, tenant_id, sponsor_identity_id, code_hash, status, expires_at, created_at, revoked_at)
		VALUES (@id, @tenant, @sponsor_identity_id, @code_hash, 'active', @expires_at, @created_at, NULL)`)
	codeByHash = tq("guest_sponsor_codes.by_hash", `
		SELECT c.id, c.sponsor_identity_id, c.code_hash, c.status, c.expires_at, c.created_at FROM guest_sponsor_codes c
		WHERE c.tenant_id = @tenant AND c.code_hash = @code_hash AND c.status = 'active' AND c.expires_at > @now`)
	codeRevoke = tq("guest_sponsor_codes.revoke_for_sponsor", `
		UPDATE guest_sponsor_codes SET status = 'revoked', revoked_at = @now
		WHERE tenant_id = @tenant AND sponsor_identity_id = @sponsor_identity_id AND status = 'active'`)

	sponsorCandidates = tq("identities.sponsor_candidates", `
		SELECT `+identityCols+` FROM identities i WHERE i.tenant_id = @tenant AND i.type = 'human' AND i.status = 'active'
			AND EXISTS (SELECT 1 FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = i.id)
			AND (@pattern = '' OR lower(i.name) LIKE @pattern ESCAPE '\')
		ORDER BY lower(i.name), i.id LIMIT @limit`)
	identityKnownByEmail = tq("identities.known_by_email", `
		SELECT (SELECT count(*) FROM identities i WHERE i.tenant_id = @tenant AND lower(i.email) = @email)
			+ (SELECT count(*) FROM identity_identifiers x WHERE x.tenant_id = @tenant AND x.type = 'email'
				AND x.status = 'active' AND x.value_norm = @email)
			+ (SELECT count(*) FROM platform_users u WHERE u.tenant_id = @tenant AND lower(u.email) = @email)`)
)

func scanRegistration(s scanner) (*Registration, error) {
	var r Registration
	var given, family, email, purpose, by, intake sql.NullString
	var ident sql.NullInt64
	var starts, ends, expires, created nullTime
	var decided, redactAfter, redacted nullTime
	if err := s.Scan(&r.ID, &r.SponsorIdentityID, &r.Via, &given, &family, &email, &purpose, &r.EmailHMAC, &starts, &ends,
		&r.Status, &expires, &by, &decided, &ident, &intake, &redactAfter, &redacted, &created); err != nil {
		return nil, err
	}
	r.GivenName, r.FamilyName, r.Email, r.Purpose, r.DecidedBy, r.IntakeID = strp(given), strp(family), strp(email), strp(purpose), strp(by), strp(intake)
	r.IdentityID = intp(ident)
	var err error
	if r.StartsAt, err = starts.val(); err != nil {
		return nil, err
	}
	if r.EndsAt, err = ends.val(); err != nil {
		return nil, err
	}
	if r.ExpiresAt, err = expires.val(); err != nil {
		return nil, err
	}
	if r.DecidedAt, err = decided.ptr(); err != nil {
		return nil, err
	}
	if r.RedactAfter, err = redactAfter.ptr(); err != nil {
		return nil, err
	}
	if r.RedactedAt, err = redacted.ptr(); err != nil {
		return nil, err
	}
	r.CreatedAt, err = created.val()
	return &r, err
}

// InsertRegistration records a pending request.
func (tx *TenantTx) InsertRegistration(r *Registration) error {
	_, err := tx.exec(regInsert, sql.Named("id", r.ID), sql.Named("sponsor_identity_id", r.SponsorIdentityID), sql.Named("via", r.Via),
		sql.Named("given_name", SP(r.GivenName)), sql.Named("family_name", SP(r.FamilyName)), sql.Named("email", SP(r.Email)),
		sql.Named("purpose", SP(r.Purpose)), sql.Named("email_hmac", r.EmailHMAC), sql.Named("starts_at", T(r.StartsAt)),
		sql.Named("ends_at", T(r.EndsAt)), sql.Named("expires_at", T(r.ExpiresAt)), sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// Registration returns one request (ErrNotFound for another tenant's).
func (tx *TenantTx) Registration(id string) (*Registration, error) {
	return one(tx, scanRegistration, regGet, sql.Named("id", id))
}

// RegistrationsForSponsor lists a sponsor's requests, oldest first; status ""
// means every status.
func (tx *TenantTx) RegistrationsForSponsor(sponsorIdentityID int64, status string) ([]*Registration, error) {
	return collect(tx, scanRegistration, regForSponsor, sql.Named("sponsor_identity_id", sponsorIdentityID), sql.Named("status", status))
}

// HasPendingRegistration reports whether the sponsor already has a pending
// request from this address (by its keyed hash).
func (tx *TenantTx) HasPendingRegistration(sponsorIdentityID int64, emailHMAC string) (bool, error) {
	n, err := tx.count(regHasPending, sql.Named("sponsor_identity_id", sponsorIdentityID), sql.Named("email_hmac", emailHMAC))
	return n > 0, err
}

// DueRegistrations lists the pending requests whose time has passed.
func (tx *TenantTx) DueRegistrations(now time.Time) ([]*Registration, error) {
	return collect(tx, scanRegistration, regDue, sql.Named("now", T(now)))
}

// DecideRegistration moves a pending request to approved, denied or expired,
// once (ErrNotFound when it is not pending). redactAfter is when its personal
// data is reduced.
func (tx *TenantTx) DecideRegistration(id, status string, by *string, identityID *int64, intakeID *string, redactAfter, now time.Time) error {
	var ident any
	if identityID != nil {
		ident = *identityID
	}
	res, err := tx.exec(regDecide, sql.Named("id", id), sql.Named("status", status), sql.Named("decided_by", SP(by)),
		sql.Named("identity_id", ident), sql.Named("intake_id", SP(intakeID)), sql.Named("redact_after", T(redactAfter)),
		sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// RedactRegistration reduces a decided request to a tombstone now.
func (tx *TenantTx) RedactRegistration(id string, now time.Time) error {
	res, err := tx.exec(regRedact, sql.Named("id", id), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// RedactDueRegistrations reduces the decided requests past their retention and
// returns how many.
func (tx *TenantTx) RedactDueRegistrations(now time.Time) (int, error) {
	res, err := tx.exec(regRedactDue, sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// RegistrationsHoldingData counts the requests that still hold personal data.
func (tx *TenantTx) RegistrationsHoldingData() (int, error) { return tx.count(regHoldingData) }

// InsertSponsorCode records a sponsor's code by its keyed hash.
func (tx *TenantTx) InsertSponsorCode(c *SponsorCode) error {
	_, err := tx.exec(codeInsert, sql.Named("id", c.ID), sql.Named("sponsor_identity_id", c.SponsorIdentityID),
		sql.Named("code_hash", c.CodeHash), sql.Named("expires_at", T(c.ExpiresAt)), sql.Named("created_at", T(c.CreatedAt)))
	return err
}

// SponsorCodeByHash returns the active, unexpired code with this hash
// (ErrNotFound otherwise; the caller never says which).
func (tx *TenantTx) SponsorCodeByHash(hash string, now time.Time) (*SponsorCode, error) {
	return one(tx, scanSponsorCode, codeByHash, sql.Named("code_hash", hash), sql.Named("now", T(now)))
}

// RevokeSponsorCodes revokes a sponsor's active codes and returns how many.
func (tx *TenantTx) RevokeSponsorCodes(sponsorIdentityID int64, now time.Time) (int, error) {
	res, err := tx.exec(codeRevoke, sql.Named("sponsor_identity_id", sponsorIdentityID), sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func scanSponsorCode(s scanner) (*SponsorCode, error) {
	var c SponsorCode
	var expires, created nullTime
	if err := s.Scan(&c.ID, &c.SponsorIdentityID, &c.CodeHash, &c.Status, &expires, &created); err != nil {
		return nil, err
	}
	var err error
	if c.ExpiresAt, err = expires.val(); err != nil {
		return nil, err
	}
	c.CreatedAt, err = created.val()
	return &c, err
}

// SponsorCandidates lists the active people who sign in (so they can approve),
// whose name contains q (any when q is empty), by name, at most limit. The
// sponsor policy then decides who may sponsor.
func (tx *TenantTx) SponsorCandidates(q string, limit int) ([]*Identity, error) {
	pattern := ""
	if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
		pattern = "%" + esc.Replace(q) + "%"
	}
	return collect(tx, scanIdentity, sponsorCandidates, sql.Named("pattern", pattern), sql.Named("limit", limit))
}

// IdentityKnownByEmail reports whether a person, an identifier or a sign-in
// user of the tenant carries this normalized (lower-case) address.
func (tx *TenantTx) IdentityKnownByEmail(email string) (bool, error) {
	n, err := tx.count(identityKnownByEmail, sql.Named("email", strings.ToLower(email)))
	return n > 0, err
}
