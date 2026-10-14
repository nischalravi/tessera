package store

import (
	"database/sql"
	"time"
)

// Shared Signals receiver (schema/0207_ssf.sql). Secrets are sealed by
// internal/ssf; the store only holds the sealed bytes.

// SSF transmitter statuses and delivery methods.
const (
	SSFEnabled  = "enabled"
	SSFPaused   = "paused"
	SSFDisabled = "disabled"

	SSFPush = "push"
	SSFPoll = "poll"
)

// SSF event statuses.
const (
	SSFEventReceived  = "received"  // validated and recorded, not yet processed
	SSFEventMatched   = "matched"   // the subject resolved to an identity, actions not yet done
	SSFEventActioned  = "actioned"  // every kill-switch step ran (failed steps were queued for retry)
	SSFEventNoAction  = "no_action" // matched, but the identity has no other account to contain
	SSFEventUnmatched = "unmatched" // the subject did not resolve to an identity
	SSFEventIgnored   = "ignored"   // an event Tessera does not act on (unknown type, verification)
	SSFEventFailed    = "failed"    // an action failed (a retry task holds it)
)

// SSFTransmitter is one transmitter a tenant accepts events from.
type SSFTransmitter struct {
	ID                      string
	Name                    string
	Issuer                  string
	Audience                string
	JWKSURL                 string
	JWKSInline              string
	Delivery                string
	PollURL                 string
	VerificationURL         string
	SecretEnc               []byte
	APITokenEnc             []byte
	SubjectSystem           string
	ConnectionID            *string
	Status                  string
	LastEventAt             *time.Time
	LastError               string
	LastErrorAt             *time.Time
	LastPolledAt            *time.Time
	PendingAcks             string // JSON array of jti
	PendingErrs             string // JSON object jti -> {err, description}
	VerificationState       string
	VerificationRequestedAt *time.Time
	VerifiedAt              *time.Time
	CreatedBy               string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// SSFEvent is one accepted SET and what became of it.
type SSFEvent struct {
	ID            string
	TransmitterID string
	JTI           string
	Via           string
	EventType     string
	SubjectFormat string
	Subject       string
	IdentityID    *int64
	AccountID     *int64
	Status        string
	Outcome       string
	Steps         int
	StepsFailed   int
	ReceivedAt    time.Time
	IATAt         time.Time
	ActionedAt    *time.Time
	LatencyMS     *int64
	IATLatencyMS  *int64
}

const ssfTransmitterCols = `x.id, x.name, x.issuer, x.audience, x.jwks_url, x.jwks_inline, x.delivery, x.poll_url,
	x.verification_url, x.secret_enc, x.api_token_enc, x.subject_system, x.connection_id, x.status, x.last_event_at,
	x.last_error, x.last_error_at, x.last_polled_at, x.pending_acks, x.pending_errs, x.verification_state,
	x.verification_requested_at, x.verified_at, x.created_by, x.created_at, x.updated_at`

const ssfEventCols = `e.id, e.transmitter_id, e.jti, e.via, e.event_type, e.subject_format, e.subject, e.identity_id,
	e.account_id, e.status, e.outcome, e.steps, e.steps_failed, e.received_at, e.iat_at, e.actioned_at, e.latency_ms,
	e.iat_latency_ms`

var (
	ssfTransmitterInsert = tq("ssf_transmitters.insert", `
		INSERT INTO ssf_transmitters (id, tenant_id, name, issuer, audience, jwks_url, jwks_inline, delivery, poll_url,
			verification_url, secret_enc, api_token_enc, subject_system, connection_id, status, pending_acks, pending_errs,
			created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @issuer, @audience, @jwks_url, @jwks_inline, @delivery, @poll_url, @verification_url,
			@secret_enc, @api_token_enc, @subject_system, @connection_id, @status, '[]', '{}', @created_by, @now, @now)`)
	ssfTransmitterGet = tq("ssf_transmitters.get", `
		SELECT `+ssfTransmitterCols+` FROM ssf_transmitters x WHERE x.tenant_id = @tenant AND x.id = @id`)
	ssfTransmitterList = tq("ssf_transmitters.list", `
		SELECT `+ssfTransmitterCols+` FROM ssf_transmitters x WHERE x.tenant_id = @tenant ORDER BY x.name, x.id`)
	ssfTransmitterUpdate = tq("ssf_transmitters.update", `
		UPDATE ssf_transmitters SET name = @name, issuer = @issuer, audience = @audience, jwks_url = @jwks_url,
			jwks_inline = @jwks_inline, delivery = @delivery, poll_url = @poll_url, verification_url = @verification_url,
			secret_enc = @secret_enc, api_token_enc = @api_token_enc, subject_system = @subject_system,
			connection_id = @connection_id, status = @status, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterDelete = tq("ssf_transmitters.delete", `
		DELETE FROM ssf_transmitters WHERE tenant_id = @tenant AND id = @id`)
	ssfEventsDeleteFor = tq("ssf_events.delete_for_transmitter", `
		DELETE FROM ssf_events WHERE tenant_id = @tenant AND transmitter_id = @transmitter_id`)
	ssfTransmitterSeen = tq("ssf_transmitters.seen", `
		UPDATE ssf_transmitters SET last_event_at = @at WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterErr = tq("ssf_transmitters.error", `
		UPDATE ssf_transmitters SET last_error = @error, last_error_at = @at WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterClearErr = tq("ssf_transmitters.clear_error", `
		UPDATE ssf_transmitters SET last_error = '', last_error_at = NULL WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterPoll = tq("ssf_transmitters.poll_state", `
		UPDATE ssf_transmitters SET pending_acks = @pending_acks, pending_errs = @pending_errs, last_polled_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterVerifyReq = tq("ssf_transmitters.verification_requested", `
		UPDATE ssf_transmitters SET verification_state = @state, verification_requested_at = @at, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	ssfTransmitterVerified = tq("ssf_transmitters.verified", `
		UPDATE ssf_transmitters SET verification_state = '', verified_at = @at, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)

	ssfEventInsert = tq("ssf_events.insert", `
		INSERT INTO ssf_events (id, tenant_id, transmitter_id, jti, via, event_type, subject_format, subject, status,
			outcome, received_at, iat_at)
		VALUES (@id, @tenant, @transmitter_id, @jti, @via, @event_type, @subject_format, @subject, 'received', '',
			@received_at, @iat_at)`)
	ssfEventByJTI = tq("ssf_events.by_jti", `
		SELECT `+ssfEventCols+` FROM ssf_events e
		WHERE e.tenant_id = @tenant AND e.transmitter_id = @transmitter_id AND e.jti = @jti`)
	ssfEventGet = tq("ssf_events.get", `
		SELECT `+ssfEventCols+` FROM ssf_events e WHERE e.tenant_id = @tenant AND e.id = @id`)
	ssfEventsRecent = tq("ssf_events.recent", `
		SELECT `+ssfEventCols+` FROM ssf_events e
		WHERE e.tenant_id = @tenant AND (@transmitter_id = '' OR e.transmitter_id = @transmitter_id)
		ORDER BY e.received_at DESC, e.rowid DESC LIMIT @limit`)
	ssfEventUpdate = tq("ssf_events.update", `
		UPDATE ssf_events SET identity_id = @identity_id, account_id = @account_id, status = @status, outcome = @outcome,
			steps = @steps, steps_failed = @steps_failed, actioned_at = @actioned_at, latency_ms = @latency_ms,
			iat_latency_ms = @iat_latency_ms
		WHERE tenant_id = @tenant AND id = @id`)

	accountsByExternalID = tq("accounts.by_system_external_id", `
		SELECT `+accountCols+` FROM accounts a
		WHERE a.tenant_id = @tenant AND a.system = @system AND a.external_id = @external_id ORDER BY a.id LIMIT 10`)
	accountsByLogin = tq("accounts.by_system_login", `
		SELECT `+accountCols+` FROM accounts a
		WHERE a.tenant_id = @tenant AND a.system = @system AND (lower(a.username) = lower(@login)
			OR a.identity_id IN (SELECT i.id FROM identities i WHERE i.tenant_id = @tenant AND lower(i.email) = lower(@login)))
		ORDER BY a.id LIMIT 10`)
)

func scanSSFTransmitter(s scanner) (*SSFTransmitter, error) {
	var x SSFTransmitter
	var conn sql.NullString
	var lastEvent, lastErr, polled, vreq, verified sql.NullString
	var created, updated string
	if err := s.Scan(&x.ID, &x.Name, &x.Issuer, &x.Audience, &x.JWKSURL, &x.JWKSInline, &x.Delivery, &x.PollURL,
		&x.VerificationURL, &x.SecretEnc, &x.APITokenEnc, &x.SubjectSystem, &conn, &x.Status, &lastEvent, &x.LastError,
		&lastErr, &polled, &x.PendingAcks, &x.PendingErrs, &x.VerificationState, &vreq, &verified, &x.CreatedBy,
		&created, &updated); err != nil {
		return nil, err
	}
	x.ConnectionID = strp(conn)
	var err error
	for _, p := range []struct {
		n   sql.NullString
		dst **time.Time
	}{{lastEvent, &x.LastEventAt}, {lastErr, &x.LastErrorAt}, {polled, &x.LastPolledAt}, {vreq, &x.VerificationRequestedAt},
		{verified, &x.VerifiedAt}} {
		if *p.dst, err = rtp(p.n); err != nil {
			return nil, err
		}
	}
	if x.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	x.UpdatedAt, err = ParseRT(updated)
	return &x, err
}

func scanSSFEvent(s scanner) (*SSFEvent, error) {
	var e SSFEvent
	var ident, acct, latency, iatLatency sql.NullInt64
	var received, iat string
	var actioned sql.NullString
	if err := s.Scan(&e.ID, &e.TransmitterID, &e.JTI, &e.Via, &e.EventType, &e.SubjectFormat, &e.Subject, &ident, &acct,
		&e.Status, &e.Outcome, &e.Steps, &e.StepsFailed, &received, &iat, &actioned, &latency, &iatLatency); err != nil {
		return nil, err
	}
	e.IdentityID, e.AccountID, e.LatencyMS, e.IATLatencyMS = intp(ident), intp(acct), intp(latency), intp(iatLatency)
	var err error
	if e.ReceivedAt, err = ParseRT(received); err != nil {
		return nil, err
	}
	if e.IATAt, err = ParseRT(iat); err != nil {
		return nil, err
	}
	e.ActionedAt, err = rtp(actioned)
	return &e, err
}

// InsertSSFTransmitter adds a transmitter (x.ID is set when empty). ErrDuplicate
// when the tenant has a transmitter with that name.
func (tx *TenantTx) InsertSSFTransmitter(x *SSFTransmitter, now time.Time) error {
	if x.ID == "" {
		x.ID = NewID()
	}
	_, err := tx.exec(ssfTransmitterInsert, sql.Named("id", x.ID), sql.Named("name", x.Name),
		sql.Named("issuer", x.Issuer), sql.Named("audience", x.Audience), sql.Named("jwks_url", x.JWKSURL),
		sql.Named("jwks_inline", x.JWKSInline), sql.Named("delivery", x.Delivery), sql.Named("poll_url", x.PollURL),
		sql.Named("verification_url", x.VerificationURL), sql.Named("secret_enc", x.SecretEnc),
		sql.Named("api_token_enc", x.APITokenEnc), sql.Named("subject_system", x.SubjectSystem),
		sql.Named("connection_id", SP(x.ConnectionID)), sql.Named("status", x.Status),
		sql.Named("created_by", x.CreatedBy), sql.Named("now", RT(now)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// SSFTransmitter returns one transmitter or ErrNotFound.
func (tx *TenantTx) SSFTransmitter(id string) (*SSFTransmitter, error) {
	return one(tx, scanSSFTransmitter, ssfTransmitterGet, sql.Named("id", id))
}

// SSFTransmitters lists the tenant's transmitters by name.
func (tx *TenantTx) SSFTransmitters() ([]*SSFTransmitter, error) {
	return collect(tx, scanSSFTransmitter, ssfTransmitterList)
}

// UpdateSSFTransmitter replaces a transmitter's configuration (ErrNotFound for
// another tenant's id, ErrDuplicate for a taken name).
func (tx *TenantTx) UpdateSSFTransmitter(x *SSFTransmitter, now time.Time) error {
	err := tx.execOne(ssfTransmitterUpdate, sql.Named("id", x.ID), sql.Named("name", x.Name),
		sql.Named("issuer", x.Issuer), sql.Named("audience", x.Audience), sql.Named("jwks_url", x.JWKSURL),
		sql.Named("jwks_inline", x.JWKSInline), sql.Named("delivery", x.Delivery), sql.Named("poll_url", x.PollURL),
		sql.Named("verification_url", x.VerificationURL), sql.Named("secret_enc", x.SecretEnc),
		sql.Named("api_token_enc", x.APITokenEnc), sql.Named("subject_system", x.SubjectSystem),
		sql.Named("connection_id", SP(x.ConnectionID)), sql.Named("status", x.Status), sql.Named("now", RT(now)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return crossTenant(err)
}

// DeleteSSFTransmitter removes a transmitter and its events (ErrNotFound for
// another tenant's id). The audit ledger keeps the history.
func (tx *TenantTx) DeleteSSFTransmitter(id string) error {
	if _, err := tx.exec(ssfEventsDeleteFor, sql.Named("transmitter_id", id)); err != nil {
		return err
	}
	return tx.execOne(ssfTransmitterDelete, sql.Named("id", id))
}

// TouchSSFTransmitter records that an event arrived at at.
func (tx *TenantTx) TouchSSFTransmitter(id string, at time.Time) error {
	return tx.execOne(ssfTransmitterSeen, sql.Named("id", id), sql.Named("at", RT(at)))
}

// SetSSFTransmitterError records the last error of a transmitter ("" clears it).
func (tx *TenantTx) SetSSFTransmitterError(id, msg string, at time.Time) error {
	if msg == "" {
		return tx.execOne(ssfTransmitterClearErr, sql.Named("id", id))
	}
	return tx.execOne(ssfTransmitterErr, sql.Named("id", id), sql.Named("error", msg), sql.Named("at", RT(at)))
}

// SetSSFPollState stores what the next poll sends (acks, setErrs) and when the
// last poll ran.
func (tx *TenantTx) SetSSFPollState(id, pendingAcks, pendingErrs string, at time.Time) error {
	return tx.execOne(ssfTransmitterPoll, sql.Named("id", id), sql.Named("pending_acks", pendingAcks),
		sql.Named("pending_errs", pendingErrs), sql.Named("at", RT(at)))
}

// SetSSFVerificationRequested records the state of a verification request sent to the transmitter.
func (tx *TenantTx) SetSSFVerificationRequested(id, state string, at time.Time) error {
	return tx.execOne(ssfTransmitterVerifyReq, sql.Named("id", id), sql.Named("state", state), sql.Named("at", RT(at)))
}

// SetSSFVerified records that the transmitter's verification event arrived.
func (tx *TenantTx) SetSSFVerified(id string, at time.Time) error {
	return tx.execOne(ssfTransmitterVerified, sql.Named("id", id), sql.Named("at", RT(at)))
}

// InsertSSFEvent records a validated SET (status received). ErrDuplicate when
// the transmitter already delivered the jti: that is the replay check.
func (tx *TenantTx) InsertSSFEvent(e *SSFEvent) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	_, err := tx.exec(ssfEventInsert, sql.Named("id", e.ID), sql.Named("transmitter_id", e.TransmitterID),
		sql.Named("jti", e.JTI), sql.Named("via", e.Via), sql.Named("event_type", e.EventType),
		sql.Named("subject_format", e.SubjectFormat), sql.Named("subject", e.Subject),
		sql.Named("received_at", RT(e.ReceivedAt)), sql.Named("iat_at", RT(e.IATAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	e.Status = SSFEventReceived
	return crossTenant(err)
}

// SSFEventByJTI returns the event a transmitter delivered with that jti, or ErrNotFound.
func (tx *TenantTx) SSFEventByJTI(transmitterID, jti string) (*SSFEvent, error) {
	return one(tx, scanSSFEvent, ssfEventByJTI, sql.Named("transmitter_id", transmitterID), sql.Named("jti", jti))
}

// SSFEvent returns one event or ErrNotFound.
func (tx *TenantTx) SSFEvent(id string) (*SSFEvent, error) {
	return one(tx, scanSSFEvent, ssfEventGet, sql.Named("id", id))
}

// SSFEvents lists the newest events, of one transmitter or (empty id) of all.
func (tx *TenantTx) SSFEvents(transmitterID string, limit int) ([]*SSFEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, scanSSFEvent, ssfEventsRecent, sql.Named("transmitter_id", transmitterID), sql.Named("limit", limit))
}

// UpdateSSFEvent stores the outcome of processing an event.
func (tx *TenantTx) UpdateSSFEvent(e *SSFEvent) error {
	var latency, iat any
	if e.LatencyMS != nil {
		latency = *e.LatencyMS
	}
	if e.IATLatencyMS != nil {
		iat = *e.IATLatencyMS
	}
	return tx.execOne(ssfEventUpdate, sql.Named("id", e.ID), sql.Named("identity_id", IP(e.IdentityID)),
		sql.Named("account_id", IP(e.AccountID)), sql.Named("status", e.Status), sql.Named("outcome", e.Outcome),
		sql.Named("steps", e.Steps), sql.Named("steps_failed", e.StepsFailed), sql.Named("actioned_at", RTP(e.ActionedAt)),
		sql.Named("latency_ms", latency), sql.Named("iat_latency_ms", iat))
}

// AccountsByExternalID returns the accounts of a system with that external id (at most 10).
func (tx *TenantTx) AccountsByExternalID(system, externalID string) ([]*Account, error) {
	return collect(tx, scanAccount, accountsByExternalID, sql.Named("system", system), sql.Named("external_id", externalID))
}

// AccountsByLogin returns the accounts of a system whose username, or whose
// identity's email, equals login (case-insensitively; at most 10).
func (tx *TenantTx) AccountsByLogin(system, login string) ([]*Account, error) {
	return collect(tx, scanAccount, accountsByLogin, sql.Named("system", system), sql.Named("login", login))
}
