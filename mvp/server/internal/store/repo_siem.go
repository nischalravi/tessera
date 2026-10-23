package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// SIEM sinks (schema/0210_siem.sql, issue #169).

// SiemSink is a push destination for the tenant's audit ledger.
type SiemSink struct {
	ID              string
	Name            string
	Kind            string // syslog | webhook | s3
	Format          string // json | ocsf
	Target          string // host:port, the webhook URL, or the bucket URL with its key prefix
	Flavor          string // webhook: hec | json
	CAPEM           *string
	SecretSealed    []byte
	IncludeHTTP     bool
	EventFilter     []string // audit actions or prefixes (grant.revoke, auth.*); empty: every event
	Region          string   // s3: the signing region
	AccessKeyID     string   // s3: the access key id (the secret is SecretSealed)
	Enabled         bool
	CursorSeq       int64
	Attempts        int // consecutive failed attempts of the current batch
	NextAttemptAt   *time.Time
	LastError       *string
	LastSuccessAt   *time.Time
	DeliveredCount  int64
	DeadLetterCount int64
	CreatedBy       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SiemDeadLetter is a batch a sink rejected for good.
type SiemDeadLetter struct {
	ID        string
	SinkID    string
	FromSeq   int64
	ToSeq     int64
	Events    int
	Error     string
	CreatedAt time.Time
}

const siemSinkCols = `s.id, s.name, s.kind, s.format, s.target, s.flavor, s.ca_pem, s.secret_sealed, s.include_http, s.enabled,
	s.event_filter, s.region, s.access_key_id, s.cursor_seq, s.attempts, s.next_attempt_at, s.last_error, s.last_success_at, s.delivered_count, s.dead_letter_count,
	s.created_by, s.created_at, s.updated_at`

var (
	siemSinksList = tq("siem_sinks.list", `
		SELECT `+siemSinkCols+` FROM siem_sinks s WHERE s.tenant_id = @tenant ORDER BY s.name, s.id`)
	siemSinksGet = tq("siem_sinks.get", `
		SELECT `+siemSinkCols+` FROM siem_sinks s WHERE s.tenant_id = @tenant AND s.id = @id`)
	siemSinksInsert = tq("siem_sinks.insert", `
		INSERT INTO siem_sinks (id, tenant_id, name, kind, format, target, flavor, ca_pem, secret_sealed, include_http, enabled,
			event_filter, region, access_key_id, cursor_seq, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @kind, @format, @target, @flavor, @ca_pem, @secret, @include_http, @enabled,
			@event_filter, @region, @access_key_id, @cursor_seq, @created_by, @created_at, @updated_at)`)
	siemSinksUpdate = tq("siem_sinks.update", `
		UPDATE siem_sinks SET name = @name, format = @format, target = @target, flavor = @flavor, ca_pem = @ca_pem,
			secret_sealed = @secret, include_http = @include_http, enabled = @enabled, updated_at = @updated_at,
			event_filter = @event_filter, region = @region, access_key_id = @access_key_id, attempts = 0, next_attempt_at = NULL
		WHERE tenant_id = @tenant AND id = @id`)
	siemSinksAck = tq("siem_sinks.ack", `
		UPDATE siem_sinks SET cursor_seq = @to, attempts = 0, next_attempt_at = NULL, last_error = NULL,
			last_success_at = @at, delivered_count = delivered_count + @n
		WHERE tenant_id = @tenant AND id = @id AND cursor_seq = @from`)
	siemSinksFail = tq("siem_sinks.fail", `
		UPDATE siem_sinks SET attempts = @attempts, next_attempt_at = @next, last_error = @error
		WHERE tenant_id = @tenant AND id = @id AND cursor_seq = @from`)
	siemSinksSkip = tq("siem_sinks.skip", `
		UPDATE siem_sinks SET cursor_seq = @to, attempts = 0, next_attempt_at = NULL, last_error = @error,
			dead_letter_count = dead_letter_count + @n
		WHERE tenant_id = @tenant AND id = @id AND cursor_seq = @from`)
	siemSinksSetCursor = tq("siem_sinks.set_cursor", `
		UPDATE siem_sinks SET cursor_seq = @seq, attempts = 0, next_attempt_at = NULL, last_error = NULL, updated_at = @at
		WHERE tenant_id = @tenant AND id = @id`)
	siemDeadLettersInsert = tq("siem_dead_letters.insert", `
		INSERT INTO siem_dead_letters (id, tenant_id, sink_id, from_seq, to_seq, events, error, created_at)
		VALUES (@id, @tenant, @sink_id, @from_seq, @to_seq, @events, @error, @created_at)`)
	siemPendingCount = tq("audit_events.count_pending", `
		SELECT count(e.id) FROM audit_events e WHERE e.tenant_id = @tenant AND e.seq > @seq
			AND (@http = 1 OR e.action <> 'http.request')`)
	siemDeadLettersList = tq("siem_dead_letters.list", `
		SELECT d.id, d.sink_id, d.from_seq, d.to_seq, d.events, d.error, d.created_at FROM siem_dead_letters d
		WHERE d.tenant_id = @tenant AND d.sink_id = @sink_id ORDER BY d.created_at DESC, d.id LIMIT 100`)
)

func scanSiemSink(s scanner) (*SiemSink, error) {
	var k SiemSink
	var ca, lastErr, by sql.NullString
	var filter string
	var next, lastOK, created, updated nullTime
	if err := s.Scan(&k.ID, &k.Name, &k.Kind, &k.Format, &k.Target, &k.Flavor, &ca, &k.SecretSealed, &k.IncludeHTTP, &k.Enabled,
		&filter, &k.Region, &k.AccessKeyID, &k.CursorSeq, &k.Attempts, &next, &lastErr, &lastOK, &k.DeliveredCount, &k.DeadLetterCount, &by, &created,
		&updated); err != nil {
		return nil, err
	}
	k.CAPEM, k.LastError, k.CreatedBy = strp(ca), strp(lastErr), strp(by)
	k.EventFilter = []string{}
	if err := json.Unmarshal([]byte(filter), &k.EventFilter); err != nil {
		return nil, err
	}
	var err error
	if k.NextAttemptAt, err = next.ptr(); err != nil {
		return nil, err
	}
	if k.LastSuccessAt, err = lastOK.ptr(); err != nil {
		return nil, err
	}
	if k.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	k.UpdatedAt, err = updated.val()
	return &k, err
}

// SiemSinks lists the tenant's sinks.
func (tx *TenantTx) SiemSinks() ([]*SiemSink, error) { return collect(tx, scanSiemSink, siemSinksList) }

// SiemSink returns one sink, or ErrNotFound.
func (tx *TenantTx) SiemSink(id string) (*SiemSink, error) {
	return one(tx, scanSiemSink, siemSinksGet, sql.Named("id", id))
}

// InsertSiemSink adds a sink starting after k.CursorSeq.
func (tx *TenantTx) InsertSiemSink(k *SiemSink) error {
	_, err := tx.exec(siemSinksInsert, sql.Named("id", k.ID), sql.Named("name", k.Name), sql.Named("kind", k.Kind),
		sql.Named("format", k.Format), sql.Named("target", k.Target), sql.Named("flavor", k.Flavor), sql.Named("ca_pem", SP(k.CAPEM)),
		sql.Named("secret", k.SecretSealed), sql.Named("include_http", B(k.IncludeHTTP)), sql.Named("enabled", B(k.Enabled)),
		sql.Named("event_filter", filterJSON(k.EventFilter)), sql.Named("region", k.Region), sql.Named("access_key_id", k.AccessKeyID),
		sql.Named("cursor_seq", k.CursorSeq), sql.Named("created_by", SP(k.CreatedBy)), sql.Named("created_at", T(k.CreatedAt)),
		sql.Named("updated_at", T(k.UpdatedAt)))
	return err
}

// UpdateSiemSink replaces a sink's settings (its kind is fixed) and clears
// its backoff, so the next tick tries again at once.
func (tx *TenantTx) UpdateSiemSink(k *SiemSink) error {
	return tx.execOne(siemSinksUpdate, sql.Named("id", k.ID), sql.Named("name", k.Name), sql.Named("format", k.Format),
		sql.Named("target", k.Target), sql.Named("flavor", k.Flavor), sql.Named("ca_pem", SP(k.CAPEM)),
		sql.Named("secret", k.SecretSealed), sql.Named("include_http", B(k.IncludeHTTP)), sql.Named("enabled", B(k.Enabled)),
		sql.Named("event_filter", filterJSON(k.EventFilter)), sql.Named("region", k.Region), sql.Named("access_key_id", k.AccessKeyID),
		sql.Named("updated_at", T(k.UpdatedAt)))
}

func filterJSON(f []string) string {
	if len(f) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(f) // a []string always marshals
	return string(b)
}

// AckSiemBatch moves the cursor from `from` to `to` after the destination
// accepted n events. ErrNotFound: the cursor moved meanwhile (another worker
// or a reset), and nothing changed.
func (tx *TenantTx) AckSiemBatch(id string, from, to int64, n int, at time.Time) error {
	return tx.execOne(siemSinksAck, sql.Named("id", id), sql.Named("from", from), sql.Named("to", to), sql.Named("n", n),
		sql.Named("at", T(at)))
}

// FailSiemBatch records a failed attempt of the batch after `from`.
func (tx *TenantTx) FailSiemBatch(id string, from int64, attempts int, next time.Time, msg string) error {
	return tx.execOne(siemSinksFail, sql.Named("id", id), sql.Named("from", from), sql.Named("attempts", attempts),
		sql.Named("next", T(next)), sql.Named("error", msg))
}

// DeadLetterSiemBatch skips a rejected batch: it records the dead letter and
// moves the cursor past it.
func (tx *TenantTx) DeadLetterSiemBatch(d *SiemDeadLetter) error {
	if err := tx.execOne(siemSinksSkip, sql.Named("id", d.SinkID), sql.Named("from", d.FromSeq-1), sql.Named("to", d.ToSeq),
		sql.Named("n", d.Events), sql.Named("error", d.Error)); err != nil {
		return err
	}
	_, err := tx.exec(siemDeadLettersInsert, sql.Named("id", d.ID), sql.Named("sink_id", d.SinkID), sql.Named("from_seq", d.FromSeq),
		sql.Named("to_seq", d.ToSeq), sql.Named("events", d.Events), sql.Named("error", d.Error),
		sql.Named("created_at", T(d.CreatedAt)))
	return err
}

// SetSiemCursor moves a sink's cursor (replay from an earlier seq, or skip ahead).
func (tx *TenantTx) SetSiemCursor(id string, seq int64, at time.Time) error {
	return tx.execOne(siemSinksSetCursor, sql.Named("id", id), sql.Named("seq", seq), sql.Named("at", T(at)))
}

// SiemDeadLetters lists a sink's latest dead letters.
func (tx *TenantTx) SiemDeadLetters(sinkID string) ([]*SiemDeadLetter, error) {
	return collect(tx, func(s scanner) (*SiemDeadLetter, error) {
		var d SiemDeadLetter
		var at nullTime
		if err := s.Scan(&d.ID, &d.SinkID, &d.FromSeq, &d.ToSeq, &d.Events, &d.Error, &at); err != nil {
			return nil, err
		}
		var err error
		d.CreatedAt, err = at.val()
		return &d, err
	}, siemDeadLettersList, sql.Named("sink_id", sinkID))
}

// SiemPending counts the audit events after seq a sink would send
// (http.request only when includeHTTP).
func (tx *TenantTx) SiemPending(seq int64, includeHTTP bool) (int64, error) {
	var n int64
	err := tx.queryRow(siemPendingCount, sql.Named("seq", seq), sql.Named("http", B(includeHTTP))).Scan(&n)
	return n, err
}
