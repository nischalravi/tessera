package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Group event sinks and their dead letters (schema/0379_group_event_sinks.sql,
// issue #61, GR-18). The rules (delivery, retry, sealing) live in
// internal/groups/events/sinks; this file is only the statements, all bound to
// the transaction's tenant. A sink's cursor is its grp_event_cursors row
// ("sink:<id>"), kept with GrpCursor and SetGrpCursor.

// Sink kinds.
const (
	SinkSQS      = "sqs"
	SinkSNS      = "sns"
	SinkRabbitMQ = "rabbitmq"
	SinkKafka    = "kafka"
)

// Sink states.
const (
	SinkIdle     = "idle"     // nothing delivered yet
	SinkOK       = "ok"       // the last delivery succeeded
	SinkRetrying = "retrying" // the event after the cursor failed and will be retried
)

// Dead letter statuses.
const (
	DeadLetterDead      = "dead"
	DeadLetterRequeued  = "requeued"
	DeadLetterDelivered = "delivered"
	DeadLetterDiscarded = "discarded"
)

// GrpSink is a row of grp_event_sinks. SecretEnc is the sealed credentials
// (nil when the sink has none).
type GrpSink struct {
	ID               string
	Name             string
	Kind             string
	Enabled          bool
	Config           json.RawMessage
	EventTypes       []string
	SecretEnc        []byte
	State            string
	Attempts         int
	NextAttemptAt    *time.Time
	LastError        string
	LastDeliveredSeq int64
	LastDeliveredAt  *time.Time
	DeliveredCount   int64
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// GrpSinkHealth is the delivery state a runner records after a pass.
type GrpSinkHealth struct {
	State         string
	Attempts      int
	NextAttemptAt *time.Time
	LastError     string
	// Delivered is how many events this pass delivered; LastDeliveredSeq and
	// LastDeliveredAt are set only when it is above 0.
	Delivered        int64
	LastDeliveredSeq int64
	LastDeliveredAt  time.Time
}

// GrpDeadLetter is a row of grp_sink_dead_letters.
type GrpDeadLetter struct {
	SinkID    string
	Seq       int64
	EventType string
	ObjectID  string
	Payload   string
	Attempts  int
	LastError string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

const sinkCols = `s.id, s.name, s.kind, s.enabled, s.config, s.event_types, s.secret_enc, s.state, s.attempts, s.next_attempt_at,
	s.last_error, s.last_delivered_seq, s.last_delivered_at, s.delivered_count, s.created_by, s.created_at, s.updated_at`

const deadCols = `d.sink_id, d.seq, d.event_type, d.object_id, d.payload, d.attempts, d.last_error, d.status, d.created_at, d.updated_at`

var (
	sinkInsert = tq("grp_event_sinks.insert", `
		INSERT INTO grp_event_sinks (id, tenant_id, name, kind, enabled, config, event_types, secret_enc, state, attempts,
			last_error, last_delivered_seq, delivered_count, created_by, created_at, updated_at)
		VALUES (@id, @tenant, @name, @kind, @enabled, @config, @event_types, @secret_enc, 'idle', 0, '', 0, 0, @created_by, @now, @now)`)
	sinkGet  = tq("grp_event_sinks.get", `SELECT `+sinkCols+` FROM grp_event_sinks s WHERE s.tenant_id = @tenant AND s.id = @id`)
	sinkList = tq("grp_event_sinks.list", `SELECT `+sinkCols+` FROM grp_event_sinks s WHERE s.tenant_id = @tenant ORDER BY s.name, s.id`)
	// a new configuration starts afresh: the retry state of the old one is cleared
	sinkUpdate = tq("grp_event_sinks.update", `
		UPDATE grp_event_sinks SET name = @name, enabled = @enabled, config = @config, event_types = @event_types,
			secret_enc = @secret_enc, state = 'idle', attempts = 0, next_attempt_at = NULL, last_error = '', updated_at = @now
		WHERE tenant_id = @tenant AND id = @id`)
	sinkHealth = tq("grp_event_sinks.health", `
		UPDATE grp_event_sinks SET state = @state, attempts = @attempts, next_attempt_at = @next_attempt_at, last_error = @last_error,
			delivered_count = delivered_count + @delivered,
			last_delivered_seq = CASE WHEN @delivered > 0 THEN @last_seq ELSE last_delivered_seq END,
			last_delivered_at = CASE WHEN @delivered > 0 THEN @last_at ELSE last_delivered_at END
		WHERE tenant_id = @tenant AND id = @id`)
	sinkDelete       = tq("grp_event_sinks.delete", `DELETE FROM grp_event_sinks WHERE tenant_id = @tenant AND id = @id`)
	sinkDeleteDead   = tq("grp_sink_dead_letters.delete_of_sink", `DELETE FROM grp_sink_dead_letters WHERE tenant_id = @tenant AND sink_id = @sink_id`)
	sinkDeleteCursor = tq("grp_event_cursors.delete", `DELETE FROM grp_event_cursors WHERE tenant_id = @tenant AND consumer = @consumer`)

	deadInsert = tq("grp_sink_dead_letters.insert", `
		INSERT INTO grp_sink_dead_letters (tenant_id, sink_id, seq, event_type, object_id, payload, attempts, last_error, status,
			created_at, updated_at)
		VALUES (@tenant, @sink_id, @seq, @event_type, @object_id, @payload, @attempts, @last_error, 'dead', @now, @now)
		ON CONFLICT (tenant_id, sink_id, seq) DO NOTHING`)
	deadGet  = tq("grp_sink_dead_letters.get", `SELECT `+deadCols+` FROM grp_sink_dead_letters d WHERE d.tenant_id = @tenant AND d.sink_id = @sink_id AND d.seq = @seq`)
	deadList = tq("grp_sink_dead_letters.list", `SELECT `+deadCols+` FROM grp_sink_dead_letters d
		WHERE d.tenant_id = @tenant AND d.sink_id = @sink_id AND (@status = '' OR d.status = @status)
		ORDER BY d.seq LIMIT @limit`)
	deadCount = tq("grp_sink_dead_letters.count", `SELECT count(*) FROM grp_sink_dead_letters d
		WHERE d.tenant_id = @tenant AND d.sink_id = @sink_id AND d.status = @status`)
	deadSet = tq("grp_sink_dead_letters.set_status", `
		UPDATE grp_sink_dead_letters SET status = @status, attempts = @attempts, last_error = @last_error, updated_at = @now
		WHERE tenant_id = @tenant AND sink_id = @sink_id AND seq = @seq`)
)

func scanSink(s scanner) (*GrpSink, error) {
	var k GrpSink
	var enabled int
	var cfg, types, next, delivered sql.NullString
	var created, updated string
	if err := s.Scan(&k.ID, &k.Name, &k.Kind, &enabled, &cfg, &types, &k.SecretEnc, &k.State, &k.Attempts, &next, &k.LastError,
		&k.LastDeliveredSeq, &delivered, &k.DeliveredCount, &k.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	k.Enabled = enabled == 1
	k.Config = json.RawMessage(cfg.String)
	if types.String != "" {
		if err := json.Unmarshal([]byte(types.String), &k.EventTypes); err != nil {
			return nil, err
		}
	}
	var err error
	if k.NextAttemptAt, err = rtp(next); err != nil {
		return nil, err
	}
	if k.LastDeliveredAt, err = rtp(delivered); err != nil {
		return nil, err
	}
	if k.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	k.UpdatedAt, err = ParseRT(updated)
	return &k, err
}

func scanDeadLetter(s scanner) (*GrpDeadLetter, error) {
	var d GrpDeadLetter
	var created, updated string
	if err := s.Scan(&d.SinkID, &d.Seq, &d.EventType, &d.ObjectID, &d.Payload, &d.Attempts, &d.LastError, &d.Status, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if d.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	d.UpdatedAt, err = ParseRT(updated)
	return &d, err
}

func sinkEventTypes(types []string) (string, error) {
	if types == nil {
		types = []string{}
	}
	b, err := json.Marshal(types)
	return string(b), err
}

// InsertGrpSink adds a sink. k.ID must be set (a UUID).
func (tx *TenantTx) InsertGrpSink(k *GrpSink) error {
	types, err := sinkEventTypes(k.EventTypes)
	if err != nil {
		return err
	}
	_, err = tx.exec(sinkInsert, sql.Named("id", k.ID), sql.Named("name", k.Name), sql.Named("kind", k.Kind),
		sql.Named("enabled", B(k.Enabled)), sql.Named("config", string(k.Config)), sql.Named("event_types", types),
		sql.Named("secret_enc", k.SecretEnc), sql.Named("created_by", k.CreatedBy), sql.Named("now", RT(k.CreatedAt)))
	return err
}

// GrpSink returns a sink or ErrNotFound (another tenant's sink is not found).
func (tx *TenantTx) GrpSink(id string) (*GrpSink, error) {
	return one(tx, scanSink, sinkGet, sql.Named("id", id))
}

// GrpSinks lists the tenant's sinks by name.
func (tx *TenantTx) GrpSinks() ([]*GrpSink, error) { return collect(tx, scanSink, sinkList) }

// UpdateGrpSink replaces a sink's name, switch, configuration, filter and
// sealed credentials, and clears its retry state. ErrNotFound if it does not exist.
func (tx *TenantTx) UpdateGrpSink(k *GrpSink, now time.Time) error {
	types, err := sinkEventTypes(k.EventTypes)
	if err != nil {
		return err
	}
	return tx.execOne(sinkUpdate, sql.Named("id", k.ID), sql.Named("name", k.Name), sql.Named("enabled", B(k.Enabled)),
		sql.Named("config", string(k.Config)), sql.Named("event_types", types), sql.Named("secret_enc", k.SecretEnc),
		sql.Named("now", RT(now)))
}

// SetGrpSinkHealth records what a delivery pass did. ErrNotFound if the sink does not exist.
func (tx *TenantTx) SetGrpSinkHealth(id string, h GrpSinkHealth) error {
	var next any
	if h.NextAttemptAt != nil {
		next = RT(*h.NextAttemptAt)
	}
	return tx.execOne(sinkHealth, sql.Named("id", id), sql.Named("state", h.State), sql.Named("attempts", h.Attempts),
		sql.Named("next_attempt_at", next), sql.Named("last_error", h.LastError), sql.Named("delivered", h.Delivered),
		sql.Named("last_seq", h.LastDeliveredSeq), sql.Named("last_at", RT(h.LastDeliveredAt)))
}

// DeleteGrpSink removes a sink with its dead letters and its cursor.
func (tx *TenantTx) DeleteGrpSink(id string) error {
	if _, err := tx.exec(sinkDeleteDead, sql.Named("sink_id", id)); err != nil {
		return err
	}
	if _, err := tx.exec(sinkDeleteCursor, sql.Named("consumer", "sink:"+id)); err != nil {
		return err
	}
	return tx.execOne(sinkDelete, sql.Named("id", id))
}

// InsertGrpDeadLetter records an undeliverable event (a repeat of the same seq is ignored).
func (tx *TenantTx) InsertGrpDeadLetter(d *GrpDeadLetter) error {
	_, err := tx.exec(deadInsert, sql.Named("sink_id", d.SinkID), sql.Named("seq", d.Seq), sql.Named("event_type", d.EventType),
		sql.Named("object_id", d.ObjectID), sql.Named("payload", d.Payload), sql.Named("attempts", d.Attempts),
		sql.Named("last_error", d.LastError), sql.Named("now", RT(d.CreatedAt)))
	return err
}

// GrpDeadLetter returns one dead letter or ErrNotFound.
func (tx *TenantTx) GrpDeadLetter(sinkID string, seq int64) (*GrpDeadLetter, error) {
	return one(tx, scanDeadLetter, deadGet, sql.Named("sink_id", sinkID), sql.Named("seq", seq))
}

// GrpDeadLetters lists a sink's dead letters oldest first, of one status ("" for all).
func (tx *TenantTx) GrpDeadLetters(sinkID, status string, limit int) ([]*GrpDeadLetter, error) {
	return collect(tx, scanDeadLetter, deadList, sql.Named("sink_id", sinkID), sql.Named("status", status), sql.Named("limit", limit))
}

// CountGrpDeadLetters counts a sink's dead letters of one status.
func (tx *TenantTx) CountGrpDeadLetters(sinkID, status string) (int64, error) {
	var n int64
	err := tx.queryRow(deadCount, sql.Named("sink_id", sinkID), sql.Named("status", status)).Scan(&n)
	return n, err
}

// SetGrpDeadLetterStatus moves a dead letter to a status. ErrNotFound if it does not exist.
func (tx *TenantTx) SetGrpDeadLetterStatus(sinkID string, seq int64, status string, attempts int, lastError string, now time.Time) error {
	return tx.execOne(deadSet, sql.Named("sink_id", sinkID), sql.Named("seq", seq), sql.Named("status", status),
		sql.Named("attempts", attempts), sql.Named("last_error", lastError), sql.Named("now", RT(now)))
}
