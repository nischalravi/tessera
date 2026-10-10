package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// ---------------------------------------------------------------- audit ledger
//
// Appends happen only through AppendAudit, inside the caller's transaction,
// so a domain event commits or rolls back with the change it describes.
// Writers are serialized per database (DB.mu, and SQLite's single writer);
// the head row is advanced with a compare-and-set on last_seq, and the
// schema's triggers refuse any event that does not extend the head, so a race
// fails the transaction instead of forking the chain.

const auditEventCols = `e.id, e.tenant_id, e.seq, e.occurred_at, e.actor_type, e.actor_id, e.actor_display,
	e.session_id, e.client_id, e.authn, e.action, e.target_type, e.target_id, e.outcome, e.request_id, e.http,
	e.ip, e.user_agent_sha256, e.policy_version, e.detail, e.schema_version, e.prev_hash, e.hash`

const auditCheckpointCols = `c.id, c.tenant_id, c.seq, c.head_hash, c.created_at, c.jws, c.anchor_status,
	c.anchor_ref, c.anchored_at, c.anchor_attempts`

var (
	auditHeadGet = tq("audit_chain_heads.get", `
		SELECT h.last_seq, h.last_hash, h.updated_at FROM audit_chain_heads h WHERE h.tenant_id = @tenant`)
	auditHeadInsert = tq("audit_chain_heads.insert", `
		INSERT INTO audit_chain_heads (tenant_id, last_seq, last_hash, updated_at) VALUES (@tenant, 0, @hash, @at)`)
	auditHeadAdvance = tq("audit_chain_heads.advance", `
		UPDATE audit_chain_heads SET last_seq = @seq, last_hash = @hash, updated_at = @at
		WHERE tenant_id = @tenant AND last_seq = @prev_seq AND last_hash = @prev_hash`)
	auditEventInsert = tq("audit_events.insert", `
		INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, actor_id, actor_display, session_id,
			client_id, authn, action, target_type, target_id, outcome, request_id, http, ip, user_agent_sha256,
			policy_version, detail, schema_version, prev_hash, hash)
		VALUES (@id, @tenant, @seq, @occurred_at, @actor_type, @actor_id, @actor_display, @session_id,
			@client_id, @authn, @action, @target_type, @target_id, @outcome, @request_id, @http, @ip, @ua,
			@policy_version, @detail, @schema_version, @prev_hash, @hash)`)
	auditEventsFiltered = tq("audit_events.filtered", `
		SELECT `+auditEventCols+` FROM audit_events e
		WHERE e.tenant_id = @tenant
			AND (@before_seq = 0 OR e.seq < @before_seq)
			AND (@action = '' OR e.action = @action)
			AND (@include_http = 1 OR @action <> '' OR e.action <> 'http.request')
			AND (@actor_id = '' OR e.actor_id = @actor_id)
			AND (@target_type = '' OR e.target_type = @target_type)
			AND (@target_id = '' OR e.target_id = @target_id)
			AND (@from = '' OR e.occurred_at >= @from)
			AND (@to = '' OR e.occurred_at < @to)
		ORDER BY e.seq DESC LIMIT @limit`)
	auditEventsRange = tq("audit_events.range", `
		SELECT `+auditEventCols+` FROM audit_events e
		WHERE e.tenant_id = @tenant AND e.seq >= @from_seq AND (@to_seq = 0 OR e.seq <= @to_seq)
		ORDER BY e.seq, e.id LIMIT @limit`)
	auditEventByID = tq("audit_events.by_id", `
		SELECT `+auditEventCols+` FROM audit_events e WHERE e.tenant_id = @tenant AND e.id = @id`)
	auditEventBySeq = tq("audit_events.by_seq", `
		SELECT `+auditEventCols+` FROM audit_events e WHERE e.tenant_id = @tenant AND e.seq = @seq`)
	auditEventsStats = tq("audit_events.stats", `
		SELECT count(*), coalesce(min(e.seq), 0), coalesce(max(e.seq), 0) FROM audit_events e
		WHERE e.tenant_id = @tenant AND e.seq >= @from_seq AND (@to_seq = 0 OR e.seq <= @to_seq)`)

	auditCheckpointInsert = tq("audit_checkpoints.insert", `
		INSERT INTO audit_checkpoints (id, tenant_id, seq, head_hash, created_at, jws, anchor_status)
		VALUES (@id, @tenant, @seq, @head_hash, @created_at, @jws, 'pending')`)
	auditCheckpointsFrom = tq("audit_checkpoints.from_seq", `
		SELECT `+auditCheckpointCols+` FROM audit_checkpoints c
		WHERE c.tenant_id = @tenant AND c.seq >= @from_seq AND (@to_seq = 0 OR c.seq <= @to_seq)
		ORDER BY c.seq`)
	auditCheckpointLatest = tq("audit_checkpoints.latest", `
		SELECT `+auditCheckpointCols+` FROM audit_checkpoints c WHERE c.tenant_id = @tenant ORDER BY c.seq DESC LIMIT 1`)
	auditCheckpointCovering = tq("audit_checkpoints.covering", `
		SELECT `+auditCheckpointCols+` FROM audit_checkpoints c WHERE c.tenant_id = @tenant AND c.seq >= @seq
		ORDER BY c.seq LIMIT 1`)
	auditCheckpointsUnanchored = tq("audit_checkpoints.unanchored", `
		SELECT `+auditCheckpointCols+` FROM audit_checkpoints c
		WHERE c.tenant_id = @tenant AND c.anchor_status <> 'anchored' ORDER BY c.seq`)
	auditCheckpointSetAnchor = tq("audit_checkpoints.set_anchor", `
		UPDATE audit_checkpoints SET anchor_status = @status, anchor_ref = @ref, anchored_at = @at,
			anchor_attempts = anchor_attempts + 1
		WHERE tenant_id = @tenant AND id = @id`)
)

// ErrAuditDetail is returned for a detail object the ledger refuses (floats,
// unsupported types, oversize); see canon.Detail.
var ErrAuditDetail = canon.ErrDetail

// AuditHead returns the tenant's chain head; before the first event it is
// seq 0 with the genesis hash (not yet stored).
func (tx *TenantTx) AuditHead() (AuditChainHead, error) {
	h := AuditChainHead{TenantID: tx.tenant}
	var at string
	err := tx.queryRow(auditHeadGet).Scan(&h.LastSeq, &h.LastHash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		h.LastHash = canon.Genesis(tx.tenant.String())
		return h, nil
	}
	if err != nil {
		return h, err
	}
	h.UpdatedAt, err = canon.ParseTime(at)
	return h, err
}

// AppendAudit appends e to the transaction's tenant chain: it assigns the id
// (when unset), seq, prev_hash, schema version and hash, inserts the event and
// advances the head, all in this transaction. e.TenantID must be zero or the
// transaction's tenant.
func (tx *TenantTx) AppendAudit(e AuditEvent) (AuditEvent, error) {
	if tx.readOnly {
		return e, ErrReadOnly
	}
	if err := tx.own(e.TenantID); err != nil {
		return e, err
	}
	e.TenantID = tx.tenant
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = nowUTC()
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	if e.Outcome == "" {
		e.Outcome = OutcomeSuccess
	}
	if e.ActorType == "" {
		return e, errors.New("store: audit event without an actor type")
	}
	detail := e.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	var err error
	if e.Detail, err = canon.DetailJSON(detail); err != nil {
		return e, err
	}
	for _, raw := range []json.RawMessage{e.Authn, e.HTTP} {
		if len(raw) > 0 && !json.Valid(raw) {
			return e, errors.New("store: audit authn/http is not valid JSON")
		}
	}
	e.SchemaVersion = canon.Version

	var headAt string
	var lastSeq int64
	var lastHash string
	switch err := tx.queryRow(auditHeadGet).Scan(&lastSeq, &lastHash, &headAt); {
	case errors.Is(err, sql.ErrNoRows):
		lastHash = canon.Genesis(tx.tenant.String())
		if _, err := tx.exec(auditHeadInsert, sql.Named("hash", lastHash), sql.Named("at", canon.FormatTime(e.OccurredAt))); err != nil {
			return e, fmt.Errorf("store: audit head: %w", err)
		}
	case err != nil:
		return e, fmt.Errorf("store: audit head: %w", err)
	}
	e.Seq, e.PrevHash = lastSeq+1, lastHash
	if e.Hash, err = AuditEventHash(&e); err != nil {
		return e, err
	}
	if _, err := tx.exec(auditEventInsert,
		sql.Named("id", e.ID.String()), sql.Named("seq", e.Seq), sql.Named("occurred_at", canon.FormatTime(e.OccurredAt)),
		sql.Named("actor_type", e.ActorType), sql.Named("actor_id", e.ActorID), sql.Named("actor_display", e.ActorDisplay),
		sql.Named("session_id", e.SessionID), sql.Named("client_id", e.ClientID), sql.Named("authn", rawOrNil(e.Authn)),
		sql.Named("action", e.Action), sql.Named("target_type", e.TargetType), sql.Named("target_id", e.TargetID),
		sql.Named("outcome", e.Outcome), sql.Named("request_id", e.RequestID), sql.Named("http", rawOrNil(e.HTTP)),
		sql.Named("ip", e.IP), sql.Named("ua", e.UserAgentSHA256), sql.Named("policy_version", e.PolicyVersion),
		sql.Named("detail", string(e.Detail)), sql.Named("schema_version", e.SchemaVersion),
		sql.Named("prev_hash", e.PrevHash), sql.Named("hash", e.Hash)); err != nil {
		return e, fmt.Errorf("store: audit append: %w", err)
	}
	res, err := tx.exec(auditHeadAdvance, sql.Named("seq", e.Seq), sql.Named("hash", e.Hash),
		sql.Named("at", canon.FormatTime(e.OccurredAt)), sql.Named("prev_seq", lastSeq), sql.Named("prev_hash", lastHash))
	if err != nil {
		return e, fmt.Errorf("store: audit head: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return e, fmt.Errorf("store: audit head moved during append (rows=%d): %v", n, err)
	}
	return e, nil
}

func rawOrNil(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return string(r)
}

// RecordAudit appends a domain event. The actor comes from the transaction's
// context (AuditContext); only without one (system jobs, seeding, the CLI) is
// r.LegacyActor used, as a system actor. With a context whose actor is not
// the system, a LegacyActor other than "system" is kept as
// detail.claimed_actor: it may come from a request body or header, so it is
// recorded but never trusted.
func (tx *TenantTx) RecordAudit(r AuditRecord) (AuditEvent, error) {
	e := AuditEvent{OccurredAt: r.At, Action: r.Action, Outcome: r.Outcome,
		TargetType: strPtr(r.TargetType), TargetID: strPtr(r.TargetID), PolicyVersion: strPtr(r.PolicyVersion)}
	detail, err := canon.Detail(r.Detail)
	if err != nil {
		return e, fmt.Errorf("%s: %w", r.Action, err)
	}
	if ac, ok := AuditContextFrom(tx.ctx); ok {
		e.ActorType, e.ActorID, e.ActorDisplay = ac.Actor.Type, ac.Actor.ID, ac.Actor.Display
		e.SessionID, e.ClientID, e.Authn = ac.SessionID, ac.ClientID, ac.Authn
		e.RequestID, e.IP, e.UserAgentSHA256 = ac.RequestID, ac.IP, ac.UAHash
		if ac.Actor.Type != ActorSystem && r.LegacyActor != "" && r.LegacyActor != ActorSystem {
			if detail, err = withClaimedActor(detail, r.LegacyActor); err != nil {
				return e, err
			}
		}
	} else {
		actor := r.LegacyActor
		if actor == "" {
			actor = ActorSystem
		}
		e.ActorType, e.ActorID, e.ActorDisplay = ActorSystem, &actor, &actor
	}
	e.Detail = detail
	return tx.AppendAudit(e)
}

func withClaimedActor(detail json.RawMessage, claimed string) (json.RawMessage, error) {
	v, err := ojson.Decode(detail)
	if err != nil {
		return nil, err
	}
	obj, _ := v.(ojson.Object)
	if _, exists := obj.Get("claimed_actor"); exists {
		return detail, nil
	}
	return canon.Detail(append(obj, ojson.KV{Key: "claimed_actor", Value: claimed}))
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Audit is the MVP audit helper, kept with the same call shape for existing
// callers: it appends a domain event to the ledger in this transaction (see
// RecordAudit for how the actor is chosen). now is the event time.
func (tx *TenantTx) Audit(now time.Time, actor, action string, detail ojson.Object) error {
	_, err := tx.RecordAudit(AuditRecord{At: now, Action: action, LegacyActor: actor, Detail: detail})
	return err
}

// AuditLog returns the newest events first, every action included (limit <= 0:
// all).
func (tx *TenantTx) AuditLog(limit int) ([]*AuditEvent, error) {
	return tx.AuditEvents(AuditFilter{Limit: limit, IncludeHTTP: true})
}

// AuditEvents returns the events matching f, newest first.
func (tx *TenantTx) AuditEvents(f AuditFilter) ([]*AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = -1
	}
	inc := 0
	if f.IncludeHTTP {
		inc = 1
	}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return canon.FormatTime(t)
	}
	return collect(tx, scanAuditEvent, auditEventsFiltered, sql.Named("before_seq", f.BeforeSeq),
		sql.Named("action", f.Action), sql.Named("include_http", inc), sql.Named("actor_id", f.ActorID),
		sql.Named("target_type", f.TargetType), sql.Named("target_id", f.TargetID),
		sql.Named("from", ts(f.From)), sql.Named("to", ts(f.To)), sql.Named("limit", limit))
}

// AuditEventsRange returns up to limit events with fromSeq <= seq <= toSeq
// (toSeq 0: no upper bound), in seq order. Duplicated seqs (impossible
// without tampering) are all returned.
func (tx *TenantTx) AuditEventsRange(fromSeq, toSeq int64, limit int) ([]*AuditEvent, error) {
	if limit <= 0 {
		limit = -1
	}
	return collect(tx, scanAuditEvent, auditEventsRange, sql.Named("from_seq", fromSeq), sql.Named("to_seq", toSeq),
		sql.Named("limit", limit))
}

// AuditEventStats counts the events in [fromSeq, toSeq] and returns their
// lowest and highest seq.
func (tx *TenantTx) AuditEventStats(fromSeq, toSeq int64) (n int64, first, last int64, err error) {
	err = tx.queryRow(auditEventsStats, sql.Named("from_seq", fromSeq), sql.Named("to_seq", toSeq)).Scan(&n, &first, &last)
	return n, first, last, err
}

// AuditEvent returns one event by id; ErrNotFound for another tenant's.
func (tx *TenantTx) AuditEvent(id uuid.UUID) (*AuditEvent, error) {
	return one(tx, scanAuditEvent, auditEventByID, sql.Named("id", id.String()))
}

// AuditEventBySeq returns the event at seq; ErrNotFound when there is none.
func (tx *TenantTx) AuditEventBySeq(seq int64) (*AuditEvent, error) {
	return one(tx, scanAuditEvent, auditEventBySeq, sql.Named("seq", seq))
}

func scanAuditEvent(s scanner) (*AuditEvent, error) {
	var e AuditEvent
	var id, tid, at string
	var authn, httpj sql.NullString
	var detail string
	if err := s.Scan(&id, &tid, &e.Seq, &at, &e.ActorType, &e.ActorID, &e.ActorDisplay, &e.SessionID, &e.ClientID,
		&authn, &e.Action, &e.TargetType, &e.TargetID, &e.Outcome, &e.RequestID, &httpj, &e.IP, &e.UserAgentSHA256,
		&e.PolicyVersion, &detail, &e.SchemaVersion, &e.PrevHash, &e.Hash); err != nil {
		return nil, err
	}
	var err error
	if e.ID, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("store: audit event id: %w", err)
	}
	if e.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if e.OccurredAt, err = canon.ParseTime(at); err != nil {
		return nil, fmt.Errorf("store: audit event time: %w", err)
	}
	if authn.Valid {
		e.Authn = json.RawMessage(authn.String)
	}
	if httpj.Valid {
		e.HTTP = json.RawMessage(httpj.String)
	}
	e.Detail = json.RawMessage(detail)
	return &e, nil
}

// ---------------------------------------------------------------- checkpoints

// InsertAuditCheckpoint stores a signed checkpoint (anchor pending). The
// schema refuses one whose (seq, head_hash) is not an event of this tenant.
func (tx *TenantTx) InsertAuditCheckpoint(c AuditCheckpoint) (AuditCheckpoint, error) {
	if err := tx.own(c.TenantID); err != nil {
		return c, err
	}
	c.TenantID = tx.tenant
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = nowUTC()
	}
	c.CreatedAt = c.CreatedAt.UTC().Truncate(time.Microsecond)
	c.AnchorStatus = AnchorPending
	_, err := tx.exec(auditCheckpointInsert, sql.Named("id", c.ID.String()), sql.Named("seq", c.Seq),
		sql.Named("head_hash", c.HeadHash), sql.Named("created_at", canon.FormatTime(c.CreatedAt)), sql.Named("jws", c.JWS))
	return c, err
}

// AuditCheckpoints returns the checkpoints with fromSeq <= seq <= toSeq (toSeq
// 0: no upper bound), in seq order.
func (tx *TenantTx) AuditCheckpoints(fromSeq, toSeq int64) ([]*AuditCheckpoint, error) {
	return collect(tx, scanAuditCheckpoint, auditCheckpointsFrom, sql.Named("from_seq", fromSeq), sql.Named("to_seq", toSeq))
}

// LatestAuditCheckpoint returns the newest checkpoint; ErrNotFound when there is none.
func (tx *TenantTx) LatestAuditCheckpoint() (*AuditCheckpoint, error) {
	return one(tx, scanAuditCheckpoint, auditCheckpointLatest)
}

// CoveringAuditCheckpoint returns the first checkpoint at or after seq;
// ErrNotFound when the event is newer than every checkpoint.
func (tx *TenantTx) CoveringAuditCheckpoint(seq int64) (*AuditCheckpoint, error) {
	return one(tx, scanAuditCheckpoint, auditCheckpointCovering, sql.Named("seq", seq))
}

// UnanchoredAuditCheckpoints returns the pending and failed checkpoints.
func (tx *TenantTx) UnanchoredAuditCheckpoints() ([]*AuditCheckpoint, error) {
	return collect(tx, scanAuditCheckpoint, auditCheckpointsUnanchored)
}

// SetAuditCheckpointAnchor records an anchoring attempt (status anchored or
// failed). Only the anchor columns can change; the schema refuses the rest.
func (tx *TenantTx) SetAuditCheckpointAnchor(id uuid.UUID, status string, ref *string, at time.Time) error {
	if status != AnchorAnchored && status != AnchorFailed {
		return fmt.Errorf("store: anchor status %q", status)
	}
	var anchoredAt any
	if status == AnchorAnchored {
		anchoredAt = canon.FormatTime(at)
	}
	res, err := tx.exec(auditCheckpointSetAnchor, sql.Named("status", status), sql.Named("ref", ref),
		sql.Named("at", anchoredAt), sql.Named("id", id.String()))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrNotFound
	}
	return nil
}

func scanAuditCheckpoint(s scanner) (*AuditCheckpoint, error) {
	var c AuditCheckpoint
	var id, tid, created string
	var anchoredAt sql.NullString
	if err := s.Scan(&id, &tid, &c.Seq, &c.HeadHash, &created, &c.JWS, &c.AnchorStatus, &c.AnchorRef, &anchoredAt,
		&c.AnchorAttempts); err != nil {
		return nil, err
	}
	var err error
	if c.ID, err = uuid.Parse(id); err != nil {
		return nil, err
	}
	if c.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = canon.ParseTime(created); err != nil {
		return nil, err
	}
	if anchoredAt.Valid {
		t, err := canon.ParseTime(anchoredAt.String)
		if err != nil {
			return nil, err
		}
		c.AnchoredAt = &t
	}
	return &c, nil
}
