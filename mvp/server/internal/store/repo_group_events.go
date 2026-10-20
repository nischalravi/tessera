package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Group event outbox and point-in-time repository (schema/0285_group_events.sql).
// The rules of events and history live in internal/groups/events and
// internal/groups/pit; this file is only their statements, all bound to the
// transaction's tenant. Like repo_group_engine.go it avoids CTEs, UNION and
// RETURNING.

const evCols = `e.seq, e.type, e.object_type, e.object_id, e.identity_id, e.member_group_id, e.list_id, e.data,
	e.cause_type, e.cause_ref, e.audit_seq, e.occurred_at`

const pitObjCols = `p.object_type, p.object_id, p.snapshot, p.start_at, p.end_at, p.start_seq, p.end_seq`
const pitDirCols = `p.group_id, p.list_id, p.member_type, p.member_key, p.member_identity_id, p.member_group_id, p.source,
	p.enabled_from, p.disabled_at, p.start_at, p.end_at, p.start_seq, p.end_seq`
const pitEffCols = `p.group_id, p.list_id, p.identity_id, p.start_at, p.end_at, p.start_seq, p.end_seq`
const pitPrivCols = `p.privilege_id, p.snapshot, p.start_at, p.end_at, p.start_seq, p.end_seq`
const digestCols = `d.day, d.first_seq, d.last_seq, d.event_count, d.merkle_root, d.audit_seq, d.created_at`

var (
	// ---- events and cursors
	grpHeadBump = tq("grp_events.head_bump", `UPDATE grp_event_heads SET last_seq = last_seq + 1 WHERE tenant_id = @tenant`)
	grpHeadNew  = tq("grp_events.head_new", `INSERT INTO grp_event_heads (tenant_id, last_seq, pruned_seq) VALUES (@tenant, 0, 0)
		ON CONFLICT (tenant_id) DO NOTHING`)
	grpHeadGet = tq("grp_events.head_get", `SELECT h.last_seq, h.pruned_seq FROM grp_event_heads h WHERE h.tenant_id = @tenant`)
	grpHeadSet = tq("grp_events.head_set_pruned", `UPDATE grp_event_heads SET pruned_seq = @pruned_seq WHERE tenant_id = @tenant`)

	grpEventInsert = tq("grp_events.insert", `
		INSERT INTO grp_events (tenant_id, seq, type, object_type, object_id, identity_id, member_group_id, list_id, data,
			cause_type, cause_ref, audit_seq, occurred_at)
		VALUES (@tenant, @seq, @type, @object_type, @object_id, @identity_id, @member_group_id, @list_id, @data,
			@cause_type, @cause_ref, @audit_seq, @occurred_at)`)
	grpEventsAfter = tq("grp_events.after", `SELECT `+evCols+` FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.seq > @after AND e.seq <= @upto ORDER BY e.seq LIMIT @limit`)
	grpEventsOfObject = tq("grp_events.of_object", `SELECT `+evCols+` FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.object_type = @object_type AND e.object_id = @object_id AND e.seq > @after
		ORDER BY e.seq LIMIT @limit`)
	grpEventsOfDay = tq("grp_events.of_day", `SELECT `+evCols+` FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.occurred_at >= @from AND e.occurred_at < @to AND e.seq > @after
		ORDER BY e.seq LIMIT @limit`)
	grpEventsFirstAtOrAfter = tq("grp_events.first_at_or_after", `SELECT MIN(e.seq) FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.occurred_at >= @at`)
	grpEventsDelete = tq("grp_events.delete_upto", `DELETE FROM grp_events WHERE tenant_id = @tenant AND seq <= @upto`)
	grpEventsDays   = tq("grp_events.days", `SELECT DISTINCT substr(e.occurred_at, 1, 10) FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.occurred_at >= @from AND e.occurred_at < @to ORDER BY 1`)
	grpEventGroups = tq("grp_events.group_ids", `SELECT DISTINCT e.object_id FROM grp_events e
		WHERE e.tenant_id = @tenant AND e.object_type = 'group' AND e.object_id > @after ORDER BY e.object_id LIMIT @limit`)

	grpCursorGet = tq("grp_cursors.get", `SELECT c.last_seq FROM grp_event_cursors c WHERE c.tenant_id = @tenant AND c.consumer = @consumer`)
	grpCursorSet = tq("grp_cursors.set", `INSERT INTO grp_event_cursors (tenant_id, consumer, last_seq, updated_at)
		VALUES (@tenant, @consumer, @last_seq, @updated_at)
		ON CONFLICT (tenant_id, consumer) DO UPDATE SET last_seq = @last_seq, updated_at = @updated_at`)

	// ---- point in time: writes
	pitObjOpen = tq("grp_pit_objects.open", `INSERT INTO grp_pit_objects (tenant_id, object_type, object_id, snapshot, start_at, start_seq)
		VALUES (@tenant, @object_type, @object_id, @snapshot, @start_at, @start_seq)`)
	pitObjClose = tq("grp_pit_objects.close", `UPDATE grp_pit_objects SET end_at = @end_at, end_seq = @end_seq
		WHERE tenant_id = @tenant AND object_type = @object_type AND object_id = @object_id AND end_seq IS NULL`)
	pitDirOpen = tq("grp_pit_direct.open", `INSERT INTO grp_pit_direct (tenant_id, group_id, list_id, member_type, member_key,
			member_identity_id, member_group_id, source, enabled_from, disabled_at, start_at, start_seq)
		VALUES (@tenant, @group_id, @list_id, @member_type, @member_key, @member_identity_id, @member_group_id, @source,
			@enabled_from, @disabled_at, @start_at, @start_seq)`)
	pitDirClose = tq("grp_pit_direct.close", `UPDATE grp_pit_direct SET end_at = @end_at, end_seq = @end_seq
		WHERE tenant_id = @tenant AND group_id = @group_id AND list_id = @list_id AND member_type = @member_type
		  AND member_key = @member_key AND end_seq IS NULL`)
	pitEffOpen = tq("grp_pit_effective.open", `INSERT INTO grp_pit_effective (tenant_id, group_id, list_id, identity_id, start_at, start_seq)
		VALUES (@tenant, @group_id, @list_id, @identity_id, @start_at, @start_seq)`)
	pitEffClose = tq("grp_pit_effective.close", `UPDATE grp_pit_effective SET end_at = @end_at, end_seq = @end_seq
		WHERE tenant_id = @tenant AND group_id = @group_id AND list_id = @list_id AND identity_id = @identity_id AND end_seq IS NULL`)
	pitPrivOpen = tq("grp_pit_privileges.open", `INSERT INTO grp_pit_privileges (tenant_id, privilege_id, snapshot, start_at, start_seq)
		VALUES (@tenant, @privilege_id, @snapshot, @start_at, @start_seq)`)
	pitPrivClose = tq("grp_pit_privileges.close", `UPDATE grp_pit_privileges SET end_at = @end_at, end_seq = @end_seq
		WHERE tenant_id = @tenant AND privilege_id = @privilege_id AND end_seq IS NULL`)

	// ---- point in time: whole-table scopes (rebuild, retention, comparison)
	pitObjDelete  = tq("grp_pit_objects.delete_of", `DELETE FROM grp_pit_objects WHERE tenant_id = @tenant AND (@object_id = '' OR object_id = @object_id)`)
	pitDirDelete  = tq("grp_pit_direct.delete_of", `DELETE FROM grp_pit_direct WHERE tenant_id = @tenant AND (@group_id = '' OR group_id = @group_id)`)
	pitEffDelete  = tq("grp_pit_effective.delete_of", `DELETE FROM grp_pit_effective WHERE tenant_id = @tenant AND (@group_id = '' OR group_id = @group_id)`)
	pitPrivDelete = tq("grp_pit_privileges.delete_all", `DELETE FROM grp_pit_privileges WHERE tenant_id = @tenant`)
	pitObjList    = tq("grp_pit_objects.list", `SELECT `+pitObjCols+` FROM grp_pit_objects p
		WHERE p.tenant_id = @tenant AND (@object_id = '' OR p.object_id = @object_id) ORDER BY p.object_type, p.object_id, p.start_seq`)
	pitDirList = tq("grp_pit_direct.list", `SELECT `+pitDirCols+` FROM grp_pit_direct p
		WHERE p.tenant_id = @tenant AND (@group_id = '' OR p.group_id = @group_id)
		ORDER BY p.group_id, p.list_id, p.member_type, p.member_key, p.start_seq`)
	pitEffList = tq("grp_pit_effective.list", `SELECT `+pitEffCols+` FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND (@group_id = '' OR p.group_id = @group_id)
		ORDER BY p.group_id, p.list_id, p.identity_id, p.start_seq`)
	pitPrivList = tq("grp_pit_privileges.list", `SELECT `+pitPrivCols+` FROM grp_pit_privileges p
		WHERE p.tenant_id = @tenant ORDER BY p.privilege_id, p.start_seq`)
	pitObjCountBefore = tq("grp_pit_objects.count_before", `SELECT count(*) FROM grp_pit_objects p
		WHERE p.tenant_id = @tenant AND (@object_id = '' OR p.object_id = @object_id) AND p.start_seq <= @seq`)
	pitDirCountBefore = tq("grp_pit_direct.count_before", `SELECT count(*) FROM grp_pit_direct p
		WHERE p.tenant_id = @tenant AND (@group_id = '' OR p.group_id = @group_id) AND p.start_seq <= @seq`)
	pitEffCountBefore = tq("grp_pit_effective.count_before", `SELECT count(*) FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND (@group_id = '' OR p.group_id = @group_id) AND p.start_seq <= @seq`)
	pitPrivCountBefore = tq("grp_pit_privileges.count_before", `SELECT count(*) FROM grp_pit_privileges p
		WHERE p.tenant_id = @tenant AND p.start_seq <= @seq`)
	pitObjPrune = tq("grp_pit_objects.prune", `DELETE FROM grp_pit_objects
		WHERE tenant_id = @tenant AND end_at IS NOT NULL AND end_at < @before AND end_seq <= @max_seq`)
	pitDirPrune = tq("grp_pit_direct.prune", `DELETE FROM grp_pit_direct
		WHERE tenant_id = @tenant AND end_at IS NOT NULL AND end_at < @before AND end_seq <= @max_seq`)
	pitEffPrune = tq("grp_pit_effective.prune", `DELETE FROM grp_pit_effective
		WHERE tenant_id = @tenant AND end_at IS NOT NULL AND end_at < @before AND end_seq <= @max_seq`)
	pitPrivPrune = tq("grp_pit_privileges.prune", `DELETE FROM grp_pit_privileges
		WHERE tenant_id = @tenant AND end_at IS NOT NULL AND end_at < @before AND end_seq <= @max_seq`)

	// ---- point in time: queries (an interval [start_at, end_at) meets the window [@from, @to];
	// an interval that ended where it began held nothing at any instant)
	pitObjAt = tq("grp_pit_objects.at", `SELECT `+pitObjCols+` FROM grp_pit_objects p
		WHERE p.tenant_id = @tenant AND p.object_type = @object_type AND p.object_id = @object_id
		  AND p.start_at <= @at AND (p.end_at IS NULL OR p.end_at > @at) ORDER BY p.start_seq DESC LIMIT 1`)
	pitEffIn = tq("grp_pit_effective.in", `SELECT `+pitEffCols+` FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND p.group_id = @group_id AND p.list_id = @list_id
		  AND p.start_at <= @to AND (p.end_at IS NULL OR (p.end_at > @from AND p.end_at > p.start_at))
		ORDER BY p.identity_id, p.start_seq LIMIT @limit OFFSET @offset`)
	pitEffInCount = tq("grp_pit_effective.in_count", `SELECT count(DISTINCT p.identity_id) FROM grp_pit_effective p
		WHERE p.tenant_id = @tenant AND p.group_id = @group_id AND p.list_id = @list_id
		  AND p.start_at <= @to AND (p.end_at IS NULL OR (p.end_at > @from AND p.end_at > p.start_at))`)
	pitDirIn = tq("grp_pit_direct.in", `SELECT `+pitDirCols+` FROM grp_pit_direct p
		WHERE p.tenant_id = @tenant AND p.group_id = @group_id AND p.list_id = @list_id
		  AND p.start_at <= @to AND (p.end_at IS NULL OR (p.end_at > @from AND p.end_at > p.start_at))
		ORDER BY p.member_type, p.member_key, p.start_seq LIMIT @limit OFFSET @offset`)
	pitDirInCount = tq("grp_pit_direct.in_count", `SELECT count(*) FROM grp_pit_direct p
		WHERE p.tenant_id = @tenant AND p.group_id = @group_id AND p.list_id = @list_id
		  AND p.start_at <= @to AND (p.end_at IS NULL OR (p.end_at > @from AND p.end_at > p.start_at))`)

	// ---- digests
	digestInsert = tq("grp_pit_digests.insert", `INSERT INTO grp_pit_digests (tenant_id, day, first_seq, last_seq, event_count,
			merkle_root, audit_seq, created_at)
		VALUES (@tenant, @day, @first_seq, @last_seq, @event_count, @merkle_root, @audit_seq, @created_at)`)
	digestGet  = tq("grp_pit_digests.get", `SELECT `+digestCols+` FROM grp_pit_digests d WHERE d.tenant_id = @tenant AND d.day = @day`)
	digestList = tq("grp_pit_digests.list", `SELECT `+digestCols+` FROM grp_pit_digests d WHERE d.tenant_id = @tenant
		ORDER BY d.day DESC LIMIT @limit`)
)

// ---------------------------------------------------------------- events

func scanGrpEvent(s scanner) (*GrpEvent, error) {
	var e GrpEvent
	var ident, audit sql.NullInt64
	var grp, list, ref sql.NullString
	var data, at string
	if err := s.Scan(&e.Seq, &e.Type, &e.ObjectType, &e.ObjectID, &ident, &grp, &list, &data, &e.CauseType, &ref, &audit, &at); err != nil {
		return nil, err
	}
	e.Identity, e.AuditSeq = intp(ident), intp(audit)
	e.MemberGroup, e.List, e.CauseRef = grp.String, list.String, ref.String
	e.Data = json.RawMessage(data)
	var err error
	e.OccurredAt, err = ParseRT(at)
	return &e, err
}

// AppendGrpEvent writes e as the tenant's next event and sets e.Seq and
// e.TenantID. The counter row is bumped first, which takes the write lock, so
// concurrent writers queue and the sequence has no gaps; a transaction that
// rolls back gives its number back. Data defaults to {}.
func (tx *TenantTx) AppendGrpEvent(e *GrpEvent) error {
	if err := tx.own(e.TenantID); err != nil {
		return err
	}
	if len(e.Data) == 0 {
		e.Data = json.RawMessage("{}")
	}
	res, err := tx.exec(grpHeadBump)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.exec(grpHeadNew); err != nil {
			return err
		}
		if _, err := tx.exec(grpHeadBump); err != nil {
			return err
		}
	}
	h, err := tx.GrpEventHead()
	if err != nil {
		return err
	}
	var ident, audit any
	if e.Identity != nil {
		ident = *e.Identity
	}
	if e.AuditSeq != nil {
		audit = *e.AuditSeq
	}
	if _, err := tx.exec(grpEventInsert, sql.Named("seq", h.LastSeq), sql.Named("type", e.Type), sql.Named("object_type", e.ObjectType),
		sql.Named("object_id", e.ObjectID), sql.Named("identity_id", ident), sql.Named("member_group_id", nilIfEmpty(e.MemberGroup)),
		sql.Named("list_id", nilIfEmpty(e.List)), sql.Named("data", string(e.Data)), sql.Named("cause_type", e.CauseType),
		sql.Named("cause_ref", nilIfEmpty(e.CauseRef)), sql.Named("audit_seq", audit), sql.Named("occurred_at", RT(e.OccurredAt))); err != nil {
		return err
	}
	e.Seq, e.TenantID = h.LastSeq, tx.tenant
	return nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// GrpEventHead returns the event counter (zero values before the first event).
func (tx *TenantTx) GrpEventHead() (GrpEventHead, error) {
	var h GrpEventHead
	err := tx.queryRow(grpHeadGet).Scan(&h.LastSeq, &h.PrunedSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return GrpEventHead{}, nil
	}
	return h, err
}

// GrpEventsAfter returns up to limit events with after < seq <= upto, oldest first.
func (tx *TenantTx) GrpEventsAfter(after, upto int64, limit int) ([]*GrpEvent, error) {
	return collect(tx, scanGrpEvent, grpEventsAfter, sql.Named("after", after), sql.Named("upto", upto), sql.Named("limit", limit))
}

// GrpEventsOfObject returns up to limit events of one object with seq > after, oldest first.
func (tx *TenantTx) GrpEventsOfObject(objectType, objectID string, after int64, limit int) ([]*GrpEvent, error) {
	return collect(tx, scanGrpEvent, grpEventsOfObject, sql.Named("object_type", objectType), sql.Named("object_id", objectID),
		sql.Named("after", after), sql.Named("limit", limit))
}

// GrpEventsOfDay returns up to limit events that occurred in [from, to) with
// seq > after, oldest first: the input of a day's digest.
func (tx *TenantTx) GrpEventsOfDay(from, to time.Time, after int64, limit int) ([]*GrpEvent, error) {
	return collect(tx, scanGrpEvent, grpEventsOfDay, sql.Named("from", RT(from)), sql.Named("to", RT(to)),
		sql.Named("after", after), sql.Named("limit", limit))
}

// GrpEventDays lists the UTC days (YYYY-MM-DD) that have events in [from, to).
func (tx *TenantTx) GrpEventDays(from, to time.Time) ([]string, error) {
	rows, err := collect(tx, func(s scanner) (*string, error) {
		var d string
		err := s.Scan(&d)
		return &d, err
	}, grpEventsDays, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = *r
	}
	return out, err
}

// GrpEventGroupIDs pages the ids of the groups that have events, in id order.
func (tx *TenantTx) GrpEventGroupIDs(after string, limit int) ([]string, error) {
	rows, err := collect(tx, func(s scanner) (*string, error) {
		var d string
		err := s.Scan(&d)
		return &d, err
	}, grpEventGroups, sql.Named("after", after), sql.Named("limit", limit))
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = *r
	}
	return out, err
}

// PruneGrpEvents deletes the oldest events: those before cutoff, but never
// past seq maxSeq (the last digested event). Events go as a prefix of the
// sequence, so a later event with an earlier clock reading keeps the ones
// before it. It records the new pruned_seq and returns how many events went.
func (tx *TenantTx) PruneGrpEvents(cutoff time.Time, maxSeq int64) (int64, error) {
	h, err := tx.GrpEventHead()
	if err != nil {
		return 0, err
	}
	upto := h.LastSeq
	var first sql.NullInt64
	if err := tx.queryRow(grpEventsFirstAtOrAfter, sql.Named("at", RT(cutoff))).Scan(&first); err != nil {
		return 0, err
	}
	if first.Valid {
		upto = first.Int64 - 1
	}
	if upto > maxSeq {
		upto = maxSeq
	}
	if upto <= h.PrunedSeq {
		return 0, nil
	}
	res, err := tx.exec(grpEventsDelete, sql.Named("upto", upto))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	_, err = tx.exec(grpHeadSet, sql.Named("pruned_seq", upto))
	return n, err
}

// GrpCursor returns a consumer's last processed seq (0 if it has none).
func (tx *TenantTx) GrpCursor(consumer string) (int64, error) {
	var n int64
	err := tx.queryRow(grpCursorGet, sql.Named("consumer", consumer)).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// SetGrpCursor records a consumer's position.
func (tx *TenantTx) SetGrpCursor(consumer string, seq int64, now time.Time) error {
	_, err := tx.exec(grpCursorSet, sql.Named("consumer", consumer), sql.Named("last_seq", seq), sql.Named("updated_at", RT(now)))
	return err
}

// ---------------------------------------------------------------- point in time: writes

func endArgs(at time.Time, seq int64) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("end_at", RT(at)), sql.Named("end_seq", seq)}
}

// OpenPitObject starts an interval of a folder's or group's snapshot.
func (tx *TenantTx) OpenPitObject(objectType, objectID string, snapshot json.RawMessage, at time.Time, seq int64) error {
	_, err := tx.exec(pitObjOpen, sql.Named("object_type", objectType), sql.Named("object_id", objectID),
		sql.Named("snapshot", string(snapshot)), sql.Named("start_at", RT(at)), sql.Named("start_seq", seq))
	return err
}

// ClosePitObject ends the open interval of an object, if there is one.
func (tx *TenantTx) ClosePitObject(objectType, objectID string, at time.Time, seq int64) error {
	_, err := tx.exec(pitObjClose, append(endArgs(at, seq), sql.Named("object_type", objectType), sql.Named("object_id", objectID))...)
	return err
}

// OpenPitDirect starts an interval of a direct membership row.
func (tx *TenantTx) OpenPitDirect(p PitDirect) error {
	var ident any
	if p.Identity != nil {
		ident = *p.Identity
	}
	_, err := tx.exec(pitDirOpen, sql.Named("group_id", p.Group), sql.Named("list_id", p.List),
		sql.Named("member_type", string(p.MemberType)), sql.Named("member_key", p.MemberKey), sql.Named("member_identity_id", ident),
		sql.Named("member_group_id", nilIfEmpty(p.MemberGroup)), sql.Named("source", p.Source),
		sql.Named("enabled_from", RTP(p.EnabledFrom)), sql.Named("disabled_at", RTP(p.DisabledAt)),
		sql.Named("start_at", RT(p.StartAt)), sql.Named("start_seq", p.StartSeq))
	return err
}

// ClosePitDirect ends the open interval of a direct membership row.
func (tx *TenantTx) ClosePitDirect(group, list string, typ MemberType, key string, at time.Time, seq int64) error {
	_, err := tx.exec(pitDirClose, append(endArgs(at, seq), sql.Named("group_id", group), sql.Named("list_id", list),
		sql.Named("member_type", string(typ)), sql.Named("member_key", key))...)
	return err
}

// OpenPitEffective starts an interval of an effective membership.
func (tx *TenantTx) OpenPitEffective(group, list string, identity int64, at time.Time, seq int64) error {
	_, err := tx.exec(pitEffOpen, sql.Named("group_id", group), sql.Named("list_id", list), sql.Named("identity_id", identity),
		sql.Named("start_at", RT(at)), sql.Named("start_seq", seq))
	return err
}

// ClosePitEffective ends the open interval of an effective membership.
func (tx *TenantTx) ClosePitEffective(group, list string, identity int64, at time.Time, seq int64) error {
	_, err := tx.exec(pitEffClose, append(endArgs(at, seq), sql.Named("group_id", group), sql.Named("list_id", list),
		sql.Named("identity_id", identity))...)
	return err
}

// OpenPitPrivilege starts an interval of a privilege grant.
func (tx *TenantTx) OpenPitPrivilege(privilegeID string, snapshot json.RawMessage, at time.Time, seq int64) error {
	_, err := tx.exec(pitPrivOpen, sql.Named("privilege_id", privilegeID), sql.Named("snapshot", string(snapshot)),
		sql.Named("start_at", RT(at)), sql.Named("start_seq", seq))
	return err
}

// ClosePitPrivilege ends the open interval of a privilege grant.
func (tx *TenantTx) ClosePitPrivilege(privilegeID string, at time.Time, seq int64) error {
	_, err := tx.exec(pitPrivClose, append(endArgs(at, seq), sql.Named("privilege_id", privilegeID))...)
	return err
}

// DeleteGrpPit empties the derived PIT tables so they can be rebuilt from the
// events: group "" for every table of the tenant, otherwise that group's
// object, direct and effective intervals.
func (tx *TenantTx) DeleteGrpPit(group string) error {
	if _, err := tx.exec(pitObjDelete, sql.Named("object_id", group)); err != nil {
		return err
	}
	if _, err := tx.exec(pitDirDelete, sql.Named("group_id", group)); err != nil {
		return err
	}
	if _, err := tx.exec(pitEffDelete, sql.Named("group_id", group)); err != nil {
		return err
	}
	if group == "" {
		_, err := tx.exec(pitPrivDelete)
		return err
	}
	return nil
}

// PruneGrpPit deletes the intervals that ended before cutoff, by an event no
// later than maxSeq (the last digested one), and returns how many.
func (tx *TenantTx) PruneGrpPit(cutoff time.Time, maxSeq int64) (PitTotals, error) {
	var t PitTotals
	for _, p := range []struct {
		s tstmt
		n *int64
	}{{pitObjPrune, &t.Objects}, {pitDirPrune, &t.Direct}, {pitEffPrune, &t.Effective}, {pitPrivPrune, &t.Privileges}} {
		res, err := tx.exec(p.s, sql.Named("before", RT(cutoff)), sql.Named("max_seq", maxSeq))
		if err != nil {
			return t, err
		}
		if *p.n, err = res.RowsAffected(); err != nil {
			return t, err
		}
	}
	return t, nil
}

// GrpPitStartedBefore counts the PIT intervals of a scope (group "" is the
// whole tenant) that began at or before seq: a rebuild from the events cannot
// recreate them once the events are pruned.
func (tx *TenantTx) GrpPitStartedBefore(group string, seq int64) (PitTotals, error) {
	var t PitTotals
	var err error
	if t.Objects, err = tx.count64(pitObjCountBefore, sql.Named("object_id", group), sql.Named("seq", seq)); err != nil {
		return t, err
	}
	if t.Direct, err = tx.count64(pitDirCountBefore, sql.Named("group_id", group), sql.Named("seq", seq)); err != nil {
		return t, err
	}
	if t.Effective, err = tx.count64(pitEffCountBefore, sql.Named("group_id", group), sql.Named("seq", seq)); err != nil {
		return t, err
	}
	if group == "" {
		t.Privileges, err = tx.count64(pitPrivCountBefore, sql.Named("seq", seq))
	}
	return t, err
}

func (tx *TenantTx) count64(s tstmt, args ...sql.NamedArg) (int64, error) {
	n, err := tx.count(s, args...)
	return int64(n), err
}

// ---------------------------------------------------------------- point in time: reads

func scanPitObject(s scanner) (*PitObject, error) {
	var p PitObject
	var snap, start string
	var end sql.NullString
	var endSeq sql.NullInt64
	if err := s.Scan(&p.ObjectType, &p.ObjectID, &snap, &start, &end, &p.StartSeq, &endSeq); err != nil {
		return nil, err
	}
	p.Snapshot, p.EndSeq = json.RawMessage(snap), intp(endSeq)
	var err error
	if p.StartAt, err = ParseRT(start); err != nil {
		return nil, err
	}
	p.EndAt, err = rtp(end)
	return &p, err
}

func scanPitDirect(s scanner) (*PitDirect, error) {
	var p PitDirect
	var typ, start string
	var ident, endSeq sql.NullInt64
	var grp, from, to, end sql.NullString
	if err := s.Scan(&p.Group, &p.List, &typ, &p.MemberKey, &ident, &grp, &p.Source, &from, &to, &start, &end, &p.StartSeq, &endSeq); err != nil {
		return nil, err
	}
	p.MemberType, p.Identity, p.MemberGroup, p.EndSeq = MemberType(typ), intp(ident), grp.String, intp(endSeq)
	var err error
	if p.EnabledFrom, err = rtp(from); err != nil {
		return nil, err
	}
	if p.DisabledAt, err = rtp(to); err != nil {
		return nil, err
	}
	if p.StartAt, err = ParseRT(start); err != nil {
		return nil, err
	}
	p.EndAt, err = rtp(end)
	return &p, err
}

func scanPitEffective(s scanner) (*PitEffective, error) {
	var p PitEffective
	var start string
	var end sql.NullString
	var endSeq sql.NullInt64
	if err := s.Scan(&p.Group, &p.List, &p.Identity, &start, &end, &p.StartSeq, &endSeq); err != nil {
		return nil, err
	}
	p.EndSeq = intp(endSeq)
	var err error
	if p.StartAt, err = ParseRT(start); err != nil {
		return nil, err
	}
	p.EndAt, err = rtp(end)
	return &p, err
}

func scanPitPrivilege(s scanner) (*PitPrivilege, error) {
	var p PitPrivilege
	var snap, start string
	var end sql.NullString
	var endSeq sql.NullInt64
	if err := s.Scan(&p.PrivilegeID, &snap, &start, &end, &p.StartSeq, &endSeq); err != nil {
		return nil, err
	}
	p.Snapshot, p.EndSeq = json.RawMessage(snap), intp(endSeq)
	var err error
	if p.StartAt, err = ParseRT(start); err != nil {
		return nil, err
	}
	p.EndAt, err = rtp(end)
	return &p, err
}

// GrpPitObjectAt returns the snapshot an object had at a time, or ErrNotFound.
func (tx *TenantTx) GrpPitObjectAt(objectType, objectID string, at time.Time) (*PitObject, error) {
	return one(tx, scanPitObject, pitObjAt, sql.Named("object_type", objectType), sql.Named("object_id", objectID), sql.Named("at", RT(at)))
}

// GrpPitObjects lists the intervals of one object, or of every folder and
// group when objectID is "".
func (tx *TenantTx) GrpPitObjects(objectID string) ([]*PitObject, error) {
	return collect(tx, scanPitObject, pitObjList, sql.Named("object_id", objectID))
}

// GrpPitDirects lists the direct-membership intervals of one group, or of the
// tenant when group is "".
func (tx *TenantTx) GrpPitDirects(group string) ([]*PitDirect, error) {
	return collect(tx, scanPitDirect, pitDirList, sql.Named("group_id", group))
}

// GrpPitEffectives lists the effective-membership intervals of one group, or
// of the tenant when group is "".
func (tx *TenantTx) GrpPitEffectives(group string) ([]*PitEffective, error) {
	return collect(tx, scanPitEffective, pitEffList, sql.Named("group_id", group))
}

// GrpPitPrivileges lists every privilege interval of the tenant.
func (tx *TenantTx) GrpPitPrivileges() ([]*PitPrivilege, error) {
	return collect(tx, scanPitPrivilege, pitPrivList)
}

// GrpPitEffectiveIn returns the effective-membership intervals of a group's
// list that meet the window [from, to] (from == to asks for one instant), in
// identity order, and the number of distinct identities among them.
func (tx *TenantTx) GrpPitEffectiveIn(group, list string, from, to time.Time, limit, offset int) ([]*PitEffective, int, error) {
	args := []sql.NamedArg{sql.Named("group_id", group), sql.Named("list_id", list), sql.Named("from", RT(from)), sql.Named("to", RT(to))}
	rows, err := collect(tx, scanPitEffective, pitEffIn, append(args, sql.Named("limit", limit), sql.Named("offset", offset))...)
	if err != nil {
		return nil, 0, err
	}
	n, err := tx.count(pitEffInCount, args...)
	return rows, n, err
}

// GrpPitDirectIn is GrpPitEffectiveIn for direct membership rows; the count is
// of intervals.
func (tx *TenantTx) GrpPitDirectIn(group, list string, from, to time.Time, limit, offset int) ([]*PitDirect, int, error) {
	args := []sql.NamedArg{sql.Named("group_id", group), sql.Named("list_id", list), sql.Named("from", RT(from)), sql.Named("to", RT(to))}
	rows, err := collect(tx, scanPitDirect, pitDirIn, append(args, sql.Named("limit", limit), sql.Named("offset", offset))...)
	if err != nil {
		return nil, 0, err
	}
	n, err := tx.count(pitDirInCount, args...)
	return rows, n, err
}

// ---------------------------------------------------------------- digests

func scanDigest(s scanner) (*PitDigest, error) {
	var d PitDigest
	var at string
	if err := s.Scan(&d.Day, &d.FirstSeq, &d.LastSeq, &d.EventCount, &d.MerkleRoot, &d.AuditSeq, &at); err != nil {
		return nil, err
	}
	var err error
	d.CreatedAt, err = ParseRT(at)
	return &d, err
}

// InsertGrpDigest stores a day's digest; a second digest for a day is an error.
func (tx *TenantTx) InsertGrpDigest(d PitDigest) error {
	_, err := tx.exec(digestInsert, sql.Named("day", d.Day), sql.Named("first_seq", d.FirstSeq), sql.Named("last_seq", d.LastSeq),
		sql.Named("event_count", d.EventCount), sql.Named("merkle_root", d.MerkleRoot), sql.Named("audit_seq", d.AuditSeq),
		sql.Named("created_at", RT(d.CreatedAt)))
	if err != nil {
		return fmt.Errorf("store: digest %s: %w", d.Day, err)
	}
	return nil
}

// GrpDigest returns a day's digest or ErrNotFound.
func (tx *TenantTx) GrpDigest(day string) (*PitDigest, error) {
	return one(tx, scanDigest, digestGet, sql.Named("day", day))
}

// GrpDigests returns the newest digests first.
func (tx *TenantTx) GrpDigests(limit int) ([]*PitDigest, error) {
	return collect(tx, scanDigest, digestList, sql.Named("limit", limit))
}
