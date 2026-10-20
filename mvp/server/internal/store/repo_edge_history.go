package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- edge history

// EdgeSpan is one period during which a grant edge existed (see
// schema/0260_edge_history.sql). The grant held at every instant t with
// ValidFrom <= t < ValidTo (ValidTo nil: still held), and not at or after its
// own ExpiresAt.
type EdgeSpan struct {
	ID        int64
	TenantID  tenancy.ID
	EdgeID    *int64 // the grant_edges id; the row may be gone since
	Src, Dst  string
	Relation  string
	Source    string // connector | jit | manual
	ExpiresAt *time.Time
	ValidFrom time.Time
	ValidTo   *time.Time
}

// End is the instant the span stopped holding: the earlier of ValidTo and
// ExpiresAt, or nil when it still holds.
func (s *EdgeSpan) End() *time.Time {
	switch {
	case s.ValidTo == nil:
		return s.ExpiresAt
	case s.ExpiresAt != nil && s.ExpiresAt.Before(*s.ValidTo):
		return s.ExpiresAt
	}
	return s.ValidTo
}

// HeldAt reports whether the grant held at t (half-open: held at ValidFrom,
// not held at its End).
func (s *EdgeSpan) HeldAt(t time.Time) bool {
	if t.Before(s.ValidFrom) {
		return false
	}
	end := s.End()
	return end == nil || t.Before(*end)
}

const spanCols = `h.id, h.tenant_id, h.edge_id, h.src, h.dst, h.relation, h.source, h.expires_at, h.valid_from, h.valid_to`

var (
	spansAsOf = tq("edge_history.as_of", `
		SELECT `+spanCols+` FROM edge_history h WHERE h.tenant_id = @tenant AND h.valid_from <= @at
		AND (h.valid_to IS NULL OR h.valid_to > @at) AND (h.expires_at IS NULL OR h.expires_at > @at)
		ORDER BY h.id`)
	spansSince = tq("edge_history.since", `
		SELECT `+spanCols+` FROM edge_history h WHERE h.tenant_id = @tenant
		AND (h.valid_to IS NULL OR h.valid_to >= @since) ORDER BY h.id`)
	spansList = tq("edge_history.list", `
		SELECT `+spanCols+` FROM edge_history h WHERE h.tenant_id = @tenant ORDER BY h.id`)
	spanOpen = tq("edge_history.open", `
		INSERT INTO edge_history (tenant_id, edge_id, src, dst, relation, source, expires_at, valid_from)
		VALUES (@tenant, @edge_id, @src, @dst, @relation, @source, @expires_at, @valid_from)`)
	spanClose = tq("edge_history.close", `
		UPDATE edge_history SET valid_to = @at WHERE tenant_id = @tenant AND src = @src AND dst = @dst
		AND valid_to IS NULL`)
	spansCloseExpired = tq("edge_history.close_expired", `
		UPDATE edge_history SET valid_to = expires_at WHERE tenant_id = @tenant AND source = 'jit'
		AND valid_to IS NULL AND expires_at <= @now`)
)

func scanSpan(s scanner) (*EdgeSpan, error) {
	var x EdgeSpan
	var tid string
	var edge sql.NullInt64
	var exp, from, to nullTime
	if err := s.Scan(&x.ID, &tid, &edge, &x.Src, &x.Dst, &x.Relation, &x.Source, &exp, &from, &to); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	x.EdgeID = intp(edge)
	if x.ExpiresAt, err = exp.ptr(); err != nil {
		return nil, err
	}
	if x.ValidFrom, err = from.val(); err != nil {
		return nil, err
	}
	x.ValidTo, err = to.ptr()
	return &x, err
}

// EdgeSpansAsOf returns the grants that held at instant at, in id order.
func (tx *TenantTx) EdgeSpansAsOf(at time.Time) ([]*EdgeSpan, error) {
	return collect(tx, scanSpan, spansAsOf, sql.Named("at", T(at)))
}

// EdgeSpansSince returns the spans that are still open or ended at or after
// since, in id order.
func (tx *TenantTx) EdgeSpansSince(since time.Time) ([]*EdgeSpan, error) {
	return collect(tx, scanSpan, spansSince, sql.Named("since", T(since)))
}

// EdgeSpans returns every span, in id order.
func (tx *TenantTx) EdgeSpans() ([]*EdgeSpan, error) { return collect(tx, scanSpan, spansList) }

// openSpan records that e now holds, from at.
func (tx *TenantTx) openSpan(edgeID int64, src, dst, relation, source string, expires *time.Time, at time.Time) error {
	_, err := tx.exec(spanOpen, sql.Named("edge_id", edgeID), sql.Named("src", src), sql.Named("dst", dst),
		sql.Named("relation", relation), sql.Named("source", source), sql.Named("expires_at", TP(expires)),
		sql.Named("valid_from", T(at)))
	return err
}

// closeSpan records that src -> dst stopped holding at at.
func (tx *TenantTx) closeSpan(src, dst string, at time.Time) error {
	_, err := tx.exec(spanClose, sql.Named("src", src), sql.Named("dst", dst), sql.Named("at", T(at)))
	return err
}
