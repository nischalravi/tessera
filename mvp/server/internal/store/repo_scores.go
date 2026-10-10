package store

import (
	"database/sql"
	"errors"
	"time"
)

// ScoreRow is one point of the readiness score series.
type ScoreRow struct {
	Scope        string // connection | tenant
	ConnectionID *string
	RevisionID   *string
	ComputedAt   time.Time
	Score        int
	Band         string
	Breakdown    string // JSON
}

var (
	scoresLatest = tq("readiness_scores.latest", `
		SELECT s.score, s.band FROM readiness_scores s
		WHERE s.tenant_id = @tenant AND s.scope = @scope AND COALESCE(s.connection_id, '') = COALESCE(@connection_id, '')
			AND COALESCE(s.revision_id, '') = COALESCE(@revision_id, '')
		ORDER BY s.computed_at DESC, s.rowid DESC LIMIT 1`)
	scoresInsert = tq("readiness_scores.insert", `
		INSERT INTO readiness_scores (id, tenant_id, scope, connection_id, revision_id, computed_at, score, band, breakdown)
		VALUES (@id, @tenant, @scope, @connection_id, @revision_id, @computed_at, @score, @band, @breakdown)`)
	// The newest @limit points, returned oldest first.
	scoresSeries = tq("readiness_scores.series", `
		SELECT x.scope, x.connection_id, x.revision_id, x.computed_at, x.score, x.band, x.breakdown FROM (
			SELECT s.scope, s.connection_id, s.revision_id, s.computed_at, s.score, s.band, s.breakdown, s.rowid AS rid
			FROM readiness_scores s
			WHERE s.tenant_id = @tenant AND s.scope = @scope AND COALESCE(s.connection_id, '') = COALESCE(@connection_id, '')
			ORDER BY s.computed_at DESC, s.rowid DESC LIMIT @limit) x
		ORDER BY x.computed_at, x.rid`)
)

// RecordScore appends a score unless it equals the latest one recorded for
// the same scope, connection and revision.
func (tx *TenantTx) RecordScore(r *ScoreRow) error {
	var last sql.NullInt64
	var band sql.NullString
	err := tx.queryRow(scoresLatest, sql.Named("scope", r.Scope), sql.Named("connection_id", SP(r.ConnectionID)),
		sql.Named("revision_id", SP(r.RevisionID))).Scan(&last, &band)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && int(last.Int64) == r.Score && band.String == r.Band {
		return nil
	}
	_, err = tx.exec(scoresInsert, sql.Named("id", NewID()), sql.Named("scope", r.Scope),
		sql.Named("connection_id", SP(r.ConnectionID)), sql.Named("revision_id", SP(r.RevisionID)),
		sql.Named("computed_at", RT(r.ComputedAt)), sql.Named("score", r.Score), sql.Named("band", r.Band),
		sql.Named("breakdown", r.Breakdown))
	return err
}

// ScoreSeries returns the recorded scores of a scope (and connection), oldest first.
func (tx *TenantTx) ScoreSeries(scope string, connectionID *string, limit int) ([]*ScoreRow, error) {
	return collect(tx, func(s scanner) (*ScoreRow, error) {
		var r ScoreRow
		var conn, rev sql.NullString
		var at string
		if err := s.Scan(&r.Scope, &conn, &rev, &at, &r.Score, &r.Band, &r.Breakdown); err != nil {
			return nil, err
		}
		r.ConnectionID, r.RevisionID = strp(conn), strp(rev)
		var err error
		r.ComputedAt, err = ParseRT(at)
		return &r, err
	}, scoresSeries, sql.Named("scope", scope), sql.Named("connection_id", SP(connectionID)), sql.Named("limit", limit))
}
