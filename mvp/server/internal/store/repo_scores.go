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

// RecordScore appends a score unless it equals the latest one recorded for
// the same scope, connection and revision.
func (c *Conn) RecordScore(r *ScoreRow) error {
	var last sql.NullInt64
	var band sql.NullString
	err := c.QueryRow(`SELECT score, band FROM readiness_scores WHERE tenant_id = ? AND scope = ?
		AND COALESCE(connection_id, '') = COALESCE(?, '') AND COALESCE(revision_id, '') = COALESCE(?, '')
		ORDER BY computed_at DESC, rowid DESC LIMIT 1`, DefaultTenantID, r.Scope, SP(r.ConnectionID), SP(r.RevisionID)).Scan(&last, &band)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && int(last.Int64) == r.Score && band.String == r.Band {
		return nil
	}
	_, err = c.Exec(`INSERT INTO readiness_scores (id, tenant_id, scope, connection_id, revision_id, computed_at, score, band, breakdown)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, NewID(), DefaultTenantID, r.Scope, SP(r.ConnectionID), SP(r.RevisionID),
		RT(r.ComputedAt), r.Score, r.Band, r.Breakdown)
	return err
}

// ScoreSeries returns the recorded scores of a scope (and connection), oldest first.
func (c *Conn) ScoreSeries(scope string, connectionID *string, limit int) ([]*ScoreRow, error) {
	return collect(c, func(s scanner) (*ScoreRow, error) {
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
	}, `SELECT scope, connection_id, revision_id, computed_at, score, band, breakdown FROM (
		SELECT *, rowid AS rid FROM readiness_scores WHERE tenant_id = ? AND scope = ? AND COALESCE(connection_id, '') = COALESCE(?, '')
		ORDER BY computed_at DESC, rid DESC LIMIT ?) ORDER BY computed_at, rid`, DefaultTenantID, scope, SP(connectionID), limit)
}
