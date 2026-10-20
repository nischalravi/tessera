package store

import (
	"database/sql"
	"time"
)

// Baseline is a live revision's activation baseline and the monitoring state
// of its scheduled re-runs (schema/0355_readiness_baselines.sql). Snapshot and
// LastCounts are JSON owned by internal/readiness.
type Baseline struct {
	RevisionID string
	CapturedAt time.Time
	Score      int
	ConfigHash string
	Snapshot   string

	LastCounts     *string
	LastRunID      *string
	LastRunAt      *time.Time
	FailStreak     int
	DegradedReason *string
	DegradedAt     *time.Time
	UpgradePin     *string
	UpgradeSeenAt  *time.Time
}

const baselineCols = `b.revision_id, b.captured_at, b.score, b.config_hash, b.snapshot, b.last_counts, b.last_run_id,
	b.last_run_at, b.fail_streak, b.degraded_reason, b.degraded_at, b.upgrade_pin, b.upgrade_seen_at`

var (
	baselinesInsert = tq("readiness_baselines.insert", `
		INSERT INTO readiness_baselines (tenant_id, revision_id, captured_at, score, config_hash, snapshot, last_counts,
			last_run_id, last_run_at, fail_streak, degraded_reason, degraded_at, upgrade_pin, upgrade_seen_at)
		VALUES (@tenant, @revision_id, @captured_at, @score, @config_hash, @snapshot, @last_counts, @last_run_id,
			@last_run_at, @fail_streak, @degraded_reason, @degraded_at, @upgrade_pin, @upgrade_seen_at)`)
	baselinesGet = tq("readiness_baselines.get", `
		SELECT `+baselineCols+` FROM readiness_baselines b WHERE b.tenant_id = @tenant AND b.revision_id = @revision_id`)
	baselinesAll = tq("readiness_baselines.all", `
		SELECT `+baselineCols+` FROM readiness_baselines b WHERE b.tenant_id = @tenant ORDER BY b.captured_at, b.revision_id`)
	baselinesUpdateMonitor = tq("readiness_baselines.update_monitor", `
		UPDATE readiness_baselines SET last_counts = @last_counts, last_run_id = @last_run_id, last_run_at = @last_run_at,
			fail_streak = @fail_streak, degraded_reason = @degraded_reason, degraded_at = @degraded_at,
			upgrade_pin = @upgrade_pin, upgrade_seen_at = @upgrade_seen_at
		WHERE tenant_id = @tenant AND revision_id = @revision_id`)
)

func scanBaseline(s scanner) (*Baseline, error) {
	var b Baseline
	var counts, runID, runAt, reason, degAt, pin, seen sql.NullString
	var captured string
	if err := s.Scan(&b.RevisionID, &captured, &b.Score, &b.ConfigHash, &b.Snapshot, &counts, &runID, &runAt, &b.FailStreak,
		&reason, &degAt, &pin, &seen); err != nil {
		return nil, err
	}
	b.LastCounts, b.LastRunID, b.DegradedReason, b.UpgradePin = strp(counts), strp(runID), strp(reason), strp(pin)
	var err error
	if b.CapturedAt, err = ParseRT(captured); err != nil {
		return nil, err
	}
	if b.LastRunAt, err = rtp(runAt); err != nil {
		return nil, err
	}
	if b.DegradedAt, err = rtp(degAt); err != nil {
		return nil, err
	}
	b.UpgradeSeenAt, err = rtp(seen)
	return &b, err
}

// InsertBaseline stores a revision's baseline (one per revision: ErrDuplicate
// when it already has one).
func (tx *TenantTx) InsertBaseline(b *Baseline) error {
	_, err := tx.exec(baselinesInsert, sql.Named("revision_id", b.RevisionID), sql.Named("captured_at", RT(b.CapturedAt)),
		sql.Named("score", b.Score), sql.Named("config_hash", b.ConfigHash), sql.Named("snapshot", b.Snapshot),
		sql.Named("last_counts", SP(b.LastCounts)), sql.Named("last_run_id", SP(b.LastRunID)),
		sql.Named("last_run_at", RTP(b.LastRunAt)), sql.Named("fail_streak", b.FailStreak),
		sql.Named("degraded_reason", SP(b.DegradedReason)), sql.Named("degraded_at", RTP(b.DegradedAt)),
		sql.Named("upgrade_pin", SP(b.UpgradePin)), sql.Named("upgrade_seen_at", RTP(b.UpgradeSeenAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// Baseline returns a revision's baseline, or ErrNotFound.
func (tx *TenantTx) Baseline(revisionID string) (*Baseline, error) {
	return one(tx, scanBaseline, baselinesGet, sql.Named("revision_id", revisionID))
}

// Baselines lists every baseline of the tenant, oldest first.
func (tx *TenantTx) Baselines() ([]*Baseline, error) { return collect(tx, scanBaseline, baselinesAll) }

// UpdateBaselineMonitor stores the monitoring columns of a baseline; the
// baseline itself (score, snapshot, config hash) is never rewritten.
func (tx *TenantTx) UpdateBaselineMonitor(b *Baseline) error {
	_, err := tx.exec(baselinesUpdateMonitor, sql.Named("revision_id", b.RevisionID),
		sql.Named("last_counts", SP(b.LastCounts)), sql.Named("last_run_id", SP(b.LastRunID)),
		sql.Named("last_run_at", RTP(b.LastRunAt)), sql.Named("fail_streak", b.FailStreak),
		sql.Named("degraded_reason", SP(b.DegradedReason)), sql.Named("degraded_at", RTP(b.DegradedAt)),
		sql.Named("upgrade_pin", SP(b.UpgradePin)), sql.Named("upgrade_seen_at", RTP(b.UpgradeSeenAt)))
	return err
}
