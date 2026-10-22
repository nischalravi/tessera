package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Per-source settings of the deletion guard (schema/0690_deletion_guard_sources.sql). The rules are
// in internal/deleteguard; this file is only the SQL.

// DeletionSourcePolicy is one source's override for a category. Mode "" inherits the category's
// thresholds (MaxCount, MaxPercent and WindowMinutes are then unset); FeedDropPercent nil is the
// default and FeedEmptyCheck nil is on.
type DeletionSourcePolicy struct {
	Kind, SourceID, Category string
	Mode                     string
	MaxCount                 *int
	MaxPercent               *float64
	WindowMinutes            int
	FeedDropPercent          *float64
	FeedEmptyCheck           *bool
	Version                  int
	UpdatedBy                *string
	UpdatedAt                time.Time
}

const delSrcCols = `p.source_kind, p.source_id, p.category, p.mode, p.max_count, p.max_percent, p.window_minutes,
	p.feed_drop_percent, p.feed_empty_check, p.version, p.updated_by, p.updated_at`

var (
	delSrcList = tq("deletion_guard_source_policies.list", `
		SELECT `+delSrcCols+` FROM deletion_guard_source_policies p WHERE p.tenant_id = @tenant
		ORDER BY p.source_kind, p.source_id, p.category`)
	delSrcOf = tq("deletion_guard_source_policies.of_source", `
		SELECT `+delSrcCols+` FROM deletion_guard_source_policies p
		WHERE p.tenant_id = @tenant AND p.source_kind = @kind AND p.source_id = @source_id ORDER BY p.category`)
	delSrcGet = tq("deletion_guard_source_policies.get", `
		SELECT `+delSrcCols+` FROM deletion_guard_source_policies p
		WHERE p.tenant_id = @tenant AND p.source_kind = @kind AND p.source_id = @source_id AND p.category = @category`)
	delSrcUpsert = tq("deletion_guard_source_policies.upsert", `
		INSERT INTO deletion_guard_source_policies (tenant_id, source_kind, source_id, category, mode, max_count, max_percent,
			window_minutes, feed_drop_percent, feed_empty_check, version, updated_by, updated_at)
		VALUES (@tenant, @kind, @source_id, @category, @mode, @max_count, @max_percent, @window_minutes, @feed_drop_percent,
			@feed_empty_check, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, source_kind, source_id, category) DO UPDATE SET mode = excluded.mode,
			max_count = excluded.max_count, max_percent = excluded.max_percent, window_minutes = excluded.window_minutes,
			feed_drop_percent = excluded.feed_drop_percent, feed_empty_check = excluded.feed_empty_check,
			version = deletion_guard_source_policies.version + 1, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	delSrcDelete = tq("deletion_guard_source_policies.delete", `
		DELETE FROM deletion_guard_source_policies
		WHERE tenant_id = @tenant AND source_kind = @kind AND source_id = @source_id AND category = @category`)

	delStateGet = tq("deletion_guard_source_state.get", `
		SELECT s.last_count FROM deletion_guard_source_state s
		WHERE s.tenant_id = @tenant AND s.source_kind = @kind AND s.source_id = @source_id AND s.category = @category`)
	delStatePut = tq("deletion_guard_source_state.put", `
		INSERT INTO deletion_guard_source_state (tenant_id, source_kind, source_id, category, last_count, updated_at)
		VALUES (@tenant, @kind, @source_id, @category, @n, @updated_at)
		ON CONFLICT (tenant_id, source_kind, source_id, category) DO UPDATE SET last_count = excluded.last_count,
			updated_at = excluded.updated_at`)

	delSrcUsed = tq("deletion_guard_source_ledger.used", `
		SELECT COALESCE(SUM(l.n), 0) FROM deletion_guard_source_ledger l
		WHERE l.tenant_id = @tenant AND l.source_kind = @kind AND l.source_id = @source_id AND l.category = @category
		  AND l.applied_at > @since`)
	delSrcLedgerInsert = tq("deletion_guard_source_ledger.insert", `
		INSERT INTO deletion_guard_source_ledger (tenant_id, id, source_kind, source_id, category, applied_at, n)
		VALUES (@tenant, @id, @kind, @source_id, @category, @applied_at, @n)`)
	delSrcLedgerPrune = tq("deletion_guard_source_ledger.prune", `
		DELETE FROM deletion_guard_source_ledger
		WHERE tenant_id = @tenant AND source_kind = @kind AND source_id = @source_id AND category = @category AND applied_at <= @before`)
)

func scanDeletionSourcePolicy(s scanner) (*DeletionSourcePolicy, error) {
	var p DeletionSourcePolicy
	var mode, by sql.NullString
	var mc, wm, fe sql.NullInt64
	var mp, fd sql.NullFloat64
	var at string
	if err := s.Scan(&p.Kind, &p.SourceID, &p.Category, &mode, &mc, &mp, &wm, &fd, &fe, &p.Version, &by, &at); err != nil {
		return nil, err
	}
	p.Mode = mode.String
	if mc.Valid {
		v := int(mc.Int64)
		p.MaxCount = &v
	}
	if mp.Valid {
		p.MaxPercent = &mp.Float64
	}
	p.WindowMinutes = int(wm.Int64)
	if fd.Valid {
		p.FeedDropPercent = &fd.Float64
	}
	if fe.Valid {
		b := fe.Int64 != 0
		p.FeedEmptyCheck = &b
	}
	p.UpdatedBy = strp(by)
	var err error
	p.UpdatedAt, err = ParseRT(at)
	return &p, err
}

// DeletionSourcePolicies lists every source override of the tenant.
func (tx *TenantTx) DeletionSourcePolicies() ([]*DeletionSourcePolicy, error) {
	return collect(tx, scanDeletionSourcePolicy, delSrcList)
}

// DeletionSourcePoliciesOf lists one source's overrides.
func (tx *TenantTx) DeletionSourcePoliciesOf(kind, sourceID string) ([]*DeletionSourcePolicy, error) {
	return collect(tx, scanDeletionSourcePolicy, delSrcOf, sql.Named("kind", kind), sql.Named("source_id", sourceID))
}

// DeletionSourcePolicy returns one source's override for a category, or ErrNotFound.
func (tx *TenantTx) DeletionSourcePolicy(kind, sourceID, category string) (*DeletionSourcePolicy, error) {
	p, err := scanDeletionSourcePolicy(tx.queryRow(delSrcGet, sql.Named("kind", kind), sql.Named("source_id", sourceID),
		sql.Named("category", category)))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return p, err
}

// PutDeletionSourcePolicy stores a source's override (bumping its version).
func (tx *TenantTx) PutDeletionSourcePolicy(p *DeletionSourcePolicy, now time.Time) error {
	var mode, mc, mp, wm, fd, fe any
	if p.Mode != "" {
		mode, wm = p.Mode, p.WindowMinutes
	}
	if p.MaxCount != nil {
		mc = *p.MaxCount
	}
	if p.MaxPercent != nil {
		mp = *p.MaxPercent
	}
	if p.FeedDropPercent != nil {
		fd = *p.FeedDropPercent
	}
	if p.FeedEmptyCheck != nil {
		fe = 0
		if *p.FeedEmptyCheck {
			fe = 1
		}
	}
	_, err := tx.exec(delSrcUpsert, sql.Named("kind", p.Kind), sql.Named("source_id", p.SourceID), sql.Named("category", p.Category),
		sql.Named("mode", mode), sql.Named("max_count", mc), sql.Named("max_percent", mp), sql.Named("window_minutes", wm),
		sql.Named("feed_drop_percent", fd), sql.Named("feed_empty_check", fe), sql.Named("updated_by", SP(p.UpdatedBy)),
		sql.Named("updated_at", RT(now)))
	return err
}

// DeleteDeletionSourcePolicy removes a source's override: the category's settings apply again.
func (tx *TenantTx) DeleteDeletionSourcePolicy(kind, sourceID, category string) error {
	_, err := tx.exec(delSrcDelete, sql.Named("kind", kind), sql.Named("source_id", sourceID), sql.Named("category", category))
	return err
}

// DeletionSourceCount returns the record count of a source's last good run, ok false when there is none.
func (tx *TenantTx) DeletionSourceCount(kind, sourceID, category string) (n int, ok bool, err error) {
	err = tx.queryRow(delStateGet, sql.Named("kind", kind), sql.Named("source_id", sourceID), sql.Named("category", category)).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return n, err == nil, err
}

// PutDeletionSourceCount records the record count of a source's last good run.
func (tx *TenantTx) PutDeletionSourceCount(kind, sourceID, category string, n int, now time.Time) error {
	_, err := tx.exec(delStatePut, sql.Named("kind", kind), sql.Named("source_id", sourceID), sql.Named("category", category),
		sql.Named("n", n), sql.Named("updated_at", RT(now)))
	return err
}

// DeletionsAppliedBySource sums what a source's requests applied in the category after since.
func (tx *TenantTx) DeletionsAppliedBySource(kind, sourceID, category string, since time.Time) (int, error) {
	return tx.count(delSrcUsed, sql.Named("kind", kind), sql.Named("source_id", sourceID), sql.Named("category", category),
		sql.Named("since", RT(since)))
}

// RecordSourceDeletions adds a source's applied deletions to its ledger and drops its rows older than prune.
func (tx *TenantTx) RecordSourceDeletions(kind, sourceID, category string, n int, now, prune time.Time) error {
	if _, err := tx.exec(delSrcLedgerPrune, sql.Named("kind", kind), sql.Named("source_id", sourceID),
		sql.Named("category", category), sql.Named("before", RT(prune))); err != nil {
		return err
	}
	if n <= 0 {
		return nil
	}
	_, err := tx.exec(delSrcLedgerInsert, sql.Named("id", uuid.NewString()), sql.Named("kind", kind), sql.Named("source_id", sourceID),
		sql.Named("category", category), sql.Named("applied_at", RT(now)), sql.Named("n", n))
	return err
}
