package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Deletion threshold guard (schema/0670_deletion_guard.sql). The categories, the
// defaults and the rules are in internal/deleteguard; this file is only the SQL.

// DeletionPolicy is one stored threshold.
type DeletionPolicy struct {
	Category      string
	MaxCount      *int
	MaxPercent    *float64
	WindowMinutes int
	Mode          string
	Version       int
	UpdatedBy     *string
	UpdatedAt     time.Time
}

// DeletionSettings is the tenant-wide row.
type DeletionSettings struct {
	HoldExpiryHours int
	Version         int
	UpdatedBy       *string
	UpdatedAt       time.Time
}

// DeletionHold is a held remainder; Reason is JSON.
type DeletionHold struct {
	ID            string
	Category      string
	Status        string
	Mode          string
	Reason        string
	Actor         string
	Source        string
	SourceID      string
	CorrelationID string
	ItemCount     int
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ResolvedAt    *time.Time
	ResolvedBy    *string
	Note          *string
}

// DeletionHoldItem is one item of a hold.
type DeletionHoldItem struct {
	HoldID string
	Ord    int
	Kind   string
	Ref    string
	Label  string
	Status string
	Note   *string
}

const (
	delPolCols  = `p.category, p.max_count, p.max_percent, p.window_minutes, p.mode, p.version, p.updated_by, p.updated_at`
	delHoldCols = `h.id, h.category, h.status, h.mode, h.reason, h.actor, h.source, h.source_id, h.correlation_id, h.item_count,
		h.created_at, h.expires_at, h.resolved_at, h.resolved_by, h.resolution_note`
)

var (
	delPolList = tq("deletion_guard_policies.list", `
		SELECT `+delPolCols+` FROM deletion_guard_policies p WHERE p.tenant_id = @tenant ORDER BY p.category`)
	delPolUpsert = tq("deletion_guard_policies.upsert", `
		INSERT INTO deletion_guard_policies (tenant_id, category, max_count, max_percent, window_minutes, mode, version, updated_by, updated_at)
		VALUES (@tenant, @category, @max_count, @max_percent, @window_minutes, @mode, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, category) DO UPDATE SET max_count = excluded.max_count, max_percent = excluded.max_percent,
			window_minutes = excluded.window_minutes, mode = excluded.mode, version = deletion_guard_policies.version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	delSetGet = tq("deletion_guard_settings.get", `
		SELECT s.hold_expiry_hours, s.version, s.updated_by, s.updated_at FROM deletion_guard_settings s WHERE s.tenant_id = @tenant`)
	delSetUpsert = tq("deletion_guard_settings.upsert", `
		INSERT INTO deletion_guard_settings (tenant_id, hold_expiry_hours, version, updated_by, updated_at)
		VALUES (@tenant, @hours, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET hold_expiry_hours = excluded.hold_expiry_hours,
			version = deletion_guard_settings.version + 1, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	// delLock is the first statement of every check: it writes the category's counter row, so a
	// concurrent check of the same category waits for this transaction (Postgres row lock; the
	// single writer of SQLite).
	delLock = tq("deletion_guard_counters.lock", `
		INSERT INTO deletion_guard_counters (tenant_id, category, seq) VALUES (@tenant, @category, 1)
		ON CONFLICT (tenant_id, category) DO UPDATE SET seq = deletion_guard_counters.seq + 1`)
	delUsed = tq("deletion_guard_ledger.used", `
		SELECT COALESCE(SUM(l.n), 0) FROM deletion_guard_ledger l
		WHERE l.tenant_id = @tenant AND l.category = @category AND l.applied_at > @since`)
	delLedgerInsert = tq("deletion_guard_ledger.insert", `
		INSERT INTO deletion_guard_ledger (tenant_id, id, category, applied_at, n, source)
		VALUES (@tenant, @id, @category, @applied_at, @n, @source)`)
	delLedgerPrune = tq("deletion_guard_ledger.prune", `
		DELETE FROM deletion_guard_ledger WHERE tenant_id = @tenant AND category = @category AND applied_at <= @before`)

	delHoldInsert = tq("deletion_holds.insert", `
		INSERT INTO deletion_holds (tenant_id, id, category, status, mode, reason, actor, source, source_id, correlation_id,
			item_count, created_at, expires_at)
		VALUES (@tenant, @id, @category, 'held', @mode, @reason, @actor, @source, @source_id, @correlation_id,
			@item_count, @created_at, @expires_at)`)
	delHoldGet = tq("deletion_holds.get", `
		SELECT `+delHoldCols+` FROM deletion_holds h WHERE h.tenant_id = @tenant AND h.id = @id`)
	delHoldList = tq("deletion_holds.list", `
		SELECT `+delHoldCols+` FROM deletion_holds h
		WHERE h.tenant_id = @tenant AND (@status = '' OR h.status = @status) AND (@category = '' OR h.category = @category)
		ORDER BY h.created_at DESC, h.id LIMIT @limit OFFSET @offset`)
	delHoldByCorr = tq("deletion_holds.by_correlation", `
		SELECT `+delHoldCols+` FROM deletion_holds h
		WHERE h.tenant_id = @tenant AND h.category = @category AND h.correlation_id = @correlation_id AND h.status = 'held'`)
	delHoldBump = tq("deletion_holds.bump", `
		UPDATE deletion_holds SET item_count = item_count + @n WHERE tenant_id = @tenant AND id = @id AND status = 'held'`)
	delHoldDue = tq("deletion_holds.due", `
		SELECT `+delHoldCols+` FROM deletion_holds h
		WHERE h.tenant_id = @tenant AND h.status = 'held' AND h.expires_at <= @now ORDER BY h.expires_at, h.id`)
	delHoldResolve = tq("deletion_holds.resolve", `
		UPDATE deletion_holds SET status = @status, resolved_at = @resolved_at, resolved_by = @resolved_by, resolution_note = @note
		WHERE tenant_id = @tenant AND id = @id AND status = 'held'`)
	delHoldOpen = tq("deletion_holds.open_count", `
		SELECT COUNT(*) FROM deletion_holds h WHERE h.tenant_id = @tenant AND h.status = 'held'`)

	delItemInsert = tq("deletion_hold_items.insert", `
		INSERT INTO deletion_hold_items (tenant_id, hold_id, ord, kind, ref, label, status)
		VALUES (@tenant, @hold_id, @ord, @kind, @ref, @label, 'held')`)
	delItemList = tq("deletion_hold_items.list", `
		SELECT i.hold_id, i.ord, i.kind, i.ref, i.label, i.status, i.note FROM deletion_hold_items i
		WHERE i.tenant_id = @tenant AND i.hold_id = @hold_id ORDER BY i.ord`)
	delItemSet = tq("deletion_hold_items.set", `
		UPDATE deletion_hold_items SET status = @status, note = @note
		WHERE tenant_id = @tenant AND hold_id = @hold_id AND ord = @ord AND status = 'held'`)

	delPopGroups = tq("deletion_guard.pop_groups", `
		SELECT COUNT(*) FROM grp_groups g WHERE g.tenant_id = @tenant AND g.status <> 'deleted'`)
	delPopFolders = tq("deletion_guard.pop_folders", `
		SELECT COUNT(*) FROM grp_folders f WHERE f.tenant_id = @tenant`)
	delPopAccounts = tq("deletion_guard.pop_accounts", `
		SELECT COUNT(*) FROM accounts a WHERE a.tenant_id = @tenant AND a.status = 'active'`)
	delPopIdentities = tq("deletion_guard.pop_identities", `
		SELECT COUNT(*) FROM identities i WHERE i.tenant_id = @tenant AND i.status = 'active'`)
	delPopMembers = tq("deletion_guard.pop_members", `
		SELECT COUNT(*) FROM grp_direct_memberships m WHERE m.tenant_id = @tenant`)
)

// DeletionPolicies returns the tenant's stored thresholds (a category with none uses its default).
func (tx *TenantTx) DeletionPolicies() ([]*DeletionPolicy, error) {
	return collect(tx, func(s scanner) (*DeletionPolicy, error) {
		var p DeletionPolicy
		var mc sql.NullInt64
		var mp sql.NullFloat64
		var by sql.NullString
		var at string
		if err := s.Scan(&p.Category, &mc, &mp, &p.WindowMinutes, &p.Mode, &p.Version, &by, &at); err != nil {
			return nil, err
		}
		if mc.Valid {
			v := int(mc.Int64)
			p.MaxCount = &v
		}
		if mp.Valid {
			p.MaxPercent = &mp.Float64
		}
		p.UpdatedBy = strp(by)
		var err error
		p.UpdatedAt, err = ParseRT(at)
		return &p, err
	}, delPolList)
}

// PutDeletionPolicy stores a category's threshold (bumping its version).
func (tx *TenantTx) PutDeletionPolicy(p *DeletionPolicy, now time.Time) error {
	var mc, mp any
	if p.MaxCount != nil {
		mc = *p.MaxCount
	}
	if p.MaxPercent != nil {
		mp = *p.MaxPercent
	}
	_, err := tx.exec(delPolUpsert, sql.Named("category", p.Category), sql.Named("max_count", mc), sql.Named("max_percent", mp),
		sql.Named("window_minutes", p.WindowMinutes), sql.Named("mode", p.Mode), sql.Named("updated_by", SP(p.UpdatedBy)),
		sql.Named("updated_at", RT(now)))
	return err
}

// DeletionSettingsRow returns the tenant-wide row, or ErrNotFound.
func (tx *TenantTx) DeletionSettingsRow() (*DeletionSettings, error) {
	var s DeletionSettings
	var by sql.NullString
	var at string
	err := tx.queryRow(delSetGet).Scan(&s.HoldExpiryHours, &s.Version, &by, &at)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.UpdatedBy = strp(by)
	s.UpdatedAt, err = ParseRT(at)
	return &s, err
}

// PutDeletionSettings stores the hold expiry.
func (tx *TenantTx) PutDeletionSettings(hours int, by *string, now time.Time) error {
	_, err := tx.exec(delSetUpsert, sql.Named("hours", hours), sql.Named("updated_by", SP(by)), sql.Named("updated_at", RT(now)))
	return err
}

// LockDeletionCategory serializes checks of one category until the transaction ends.
func (tx *TenantTx) LockDeletionCategory(category string) error {
	_, err := tx.exec(delLock, sql.Named("category", category))
	return err
}

// DeletionsApplied sums the deletions the ledger holds for the category after since.
func (tx *TenantTx) DeletionsApplied(category string, since time.Time) (int, error) {
	return tx.count(delUsed, sql.Named("category", category), sql.Named("since", RT(since)))
}

// RecordDeletions adds applied deletions to the ledger and drops rows older than prune.
func (tx *TenantTx) RecordDeletions(category string, n int, source string, now, prune time.Time) error {
	if _, err := tx.exec(delLedgerPrune, sql.Named("category", category), sql.Named("before", RT(prune))); err != nil {
		return err
	}
	if n <= 0 {
		return nil
	}
	_, err := tx.exec(delLedgerInsert, sql.Named("id", uuid.NewString()), sql.Named("category", category),
		sql.Named("applied_at", RT(now)), sql.Named("n", n), sql.Named("source", source))
	return err
}

// DeletionPopulation counts what a category's percent is of: live groups, folders, direct
// memberships, active accounts or active identities.
func (tx *TenantTx) DeletionPopulation(category string) (int, error) {
	switch category {
	case "groups":
		return tx.count(delPopGroups)
	case "folders":
		return tx.count(delPopFolders)
	case "group_members":
		return tx.count(delPopMembers)
	case "accounts":
		return tx.count(delPopAccounts)
	case "identities":
		return tx.count(delPopIdentities)
	}
	return 0, fmt.Errorf("store: no population for deletion category %q", category)
}

// InsertDeletionHold stores a hold and its items.
func (tx *TenantTx) InsertDeletionHold(h *DeletionHold, items []DeletionHoldItem) error {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	if _, err := tx.exec(delHoldInsert, sql.Named("id", h.ID), sql.Named("category", h.Category), sql.Named("mode", h.Mode),
		sql.Named("reason", h.Reason), sql.Named("actor", h.Actor), sql.Named("source", h.Source), sql.Named("source_id", h.SourceID),
		sql.Named("correlation_id", h.CorrelationID), sql.Named("item_count", len(items)),
		sql.Named("created_at", RT(h.CreatedAt)), sql.Named("expires_at", RT(h.ExpiresAt))); err != nil {
		return err
	}
	for i, it := range items {
		if _, err := tx.exec(delItemInsert, sql.Named("hold_id", h.ID), sql.Named("ord", i), sql.Named("kind", it.Kind),
			sql.Named("ref", it.Ref), sql.Named("label", it.Label)); err != nil {
			return err
		}
	}
	h.Status, h.ItemCount = "held", len(items)
	return nil
}

func scanDeletionHold(s scanner) (*DeletionHold, error) {
	var h DeletionHold
	var created, expires string
	var resolved, by, note sql.NullString
	if err := s.Scan(&h.ID, &h.Category, &h.Status, &h.Mode, &h.Reason, &h.Actor, &h.Source, &h.SourceID, &h.CorrelationID,
		&h.ItemCount, &created, &expires, &resolved, &by, &note); err != nil {
		return nil, err
	}
	var err error
	if h.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if h.ExpiresAt, err = ParseRT(expires); err != nil {
		return nil, err
	}
	if h.ResolvedAt, err = rtp(resolved); err != nil {
		return nil, err
	}
	h.ResolvedBy, h.Note = strp(by), strp(note)
	return &h, nil
}

// DeletionHoldByID returns a hold, or ErrNotFound.
func (tx *TenantTx) DeletionHoldByID(id string) (*DeletionHold, error) {
	h, err := scanDeletionHold(tx.queryRow(delHoldGet, sql.Named("id", id)))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return h, err
}

// DeletionHolds lists holds, newest first; status and category "" do not filter.
func (tx *TenantTx) DeletionHolds(status, category string, limit, offset int) ([]*DeletionHold, error) {
	return collect(tx, scanDeletionHold, delHoldList, sql.Named("status", status), sql.Named("category", category),
		sql.Named("limit", limit), sql.Named("offset", offset))
}

// DeletionHoldsDue lists the open holds that expired by now.
func (tx *TenantTx) DeletionHoldsDue(now time.Time) ([]*DeletionHold, error) {
	return collect(tx, scanDeletionHold, delHoldDue, sql.Named("now", RT(now)))
}

// OpenDeletionHolds counts the holds waiting for a decision.
func (tx *TenantTx) OpenDeletionHolds() (int, error) { return tx.count(delHoldOpen) }

// DeletionHoldItems lists a hold's items in order.
func (tx *TenantTx) DeletionHoldItems(holdID string) ([]*DeletionHoldItem, error) {
	return collect(tx, func(s scanner) (*DeletionHoldItem, error) {
		var it DeletionHoldItem
		var note sql.NullString
		if err := s.Scan(&it.HoldID, &it.Ord, &it.Kind, &it.Ref, &it.Label, &it.Status, &note); err != nil {
			return nil, err
		}
		it.Note = strp(note)
		return &it, nil
	}, delItemList, sql.Named("hold_id", holdID))
}

// SetDeletionHoldItem resolves one still-held item.
func (tx *TenantTx) SetDeletionHoldItem(holdID string, ord int, status, note string) error {
	var n any
	if note != "" {
		n = note
	}
	_, err := tx.exec(delItemSet, sql.Named("hold_id", holdID), sql.Named("ord", ord), sql.Named("status", status), sql.Named("note", n))
	return err
}

// ResolveDeletionHold closes an open hold with its final status.
func (tx *TenantTx) ResolveDeletionHold(id, status, by, note string, now time.Time) error {
	var n, b any
	if note != "" {
		n = note
	}
	if by != "" {
		b = by
	}
	res, err := tx.exec(delHoldResolve, sql.Named("id", id), sql.Named("status", status), sql.Named("resolved_at", RT(now)),
		sql.Named("resolved_by", b), sql.Named("note", n))
	if err != nil {
		return err
	}
	if c, err := res.RowsAffected(); err == nil && c == 0 {
		return ErrNotFound
	}
	return nil
}

// OpenDeletionHoldByCorrelation returns the open hold a correlation id already made in the
// category, or ErrNotFound: later items of the same batch join it instead of opening another.
func (tx *TenantTx) OpenDeletionHoldByCorrelation(category, correlation string) (*DeletionHold, error) {
	h, err := scanDeletionHold(tx.queryRow(delHoldByCorr, sql.Named("category", category), sql.Named("correlation_id", correlation)))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return h, err
}

// AppendDeletionHoldItems adds items to an open hold.
func (tx *TenantTx) AppendDeletionHoldItems(h *DeletionHold, items []DeletionHoldItem) error {
	for i, it := range items {
		if _, err := tx.exec(delItemInsert, sql.Named("hold_id", h.ID), sql.Named("ord", h.ItemCount+i), sql.Named("kind", it.Kind),
			sql.Named("ref", it.Ref), sql.Named("label", it.Label)); err != nil {
			return err
		}
	}
	if _, err := tx.exec(delHoldBump, sql.Named("id", h.ID), sql.Named("n", len(items))); err != nil {
		return err
	}
	h.ItemCount += len(items)
	return nil
}
