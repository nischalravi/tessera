package store

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// UsageEvent is a daily-aggregated use of a permission by an identity.
type UsageEvent struct {
	ID           int64
	TenantID     tenancy.ID
	IdentityID   int64
	AccountID    *int64
	PermissionID int64
	Day          time.Time
	Count        int
}

var (
	// The Python MVP inserted usage events with bulk Core inserts that had no
	// tenant; this statement stamps @tenant by construction.
	usageInsert = tq("usage_events.insert", `
		INSERT INTO usage_events (tenant_id, identity_id, permission_id, account_id, day, count)
		VALUES (@tenant, @identity_id, @permission_id, @account_id, @day, @count)`)
	usageAggregate = tq("usage_events.aggregate_since", `
		SELECT u.identity_id, u.permission_id, max(u.day), sum(u.count), count(u.id) FROM usage_events u
		WHERE u.tenant_id = @tenant AND u.day >= @since GROUP BY u.identity_id, u.permission_id`)
	usageTrend = tq("usage_events.trend_since", `
		SELECT u.day, sum(u.count) FROM usage_events u WHERE u.tenant_id = @tenant AND u.day >= @since
		GROUP BY u.day ORDER BY u.day`)
	usageCount = tq("usage_events.count", `
		SELECT count(u.id) FROM usage_events u WHERE u.tenant_id = @tenant`)
)

// InsertUsageEvents inserts usage events in order.
func (tx *TenantTx) InsertUsageEvents(rows []UsageEvent) error {
	for i := range rows {
		e := &rows[i]
		if err := tx.own(e.TenantID); err != nil {
			return err
		}
		if _, err := tx.exec(usageInsert, sql.Named("identity_id", e.IdentityID), sql.Named("permission_id", e.PermissionID),
			sql.Named("account_id", IP(e.AccountID)), sql.Named("day", T(e.Day)), sql.Named("count", e.Count)); err != nil {
			return err
		}
	}
	return nil
}

// CountUsageEvents counts usage events.
func (tx *TenantTx) CountUsageEvents() (int, error) { return tx.count(usageCount) }

// UsageAggregate is one identity's use of one permission since a date.
type UsageAggregate struct {
	IdentityID, PermissionID int64
	LastUsed                 *time.Time
	Events, Days             int
}

// UsageAggregates groups usage events on or after since by identity and permission.
func (tx *TenantTx) UsageAggregates(since time.Time) ([]*UsageAggregate, error) {
	return collect(tx, func(s scanner) (*UsageAggregate, error) {
		var a UsageAggregate
		var last sql.NullString
		var total, days sql.NullInt64
		if err := s.Scan(&a.IdentityID, &a.PermissionID, &last, &total, &days); err != nil {
			return nil, err
		}
		a.Events, a.Days = int(total.Int64), int(days.Int64)
		if last.Valid {
			t, err := timeutil.ParseDB(last.String)
			if err != nil {
				return nil, err
			}
			a.LastUsed = &t
		}
		return &a, nil
	}, usageAggregate, sql.Named("since", T(since)))
}

// UsageDay is the total number of usage events on one day.
type UsageDay struct {
	Day    string // as stored
	Events int64
}

// UsageTrend totals usage events per day on or after since, in day order.
func (tx *TenantTx) UsageTrend(since time.Time) ([]*UsageDay, error) {
	return collect(tx, func(s scanner) (*UsageDay, error) {
		var d UsageDay
		return &d, s.Scan(&d.Day, &d.Events)
	}, usageTrend, sql.Named("since", T(since)))
}
