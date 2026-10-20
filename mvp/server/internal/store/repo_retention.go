package store

import (
	"database/sql"
	"time"
)

// Log retention settings (schema/0400_retention.sql, issue #298). The classes,
// defaults and floors are in internal/retention; this file is only the SQL.

// Data classes with a retention setting and an archive.
const (
	ClassAudit     = "audit"
	ClassCampaigns = "review_campaigns"
	ClassRequests  = "requests"
	ClassJobRuns   = "job_runs"
	ClassOutbox    = "notifications"
)

// ArchiveClasses lists every class, in the order the archival job runs them.
var ArchiveClasses = []string{ClassAudit, ClassCampaigns, ClassRequests, ClassJobRuns, ClassOutbox}

// RetentionPolicy is one stored setting.
type RetentionPolicy struct {
	Class     string
	Days      int
	UpdatedAt time.Time
	UpdatedBy *string // the change request that set it
}

var (
	retentionList = tq("retention_policies.list", `
		SELECT r.class, r.days, r.updated_at, r.updated_by FROM retention_policies r
		WHERE r.tenant_id = @tenant ORDER BY r.class`)
	retentionUpsert = tq("retention_policies.upsert", `
		INSERT INTO retention_policies (tenant_id, class, days, updated_at, updated_by)
		VALUES (@tenant, @class, @days, @updated_at, @updated_by)
		ON CONFLICT (tenant_id, class) DO UPDATE SET days = excluded.days, updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`)
)

// RetentionPolicies returns the tenant's stored settings (a class with none uses its default).
func (tx *TenantTx) RetentionPolicies() ([]*RetentionPolicy, error) {
	return collect(tx, func(s scanner) (*RetentionPolicy, error) {
		var p RetentionPolicy
		var at string
		var by sql.NullString
		if err := s.Scan(&p.Class, &p.Days, &at, &by); err != nil {
			return nil, err
		}
		var err error
		p.UpdatedAt, err = ParseRT(at)
		p.UpdatedBy = strp(by)
		return &p, err
	}, retentionList)
}

// SetRetentionPolicy stores the days of a class. by names the change request
// (empty: none).
func (tx *TenantTx) SetRetentionPolicy(class string, days int, now time.Time, by string) error {
	var b any
	if by != "" {
		b = by
	}
	_, err := tx.exec(retentionUpsert, sql.Named("class", class), sql.Named("days", days),
		sql.Named("updated_at", RT(now)), sql.Named("updated_by", b))
	return err
}
