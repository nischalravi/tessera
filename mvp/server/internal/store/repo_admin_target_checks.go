package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// The approver's attempts to check the URL a proposal seals (schema/0964_change_target_checks.sql, issue #886). Every
// statement is tenant-scoped (tq). Only the keyed fingerprint of the submitted URL is stored, never the URL.

var (
	targetCheckInsert = tq("admin_change_target_checks.insert", `
		INSERT INTO admin_change_target_checks (tenant_id, id, change_id, checked_by, checked_at, fp, matched)
		VALUES (@tenant, @id, @change_id, @checked_by, @checked_at, @fp, @matched)`)
	targetCheckCount = tq("admin_change_target_checks.count", `
		SELECT COUNT(*) FROM admin_change_target_checks WHERE tenant_id = @tenant AND change_id = @change_id`)
	targetCheckCountBy = tq("admin_change_target_checks.count_by", `
		SELECT COUNT(*) FROM admin_change_target_checks WHERE tenant_id = @tenant AND checked_by = @checked_by AND checked_at >= @since`)
)

// InsertAdminChangeTargetCheck records one attempt by checkedBy (a user id) on the request changeID; fp is the keyed
// fingerprint of the URL they submitted. A request of another tenant is refused (guard trigger, composite foreign key).
func (tx *TenantTx) InsertAdminChangeTargetCheck(changeID uuid.UUID, checkedBy, fp string, matched bool, at time.Time) error {
	m := 0
	if matched {
		m = 1
	}
	_, err := tx.exec(targetCheckInsert, sql.Named("id", uuid.NewString()), sql.Named("change_id", changeID.String()),
		sql.Named("checked_by", checkedBy), sql.Named("checked_at", RT(at)), sql.Named("fp", fp), sql.Named("matched", m))
	return err
}

// AdminChangeTargetChecks counts every attempt on the request, by anyone.
func (tx *TenantTx) AdminChangeTargetChecks(changeID uuid.UUID) (int, error) {
	var n int
	err := tx.queryRow(targetCheckCount, sql.Named("change_id", changeID.String())).Scan(&n)
	return n, err
}

// AdminChangeTargetChecksBy counts the attempts checkedBy made, on any request, at or after since.
func (tx *TenantTx) AdminChangeTargetChecksBy(checkedBy string, since time.Time) (int, error) {
	var n int
	err := tx.queryRow(targetCheckCountBy, sql.Named("checked_by", checkedBy), sql.Named("since", RT(since))).Scan(&n)
	return n, err
}
