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
		INSERT INTO admin_change_target_checks (tenant_id, id, change_id, checked_by, checked_at, fp, sealed_fp, matched)
		VALUES (@tenant, @id, @change_id, @checked_by, @checked_at, @fp, @sealed_fp, @matched)`)
	targetCheckCount = tq("admin_change_target_checks.count_value", `
		SELECT COUNT(*) FROM admin_change_target_checks WHERE tenant_id = @tenant AND sealed_fp = @sealed_fp AND checked_at >= @since`)
	targetCheckCountTenant = tq("admin_change_target_checks.count_tenant", `
		SELECT COUNT(*) FROM admin_change_target_checks WHERE tenant_id = @tenant AND checked_at >= @since`)
	targetCheckCountBy = tq("admin_change_target_checks.count_by", `
		SELECT COUNT(*) FROM admin_change_target_checks WHERE tenant_id = @tenant AND checked_by = @checked_by AND checked_at >= @since`)
)

// InsertAdminChangeTargetCheck records one attempt by checkedBy (a user id) on the request changeID; fp is the
// request-bound keyed fingerprint of the URL they submitted and sealedFP the per-tenant one of the sealed URL (the counter key). A request of another tenant is refused (guard trigger, composite foreign key).
func (tx *TenantTx) InsertAdminChangeTargetCheck(changeID uuid.UUID, checkedBy, fp, sealedFP string, matched bool, at time.Time) error {
	m := 0
	if matched {
		m = 1
	}
	_, err := tx.exec(targetCheckInsert, sql.Named("id", uuid.NewString()), sql.Named("change_id", changeID.String()),
		sql.Named("checked_by", checkedBy), sql.Named("checked_at", RT(at)), sql.Named("fp", fp), sql.Named("sealed_fp", sealedFP), sql.Named("matched", m))
	return err
}

// AdminChangeTargetChecksOf counts the attempts, by anyone and on any request, against the sealed value sealedFP at or
// after since: a URL filed again as a new request does not get fresh tries.
func (tx *TenantTx) AdminChangeTargetChecksOf(sealedFP string, since time.Time) (int, error) {
	var n int
	err := tx.queryRow(targetCheckCount, sql.Named("sealed_fp", sealedFP), sql.Named("since", RT(since))).Scan(&n)
	return n, err
}

// AdminChangeTargetChecksTenant counts every attempt in the tenant at or after since.
func (tx *TenantTx) AdminChangeTargetChecksTenant(since time.Time) (int, error) {
	var n int
	err := tx.queryRow(targetCheckCountTenant, sql.Named("since", RT(since))).Scan(&n)
	return n, err
}

// AdminChangeTargetChecksBy counts the attempts checkedBy made, on any request, at or after since.
func (tx *TenantTx) AdminChangeTargetChecksBy(checkedBy string, since time.Time) (int, error) {
	var n int
	err := tx.queryRow(targetCheckCountBy, sql.Named("checked_by", checkedBy), sql.Named("since", RT(since))).Scan(&n)
	return n, err
}
