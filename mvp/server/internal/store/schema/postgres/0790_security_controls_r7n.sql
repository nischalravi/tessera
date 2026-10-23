-- Widens the admin_change_requests type CHECK to admit siem.sink.target (moving a SIEM sink to another destination,
-- issue #520, internal/admin/change_siem.go) and alerts.rule.loosen (loosening a security alert rule, issue #521,
-- internal/admin/change_alerts.go). SQLite changes the CHECK in 0008_admin_changes.sql and DB.upgradeAdminChangeTypes.
-- The list is every type of 0770_security_controls.sql and this one: a migration after this one that adds a type must
-- add it here too. No table is added, so rls.sql is unchanged.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update','siem.sink.filter','siem.sink.target','alerts.rule.loosen'));

-- Who vouched for a machine client's permissions (issue #522, store.APIClient.ApprovedBy). SQLite adds the column to an
-- existing database in DB.upgradeSecurityControls. No table is added, so rls.sql is unchanged.
ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS approved_by TEXT NOT NULL DEFAULT '';
