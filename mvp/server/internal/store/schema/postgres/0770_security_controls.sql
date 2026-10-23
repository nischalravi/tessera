-- Postgres counterpart of the columns added to schema/0720_helpdesk_auth_method_risk.sql (issue #510: who posted a
-- help-desk risk signal, and its dismissal) and schema/0320_queue.sql (issue #512: when a paused protected schedule
-- resumes by itself). SQLite adds them to an existing database in DB.upgradeSecurityControls. No table is added, so
-- rls.sql is unchanged.

-- +goose Up

ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS submitted_by TEXT NOT NULL DEFAULT '';
ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS submitted_by_user TEXT NOT NULL DEFAULT '';
ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS dismissed_at TEXT NOT NULL DEFAULT '';
ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS dismissed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS dismissed_by_user TEXT NOT NULL DEFAULT '';
ALTER TABLE helpdesk_idp_risks ADD COLUMN IF NOT EXISTS dismiss_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE queue_schedules ADD COLUMN IF NOT EXISTS paused_until TEXT NOT NULL DEFAULT '';

-- Widens the admin_change_requests type CHECK to admit siem.sink.filter (a SIEM sink's event filter, issue #511,
-- internal/admin/change_siem.go). SQLite changes the CHECK in 0008_admin_changes.sql. The list is every type of
-- 0671_deletion_guard_change_type.sql and this one: a migration after this one that adds a type must add it here too.
ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update','siem.sink.filter'));
