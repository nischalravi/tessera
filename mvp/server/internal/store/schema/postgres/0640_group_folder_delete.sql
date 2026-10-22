-- Widens the admin_change_requests type CHECK to admit groups.folder.delete_recursive (a folder
-- tree delete that a second admin approves, internal/admin/change_folder.go). SQLite changes the
-- CHECK in 0008_admin_changes.sql. The list is every type of 0400_retention.sql and this one: a
-- migration between that and this one that adds a type must add it here too. No table is added.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive'));
