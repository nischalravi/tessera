-- Widens the admin_change_requests type CHECK to admit deletion_guard.update (the deletion
-- threshold guard's settings, internal/admin/change_deleteguard.go). SQLite changes the CHECK in
-- 0008_admin_changes.sql. The list is every type of 0640_group_folder_delete.sql and this one: a
-- migration between that and this one that adds a type must add it here too. No table is added.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update'));
