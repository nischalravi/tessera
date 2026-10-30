-- Widens the admin_change_requests type CHECK to admit agent_scopes.bundle.apply (applying agent scopes from a
-- policy repository: always two admins, issue #653, internal/admin/change_agent_scopes_bundle.go). SQLite changes the
-- CHECK in 0008_admin_changes.sql and DB.upgradeAdminChangeTypes. The list is every type of
-- 0962_sod_bundle_change_type.sql and this one: a migration after this one that adds a type must add it here
-- too. No table is added, so rls.sql is unchanged by this file.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update','siem.sink.filter','siem.sink.target','alerts.rule.loosen','breach.item.attest',
    'provisioning.write_back.enable','lp.settings.update','roles.bundle.apply','config.proposal','api_client.propose.grant',
    'lp.auto_policy.apply','jit.bundle.apply','sod.bundle.apply','agent_scopes.bundle.apply'));
