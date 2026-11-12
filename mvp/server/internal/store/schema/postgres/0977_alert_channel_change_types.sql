-- Widens the admin_change_requests type CHECK to admit alerts.channel.disable, .delete, .target and
-- .severity (issue #968): disabling, deleting, retargeting or raising the min_severity of an alert channel stops or redirects
-- security alerts, so each is a two-admin change request (internal/admin/change_alert_channels.go;
-- SQLite: 0008_admin_changes.sql and DB.upgradeAdminChangeTypes). The list is every type of 0976_siem_sink_remove_change_types.sql (renumbered by #971) and
-- these four: a migration after this one that adds a type must add it here too.

-- +goose Up

ALTER TABLE admin_change_requests DROP CONSTRAINT IF EXISTS admin_change_requests_type_check;
ALTER TABLE admin_change_requests ADD CONSTRAINT admin_change_requests_type_check
  CHECK (type IN ('role.grant','role.revoke','idp_connection.create','idp_connection.update_trust',
    'idp_connection.update_cosmetic','idp_connection.disable','tenant.settings.update','tenant.security_contacts.update',
    'breakglass.register','breakglass.revoke','groups.loader.save','retention.update','groups.folder.delete_recursive',
    'deletion_guard.update','siem.sink.filter','siem.sink.target','alerts.rule.loosen','breach.item.attest',
    'provisioning.write_back.enable','lp.settings.update','roles.bundle.apply','config.proposal','api_client.propose.grant',
    'lp.auto_policy.apply','jit.bundle.apply','sod.bundle.apply','agent_scopes.bundle.apply','policy.sync.apply',
    'siem.sink.disable','siem.sink.delete','alerts.channel.disable','alerts.channel.delete','alerts.channel.target',
    'alerts.channel.severity'));
