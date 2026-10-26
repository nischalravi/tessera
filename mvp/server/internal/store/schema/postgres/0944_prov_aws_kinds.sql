-- Postgres counterpart of the aws target kind and the AWS operation kinds added to schema/0282_provisioning_targets.sql
-- and schema/0283_provisioning_ops.sql (issue #660, the AWS write target). SQLite rebuilds the tables
-- (DB.upgradeProvTargetKinds, DB.upgradeProvOpKinds); here the CHECKs are replaced. No table is added, so rls.sql is
-- unchanged.

-- +goose Up

ALTER TABLE provisioning_targets DROP CONSTRAINT IF EXISTS provisioning_targets_kind_check;
ALTER TABLE provisioning_targets ADD CONSTRAINT provisioning_targets_kind_check
  CHECK (kind IN ('scim','okta','fake','cyberark','delinea','beyondtrust','sap','oracle','rest','sql','salesforce','servicenow','atlassian','ldap','ad','aws'));

ALTER TABLE provisioning_ops DROP CONSTRAINT IF EXISTS provisioning_ops_kind_check;
ALTER TABLE provisioning_ops ADD CONSTRAINT provisioning_ops_kind_check
  CHECK (kind IN ('create_account','update_account','disable_account','delete_account',
    'add_entitlement','remove_entitlement',
    'aws_detach_policy','aws_delete_inline_policy','aws_set_policy_version',
    'aws_remove_from_group','aws_delete_assignment','aws_attach_policy',
    'aws_put_inline_policy','aws_restore_policy_version','aws_add_to_group',
    'aws_create_assignment'));
