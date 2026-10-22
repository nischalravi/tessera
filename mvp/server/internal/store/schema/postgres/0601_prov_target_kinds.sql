-- Postgres counterpart of the vault and ERP target kinds added to
-- schema/0282_provisioning_targets.sql (issue #304). SQLite rebuilds the table
-- (DB.upgradeProvTargetKinds); here the CHECK is replaced.

-- +goose Up

ALTER TABLE provisioning_targets DROP CONSTRAINT IF EXISTS provisioning_targets_kind_check;
ALTER TABLE provisioning_targets ADD CONSTRAINT provisioning_targets_kind_check
  CHECK (kind IN ('scim','okta','fake','cyberark','delinea','beyondtrust','sap','oracle'));
