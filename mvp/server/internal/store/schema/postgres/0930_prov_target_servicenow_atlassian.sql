-- Postgres counterpart of the ServiceNow and Atlassian target kinds added to
-- schema/0282_provisioning_targets.sql (issue #559). SQLite rebuilds the table
-- (DB.upgradeProvTargetKinds); here the CHECK is replaced.

-- +goose Up

ALTER TABLE provisioning_targets DROP CONSTRAINT IF EXISTS provisioning_targets_kind_check;
ALTER TABLE provisioning_targets ADD CONSTRAINT provisioning_targets_kind_check
  CHECK (kind IN ('scim','okta','fake','cyberark','delinea','beyondtrust','sap','oracle','rest','sql','salesforce','servicenow','atlassian'));
