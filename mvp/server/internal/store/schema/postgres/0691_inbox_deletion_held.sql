-- Postgres counterpart of the deletion_held task kind and deletion_hold object type added to
-- schema/0292_group_attestation.sql (the groups Inbox task for a held deletion). SQLite rebuilds the
-- table (DB.upgradeGrpInboxKinds); here the CHECKs are replaced.

-- +goose Up

ALTER TABLE grp_inbox_tasks DROP CONSTRAINT IF EXISTS grp_inbox_tasks_kind_check;
ALTER TABLE grp_inbox_tasks ADD CONSTRAINT grp_inbox_tasks_kind_check
  CHECK (kind IN ('deprovisioning','rule','micro_certification','attestation','attestation_overdue','deletion_held'));
ALTER TABLE grp_inbox_tasks DROP CONSTRAINT IF EXISTS grp_inbox_tasks_object_type_check;
ALTER TABLE grp_inbox_tasks ADD CONSTRAINT grp_inbox_tasks_object_type_check
  CHECK (object_type IN ('folder','group','deletion_hold'));
