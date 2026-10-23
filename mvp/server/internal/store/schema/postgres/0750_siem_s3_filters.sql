-- Postgres counterpart of the S3 sink kind and the per-sink event filter added to schema/0210_siem.sql
-- (issue #498). SQLite rebuilds the table and adds the columns (DB.upgradeSiemSinks); here the CHECK is
-- replaced and the columns are added.

-- +goose Up

ALTER TABLE siem_sinks DROP CONSTRAINT IF EXISTS siem_sinks_kind_check;
ALTER TABLE siem_sinks ADD CONSTRAINT siem_sinks_kind_check CHECK (kind IN ('syslog','webhook','s3'));
-- JSON array of audit actions or prefixes ("grant.revoke", "auth.*"); [] is every event
ALTER TABLE siem_sinks ADD COLUMN IF NOT EXISTS event_filter TEXT NOT NULL DEFAULT '[]';
-- s3 sinks: the signing region and the access key id (the secret access key is secret_sealed)
ALTER TABLE siem_sinks ADD COLUMN IF NOT EXISTS region TEXT NOT NULL DEFAULT '';
ALTER TABLE siem_sinks ADD COLUMN IF NOT EXISTS access_key_id TEXT NOT NULL DEFAULT '';
