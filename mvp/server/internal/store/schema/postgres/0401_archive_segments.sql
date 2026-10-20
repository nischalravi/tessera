-- Postgres dialect of schema/0401_archive_segments.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The triggers are plpgsql (tessera_abort).

-- +goose Up

CREATE TABLE archive_segments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  class TEXT NOT NULL CHECK (class IN ('audit','review_campaigns','requests','job_runs','notifications')),
  status TEXT NOT NULL CHECK (status IN ('written','verified','purged','failed')),
  seq_from BIGINT NOT NULL DEFAULT 0,
  seq_to BIGINT NOT NULL DEFAULT 0,
  range_from TEXT NOT NULL,
  range_to TEXT NOT NULL,
  item_count BIGINT NOT NULL CHECK (item_count >= 1),
  prev_hash TEXT NOT NULL DEFAULT '',
  first_hash TEXT NOT NULL DEFAULT '',
  last_hash TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL CHECK (location IN ('local','remote')),
  object_key TEXT NOT NULL CHECK (length(object_key) BETWEEN 1 AND 300),
  size_bytes BIGINT NOT NULL CHECK (size_bytes >= 1),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  created_at TEXT NOT NULL,
  verified_at TEXT,
  purged_at TEXT,
  UNIQUE (tenant_id, id),
  CHECK (class <> 'audit' OR (seq_from >= 1 AND seq_to >= seq_from)),
  CHECK ((status IN ('verified','purged')) = (verified_at IS NOT NULL)),
  CHECK ((status = 'purged') = (purged_at IS NOT NULL))
);
CREATE INDEX archive_segments_tenant_class ON archive_segments (tenant_id, class, seq_from, created_at);
CREATE UNIQUE INDEX archive_segments_audit_seq ON archive_segments (tenant_id, seq_from) WHERE class = 'audit' AND status <> 'failed';

CREATE TRIGGER archive_segments_no_delete BEFORE DELETE ON archive_segments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('archive_segments is append-only');
CREATE TRIGGER archive_segments_no_truncate BEFORE TRUNCATE ON archive_segments
	FOR EACH STATEMENT EXECUTE FUNCTION tessera_abort('archive_segments is append-only');
CREATE TRIGGER archive_segments_immutable BEFORE UPDATE OF id, tenant_id, class, seq_from, seq_to,
    range_from, range_to, item_count, prev_hash, first_hash, last_hash, location, object_key, size_bytes, sha256, created_at
  ON archive_segments
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('archive_segments core fields are immutable');
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_archive_status() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF NOT ((OLD.status = 'written' AND NEW.status IN ('verified','failed')) OR (OLD.status = 'verified' AND NEW.status IN ('purged','failed'))) THEN
		RAISE EXCEPTION 'archive_segments status moves forward only' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd
CREATE TRIGGER archive_segments_forward BEFORE UPDATE OF status ON archive_segments
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_archive_status();
