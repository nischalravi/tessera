-- Postgres dialect of schema/0379_group_event_sinks.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant trigger becomes a composite foreign key
-- (tenant_id, sink_id) -> (tenant_id, id); secret_enc is BYTEA and json_valid is IS JSON.

-- +goose Up

CREATE TABLE grp_event_sinks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  kind TEXT NOT NULL CHECK (kind IN ('sqs','sns','rabbitmq','kafka')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  config TEXT NOT NULL CHECK (config IS JSON),
  event_types TEXT NOT NULL DEFAULT '[]' CHECK (event_types IS JSON),
  secret_enc BYTEA,
  state TEXT NOT NULL DEFAULT 'idle' CHECK (state IN ('idle','ok','retrying')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  last_delivered_seq BIGINT NOT NULL DEFAULT 0,
  last_delivered_at TEXT,
  delivered_count BIGINT NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX ux_grp_event_sinks_name ON grp_event_sinks (tenant_id, name);

CREATE TABLE grp_sink_dead_letters (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sink_id TEXT NOT NULL,
  seq BIGINT NOT NULL CHECK (seq > 0),
  event_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  last_error TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'dead' CHECK (status IN ('dead','requeued','delivered','discarded')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, sink_id, seq),
  FOREIGN KEY (tenant_id, sink_id) REFERENCES grp_event_sinks (tenant_id, id)
);
CREATE INDEX ix_grp_sink_dead_letters_status ON grp_sink_dead_letters (tenant_id, sink_id, status, seq);

CREATE TRIGGER tg_grp_sink_dead_letters_sink_xtenant BEFORE INSERT OR UPDATE OF tenant_id, sink_id ON grp_sink_dead_letters
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_event_sinks', 'sink_id', 'text');
