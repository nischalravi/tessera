-- Postgres dialect of schema/0284_groups_engine.sql (kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres).

-- +goose Up

CREATE TABLE IF NOT EXISTS grp_engine_state (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  next_seq BIGINT NOT NULL DEFAULT 1,
  wheel_at TEXT,
  verified_at TEXT
);

CREATE INDEX IF NOT EXISTS grp_dm_by_group ON grp_direct_memberships (tenant_id, group_id, list_id, member_type);

CREATE INDEX IF NOT EXISTS grp_groups_enable ON grp_groups (tenant_id, enabled_from) WHERE enabled_from IS NOT NULL;
CREATE INDEX IF NOT EXISTS grp_groups_disable ON grp_groups (tenant_id, disabled_at) WHERE disabled_at IS NOT NULL;
