-- Postgres dialect of schema/0810_group_pit_assigns.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). History carries no foreign keys, like grp_pit_privileges;
-- the json_valid CHECK is dropped: the column is TEXT and the store only writes encoded JSON.

-- +goose Up

CREATE TABLE grp_pit_assigns (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  assign_id TEXT NOT NULL,
  def_id TEXT NOT NULL,
  owner_type TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT,
  start_seq BIGINT NOT NULL,
  end_seq BIGINT,
  PRIMARY KEY (tenant_id, assign_id, start_seq)
);
CREATE INDEX grp_pit_assigns_time ON grp_pit_assigns (tenant_id, start_at);
CREATE INDEX grp_pit_assigns_owner ON grp_pit_assigns (tenant_id, owner_type, owner_id);
