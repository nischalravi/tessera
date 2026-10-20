-- Postgres dialect of schema/0289_group_policy.sql (kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). The cross-tenant triggers become composite foreign keys
-- (tenant_id, x_id) -> (tenant_id, id), plus BEFORE guards on the group columns so a cross-tenant row
-- is refused before a key is checked, like SQLite. WITHOUT ROWID has no Postgres equivalent.

-- +goose Up

CREATE TABLE grp_policy_sources (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('repo','ui')),
  path TEXT NOT NULL DEFAULT '',
  commit_sha TEXT NOT NULL DEFAULT '',
  cedar TEXT NOT NULL,
  cedar_sha256 TEXT NOT NULL,
  allow_node TEXT NOT NULL DEFAULT '',
  deny_node TEXT NOT NULL DEFAULT '',
  compiled_sha256 TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  applied_by TEXT,
  PRIMARY KEY (tenant_id, group_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id)
);
CREATE UNIQUE INDEX grp_policy_sources_path ON grp_policy_sources (tenant_id, path) WHERE origin = 'repo';

CREATE TABLE grp_policy_nodes (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  node_hash TEXT NOT NULL CHECK (length(node_hash) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('union','intersection','complement','attr','has','empty')),
  attr TEXT NOT NULL DEFAULT '',
  value TEXT NOT NULL DEFAULT '',
  group_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, node_hash),
  UNIQUE (tenant_id, group_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES grp_groups (tenant_id, id)
);

CREATE TABLE grp_policy_uses (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_group_id TEXT NOT NULL,
  node_hash TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_group_id, node_hash),
  FOREIGN KEY (tenant_id, policy_group_id) REFERENCES grp_groups (tenant_id, id),
  FOREIGN KEY (tenant_id, node_hash) REFERENCES grp_policy_nodes (tenant_id, node_hash)
);
CREATE INDEX grp_policy_uses_node ON grp_policy_uses (tenant_id, node_hash);

CREATE TRIGGER tg_grp_policy_sources_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, group_id ON grp_policy_sources
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'group_id', 'text');
CREATE TRIGGER tg_grp_policy_nodes_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, group_id ON grp_policy_nodes
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'group_id', 'text');
CREATE TRIGGER tg_grp_policy_uses_group_xtenant BEFORE INSERT OR UPDATE OF tenant_id, policy_group_id ON grp_policy_uses
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_soft_ref('grp_groups', 'policy_group_id', 'text');
