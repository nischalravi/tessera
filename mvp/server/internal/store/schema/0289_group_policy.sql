-- Policy groups as code (issue #52, GR-9; design docs/design/groups-grouper-parity.md
-- §8). 0280..0288 are taken here and 0290/0291 belong to other changes, so
-- this is 0289.
--
--   grp_policy_sources   one row per policy group: its Cedar text, where it came
--                        from (the repository at a commit, or the UI), the
--                        compiled roots (allow, deny) and the digest of the
--                        compiled form
--   grp_policy_nodes     the hash-consed nodes of compiled policy: an internal
--                        composite (`union`, `intersection`, `complement`), an
--                        attribute group (`attr`: identities whose attribute has
--                        a value, `has`: that have the attribute) or the empty
--                        group. Each node is a native group; identical subtrees
--                        of different policies share one node
--   grp_policy_uses      the nodes (the whole subtree) a policy group's
--                        compiled form reaches; a node nobody uses is retired
--
-- Tenant-owned like 0001_tenancy.sql: every table has tenant_id, every unique
-- constraint starts with it, and the guard triggers at the end refuse a
-- reference to another tenant's row.

CREATE TABLE IF NOT EXISTS grp_policy_sources (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  -- 'repo' (a file of the policy repository) or 'ui' (the policy builder)
  origin TEXT NOT NULL CHECK (origin IN ('repo','ui')),
  -- repository path, e.g. groups/app/foo/foo_user.cedar; '' for the UI
  path TEXT NOT NULL DEFAULT '',
  commit_sha TEXT NOT NULL DEFAULT '',
  cedar TEXT NOT NULL,
  cedar_sha256 TEXT NOT NULL,
  -- the node hashes of the allow and deny roots ('' when the side is empty)
  allow_node TEXT NOT NULL DEFAULT '',
  deny_node TEXT NOT NULL DEFAULT '',
  compiled_sha256 TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  applied_by TEXT,
  PRIMARY KEY (tenant_id, group_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS grp_policy_sources_path ON grp_policy_sources (tenant_id, path) WHERE origin = 'repo';

CREATE TABLE IF NOT EXISTS grp_policy_nodes (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  node_hash TEXT NOT NULL CHECK (length(node_hash) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('union','intersection','complement','attr','has','empty')),
  -- attr and has: the identity attribute; attr: the value
  attr TEXT NOT NULL DEFAULT '',
  value TEXT NOT NULL DEFAULT '',
  group_id TEXT NOT NULL REFERENCES grp_groups (id),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, node_hash),
  UNIQUE (tenant_id, group_id)
);

CREATE TABLE IF NOT EXISTS grp_policy_uses (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  policy_group_id TEXT NOT NULL REFERENCES grp_groups (id),
  node_hash TEXT NOT NULL,
  PRIMARY KEY (tenant_id, policy_group_id, node_hash)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS grp_policy_uses_node ON grp_policy_uses (tenant_id, node_hash);

-- ---------------------------------------------------------------- cross-tenant guards

CREATE TRIGGER IF NOT EXISTS tg_grp_policy_sources_xtenant_ins BEFORE INSERT ON grp_policy_sources
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_sources'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_policy_sources_xtenant_upd BEFORE UPDATE OF tenant_id, group_id ON grp_policy_sources
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_sources'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_policy_nodes_xtenant_ins BEFORE INSERT ON grp_policy_nodes
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_nodes'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_policy_nodes_xtenant_upd BEFORE UPDATE OF tenant_id, group_id ON grp_policy_nodes
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.group_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_nodes'); END;

-- node_hash names a node of the same tenant, with no foreign key (the key is composite)
CREATE TRIGGER IF NOT EXISTS tg_grp_policy_uses_xtenant_ins BEFORE INSERT ON grp_policy_uses
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.policy_group_id AND p.tenant_id <> NEW.tenant_id)
	OR NOT EXISTS (SELECT 1 FROM grp_policy_nodes n WHERE n.node_hash = NEW.node_hash AND n.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_uses'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_policy_uses_xtenant_upd BEFORE UPDATE OF tenant_id, policy_group_id, node_hash ON grp_policy_uses
WHEN EXISTS (SELECT 1 FROM grp_groups p WHERE p.id = NEW.policy_group_id AND p.tenant_id <> NEW.tenant_id)
	OR NOT EXISTS (SELECT 1 FROM grp_policy_nodes n WHERE n.node_hash = NEW.node_hash AND n.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_policy_uses'); END;
