-- Grant-edge history (issue #111): one row per span during which a grant edge
-- existed, so "who could reach X on date D" can be answered after the edge was
-- removed. grant_edges stays the live table; every write to it (connector
-- sync, JIT, manual, revoke, sweep) opens or closes a span in the same
-- transaction (store/repo_edge_history.go).
--
-- A span is half-open: the grant held at every instant t with
-- valid_from <= t < valid_to (valid_to NULL: still held). expires_at is the
-- grant's own expiry (JIT), so an edge that lapsed before the sweeper deleted
-- it is not reported as held afterwards. Timestamps use the same sortable text
-- layout as the rest of the schema (timeutil.DB).
--
-- Tenant-owned: see 0001_tenancy.sql. src and dst are graph node keys, guarded
-- on insert and update like grant_edges. edge_id is the grant_edges id the span
-- was opened for, kept for traceability after that row is deleted (it is not a
-- foreign key and is only ever written from the same tenant's edge). history is append-only apart from
-- closing a span: valid_to is the only column that changes.
CREATE TABLE IF NOT EXISTS edge_history (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  edge_id INTEGER,
  src TEXT NOT NULL, dst TEXT NOT NULL, relation TEXT NOT NULL, source TEXT NOT NULL,
  expires_at TEXT, valid_from TEXT NOT NULL, valid_to TEXT
);
CREATE INDEX IF NOT EXISTS ix_edge_history_tenant_open ON edge_history (tenant_id, src, dst, valid_to);
CREATE INDEX IF NOT EXISTS ix_edge_history_tenant_from ON edge_history (tenant_id, valid_from);

CREATE TRIGGER IF NOT EXISTS tg_edge_history_xtenant_ins BEFORE INSERT ON edge_history
WHEN (CASE substr(NEW.src, 1, instr(NEW.src, ':') - 1)
		WHEN 'identity' THEN EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'account' THEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'group' THEN EXISTS (SELECT 1 FROM groups p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'perm' THEN EXISTS (SELECT 1 FROM permissions p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'resource' THEN EXISTS (SELECT 1 FROM resources p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		ELSE 0 END)
	OR (CASE substr(NEW.dst, 1, instr(NEW.dst, ':') - 1)
		WHEN 'identity' THEN EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'account' THEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'group' THEN EXISTS (SELECT 1 FROM groups p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'perm' THEN EXISTS (SELECT 1 FROM permissions p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'resource' THEN EXISTS (SELECT 1 FROM resources p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		ELSE 0 END)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: edge_history'); END;

CREATE TRIGGER IF NOT EXISTS tg_edge_history_xtenant_upd BEFORE UPDATE OF tenant_id, src, dst ON edge_history
WHEN (CASE substr(NEW.src, 1, instr(NEW.src, ':') - 1)
		WHEN 'identity' THEN EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'account' THEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'group' THEN EXISTS (SELECT 1 FROM groups p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'perm' THEN EXISTS (SELECT 1 FROM permissions p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'resource' THEN EXISTS (SELECT 1 FROM resources p WHERE p.id = CAST(substr(NEW.src, instr(NEW.src, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		ELSE 0 END)
	OR (CASE substr(NEW.dst, 1, instr(NEW.dst, ':') - 1)
		WHEN 'identity' THEN EXISTS (SELECT 1 FROM identities p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'account' THEN EXISTS (SELECT 1 FROM accounts p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'group' THEN EXISTS (SELECT 1 FROM groups p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'perm' THEN EXISTS (SELECT 1 FROM permissions p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		WHEN 'resource' THEN EXISTS (SELECT 1 FROM resources p WHERE p.id = CAST(substr(NEW.dst, instr(NEW.dst, ':') + 1) AS INTEGER) AND p.tenant_id <> NEW.tenant_id)
		ELSE 0 END)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: edge_history'); END;

-- A span's attributes and start never change: only valid_to changes (closing
-- the span). A JIT extension closes the span and opens a new one.
CREATE TRIGGER IF NOT EXISTS tg_edge_history_frozen BEFORE UPDATE OF edge_id, relation, source, valid_from, expires_at ON edge_history
BEGIN SELECT RAISE(ABORT, 'edge_history: a span is closed, not edited'); END;

-- Backfill: a grant that exists but has no open span (created before this
-- table, or the table was added to an existing database) starts at its
-- created_at. Idempotent: it runs at every open and only adds what is missing.
INSERT INTO edge_history (tenant_id, edge_id, src, dst, relation, source, expires_at, valid_from)
SELECT e.tenant_id, e.id, e.src, e.dst, e.relation, e.source, e.expires_at, e.created_at
FROM grant_edges e
WHERE NOT EXISTS (SELECT 1 FROM edge_history h WHERE h.tenant_id = e.tenant_id AND h.src = e.src AND h.dst = e.dst
	AND h.valid_to IS NULL);
