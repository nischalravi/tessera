-- MCP authorization server (issue #115): identities the kill switch contained.
-- A contained identity (an agent, or a user) gets no new MCP authorization,
-- code redemption or token exchange; its clients are disabled and its pending
-- requests denied in the same transaction. Rows are never deleted by the
-- server: lifting a containment is an operator decision.
CREATE TABLE IF NOT EXISTS mcp_contained (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  identity_id INTEGER NOT NULL REFERENCES identities (id),
  reason TEXT NOT NULL DEFAULT '',
  contained_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, identity_id)
);

CREATE TRIGGER IF NOT EXISTS tg_mcp_contained_xtenant_ins BEFORE INSERT ON mcp_contained
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_contained'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_contained_xtenant_upd BEFORE UPDATE OF tenant_id, identity_id ON mcp_contained
WHEN EXISTS (SELECT 1 FROM identities p WHERE p.id = NEW.identity_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_contained'); END;
