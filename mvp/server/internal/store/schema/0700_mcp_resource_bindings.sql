-- MCP resource bindings (issue #479). A rogue MCP server can steal the OAuth
-- credentials of an agent that sends them to a server that is not the one the
-- administrator registered (the MCP Python SDK flaw of 29 Sep, the OpenCode
-- flaw of 22 Oct). Each registered MCP resource (0356) is therefore bound to
-- the authorization server issuer it expects its tokens from and to the
-- audience those tokens carry. Tessera issues a token for the resource only
-- when the binding names this authorization server, puts the bound audience
-- in it, and refuses at introspection and at a tool-call decision a token
-- whose issuer or audience differs.
--
-- A resource with no row is bound to the defaults: this tenant's MCP issuer
-- and the resource URI. A row is written when an administrator binds a
-- resource explicitly. audience is unique per tenant, so a token for one
-- server can never be accepted by another.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- reference to another tenant's resource.
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcp_resources_tenant_id ON mcp_resources (tenant_id, id);

CREATE TABLE IF NOT EXISTS mcp_resource_bindings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  resource_id TEXT NOT NULL REFERENCES mcp_resources (id),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, resource_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mcp_resource_bindings_audience ON mcp_resource_bindings (tenant_id, audience);

CREATE TRIGGER IF NOT EXISTS tg_mcp_resource_bindings_xtenant_ins BEFORE INSERT ON mcp_resource_bindings
WHEN EXISTS (SELECT 1 FROM mcp_resources p WHERE p.id = NEW.resource_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_resource_bindings'); END;

CREATE TRIGGER IF NOT EXISTS tg_mcp_resource_bindings_xtenant_upd BEFORE UPDATE OF tenant_id, resource_id ON mcp_resource_bindings
WHEN EXISTS (SELECT 1 FROM mcp_resources p WHERE p.id = NEW.resource_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: mcp_resource_bindings'); END;
