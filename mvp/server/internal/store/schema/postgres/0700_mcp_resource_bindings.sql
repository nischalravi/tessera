-- Postgres dialect of schema/0700_mcp_resource_bindings.sql (issue #479). See 0001_tenancy.sql.

-- +goose Up

CREATE UNIQUE INDEX ux_mcp_resources_tenant_id ON mcp_resources (tenant_id, id);

CREATE TABLE mcp_resource_bindings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  resource_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, resource_id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES mcp_resources (tenant_id, id)
);
CREATE UNIQUE INDEX ux_mcp_resource_bindings_audience ON mcp_resource_bindings (tenant_id, audience);
