-- Postgres dialect of schema/0766_identity_rules.sql. See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE identity_rules (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  correlation_order TEXT NOT NULL DEFAULT '["external_id","email"]' CHECK (correlation_order IS JSON),
  authoritative TEXT NOT NULL DEFAULT '{}' CHECK (authoritative IS JSON),
  dormant_service_days BIGINT NOT NULL DEFAULT 30 CHECK (dormant_service_days BETWEEN 1 AND 3650),
  dormant_ai_agent_days BIGINT NOT NULL DEFAULT 30 CHECK (dormant_ai_agent_days BETWEEN 1 AND 3650),
  version BIGINT NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
