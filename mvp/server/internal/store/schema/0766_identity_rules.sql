-- Admin > Identity rules: what a tenant tunes in the identity engines. One row
-- per tenant; no row means the engine defaults (external ID then email, no
-- authoritative source per attribute, machine identities dormant after 30 days).
--
-- correlation_order is a JSON list of the keys the connector resolver tries, in
-- order, to match a reference to a person: "external_id" and "email". A key left
-- out is not tried. authoritative is a JSON object attribute -> connection system
-- ({"department": "workday"}): when a different system reports a person already
-- known, the stored value of that attribute is kept. dormant_service_days and
-- dormant_ai_agent_days are how long a service identity or an AI agent may go
-- unused before the machine-identity inventory flags it dormant.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS identity_rules (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  correlation_order TEXT NOT NULL DEFAULT '["external_id","email"]' CHECK (json_valid(correlation_order)),
  authoritative TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(authoritative)),
  dormant_service_days INTEGER NOT NULL DEFAULT 30 CHECK (dormant_service_days BETWEEN 1 AND 3650),
  dormant_ai_agent_days INTEGER NOT NULL DEFAULT 30 CHECK (dormant_ai_agent_days BETWEEN 1 AND 3650),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
