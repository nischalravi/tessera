-- Conditional access (issue #163): named network ranges, tenant access
-- policies and the device-compliance signal. Tenant-owned: every table has
-- tenant_id, and the guard triggers refuse references to another tenant's
-- rows (see 0005_auth.sql).

-- A named set of CIDRs a policy can test the client address against. The
-- address is the trusted-proxy client IP, never a raw X-Forwarded-For.
CREATE TABLE IF NOT EXISTS network_ranges (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
  cidrs TEXT NOT NULL DEFAULT '[]',
  created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);

-- A policy applies to one scope (the Tessera sign-in, or privileged actions)
-- and, when its conditions all hold, decides allow, step_up or deny.
-- Policies are checked in priority order and the first enforced match wins;
-- report_only policies never change the outcome, they are only recorded.
-- network_range_ids is a JSON array of network_ranges ids of the same tenant
-- (checked at the API boundary; a referenced range cannot be deleted).
CREATE TABLE IF NOT EXISTS access_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 500),
  scope TEXT NOT NULL CHECK (scope IN ('signin','privileged')),
  mode TEXT NOT NULL CHECK (mode IN ('disabled','report_only','enforce')),
  outcome TEXT NOT NULL CHECK (outcome IN ('allow','step_up','deny')),
  step_up_acr TEXT CHECK (step_up_acr IN ('urn:tessera:acr:aal2','urn:tessera:acr:phr','urn:tessera:acr:phrh')),
  step_up_max_age INTEGER NOT NULL DEFAULT 0 CHECK (step_up_max_age BETWEEN 0 AND 900),
  network_op TEXT NOT NULL DEFAULT 'any' CHECK (network_op IN ('any','in','not_in')),
  network_range_ids TEXT NOT NULL DEFAULT '[]',
  device TEXT NOT NULL DEFAULT 'any' CHECK (device IN ('any','unmanaged','not_compliant')),
  priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 10000),
  created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name),
  -- a step-up policy names what it asks for, and only a step-up policy does
  CHECK ((outcome = 'step_up') = (step_up_acr IS NOT NULL)),
  -- a network condition names its ranges, and "any" names none
  CHECK ((network_op = 'any') = (network_range_ids = '[]'))
);
CREATE INDEX IF NOT EXISTS access_policies_scope ON access_policies(tenant_id, scope, priority);

-- The latest device-compliance verdict for a user, from an admin (manual) or,
-- once the CAEP receiver (#114) lands, from a device-compliance-change event.
-- One row per user: a newer signal replaces the older one.
CREATE TABLE IF NOT EXISTS device_compliance_signals (
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES platform_users (id),
  status TEXT NOT NULL CHECK (status IN ('compliant','not_compliant')),
  source TEXT NOT NULL CHECK (source IN ('manual','caep')),
  reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
  set_by_user_id TEXT REFERENCES platform_users (id),
  set_at TEXT NOT NULL, expires_at TEXT,
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TRIGGER IF NOT EXISTS tg_device_compliance_signals_xtenant_ins BEFORE INSERT ON device_compliance_signals
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.set_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.set_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: device_compliance_signals'); END;

CREATE TRIGGER IF NOT EXISTS tg_device_compliance_signals_xtenant_upd BEFORE UPDATE OF tenant_id, user_id, set_by_user_id ON device_compliance_signals
WHEN EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.user_id AND p.tenant_id <> NEW.tenant_id)
	OR (NEW.set_by_user_id IS NOT NULL AND EXISTS (SELECT 1 FROM platform_users p WHERE p.id = NEW.set_by_user_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: device_compliance_signals'); END;
