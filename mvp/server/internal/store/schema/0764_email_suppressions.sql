-- Admin > Email delivery: addresses Tessera no longer sends email to. A hard
-- bounce (a delivery-status report with a 5.x.x status) adds the address
-- automatically; an admin can add or remove one. address is lower-cased.
-- reason is hard_bounce or manual; message_id is the email_messages row that
-- caused a bounce suppression ('' for a manual one).
--
-- A suppressed address still gets its in-app notification; only the email is
-- skipped, and the delivery log says why.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS email_suppressions (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  address TEXT NOT NULL CHECK (length(address) BETWEEN 3 AND 320),
  reason TEXT NOT NULL CHECK (reason IN ('hard_bounce', 'manual')),
  note TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  message_id TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, address)
);
