-- Admin > Notifications / Email delivery: the tenant's own SMTP relay. One row per
-- tenant; no row (or enabled = 0) means the server's relay (TESSERA_SMTP_*) sends.
--
-- host is a DNS name or a public IP address: the API refuses a name that resolves
-- to a private, loopback, link-local or metadata address, and the sender's guarded
-- dialer (internal/safehttp) refuses it again at connection time. tls is starttls,
-- tls (from the first byte) or none (dev only; the API refuses it in production).
-- password_sealed is the relay password sealed under the KEK (internal/seal, bound
-- to the tenant); it is write-only through the API, which only says whether one is
-- set. last_test_* is the outcome of the last test message ("" and no time until one
-- is sent); it never holds a credential.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS tenant_mail_relay (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  tls TEXT NOT NULL CHECK (tls IN ('starttls', 'tls', 'none')),
  username TEXT NOT NULL DEFAULT '' CHECK (length(username) <= 256),
  password_sealed BLOB,
  from_address TEXT NOT NULL CHECK (length(from_address) BETWEEN 3 AND 320),
  last_test_at TEXT,
  last_test_outcome TEXT NOT NULL DEFAULT '' CHECK (length(last_test_outcome) <= 300),
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
