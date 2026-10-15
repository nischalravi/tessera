-- Revoked-grant tombstones. A grant removed inside Tessera (least-privilege
-- revoke, access-review revoke, leaver plan) is remembered here so a connector
-- sync cannot re-create it from stale source data. Only connector ingestion
-- reads this table. Tenant-owned: see 0201_connections.sql. src and dst are
-- graph node keys, so there is nothing to guard across tenants.
CREATE TABLE IF NOT EXISTS revoked_grants (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  src TEXT NOT NULL, dst TEXT NOT NULL, reason TEXT NOT NULL, revoked_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, src, dst)
);
