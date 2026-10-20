-- Groups REST API (issue #48, GR-5; design docs/design/groups-grouper-parity.md
-- §10.11). The design has no file for it; 0280..0285 are taken here, 0287 is
-- another agent's; renumbered to 0376 in merge train 5 (0286 was taken by group privileges).
--
-- grp_idempotency stores the answer of a write that carried an Idempotency-Key,
-- so a retry replays the original response instead of repeating the change. A
-- key is scoped to the tenant and the caller (principal: "user:<id>" or
-- "client:<id>"): two callers never see each other's keys. request_hash is the
-- SHA-256 of method, route and body, so the same key with another request is
-- refused rather than replayed. A row is written in the transaction of the
-- change it describes and is immutable; it expires (expires_at) and is purged
-- by later writes of the tenant.
--
-- It references no other table, so it needs no cross-tenant guard; the primary
-- key starts with tenant_id.

CREATE TABLE IF NOT EXISTS grp_idempotency (
  tenant_id    TEXT NOT NULL REFERENCES tenants (id),
  principal    TEXT NOT NULL,
  idem_key     TEXT NOT NULL CHECK (length(idem_key) BETWEEN 1 AND 255),
  request_hash TEXT NOT NULL,
  status       INTEGER NOT NULL,
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  PRIMARY KEY (tenant_id, principal, idem_key)
);
CREATE INDEX IF NOT EXISTS grp_idem_expiry ON grp_idempotency (tenant_id, expires_at);

-- a stored answer is replayed as it was: it is never updated
CREATE TRIGGER IF NOT EXISTS tg_grp_idempotency_immutable BEFORE UPDATE ON grp_idempotency
BEGIN SELECT RAISE(ABORT, 'grp_idempotency rows are immutable'); END;
