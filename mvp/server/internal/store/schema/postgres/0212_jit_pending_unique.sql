-- Postgres dialect of schema/0207_jit_pending_unique.sql (Phase 0 PR14 dialect, kept in parity with the SQLite file
-- by TestSchemaParity_SQLiteAndPostgres). Cross-tenant guard triggers become composite
-- foreign keys (tenant_id, x_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

UPDATE access_requests SET status = 'denied', decided_at = requested_at, decided_by = 'system'
WHERE status = 'pending'
  AND id > (SELECT min(o.id) FROM access_requests o
            WHERE o.tenant_id = access_requests.tenant_id AND o.identity_id = access_requests.identity_id
              AND o.group_id = access_requests.group_id AND o.status = 'pending');
CREATE UNIQUE INDEX ux_access_requests_pending
  ON access_requests (tenant_id, identity_id, group_id) WHERE status = 'pending';

