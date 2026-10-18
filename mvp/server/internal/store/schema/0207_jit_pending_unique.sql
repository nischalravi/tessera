-- One pending just-in-time request per identity and group (issue #142).
-- A second submit while the first is undecided is refused (409) by
-- jit.CreateRequest; this index is the guarantee under it.
--
-- A database that already holds duplicates would fail to build the index, so
-- the later duplicates are denied first (the lowest id stays pending). A
-- no-op on a database without duplicates.
UPDATE access_requests SET status = 'denied', decided_at = requested_at, decided_by = 'system'
WHERE status = 'pending'
  AND id > (SELECT min(o.id) FROM access_requests o
            WHERE o.tenant_id = access_requests.tenant_id AND o.identity_id = access_requests.identity_id
              AND o.group_id = access_requests.group_id AND o.status = 'pending');

CREATE UNIQUE INDEX IF NOT EXISTS ux_access_requests_pending
  ON access_requests (tenant_id, identity_id, group_id) WHERE status = 'pending';
