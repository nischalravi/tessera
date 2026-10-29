-- Postgres dialect of schema/0951_role_keys.sql (issue #650, AC-4): business_roles.key, the role's stable key in a
-- policy repository, unique per tenant, backfilled with the slug of the name (a repeated slug gets -2, -3, ...), and
-- business_role_versions.policy_ref, the JSON {commit, path, bundle_sha256} of the repository change behind a
-- version. No table is added, so rls.sql is unchanged.

-- +goose Up

ALTER TABLE business_roles ADD COLUMN IF NOT EXISTS key TEXT;
ALTER TABLE business_role_versions ADD COLUMN IF NOT EXISTS policy_ref TEXT;

UPDATE business_roles r SET key = s.k
FROM (
  SELECT b.id,
    CASE WHEN row_number() OVER (PARTITION BY b.tenant_id, b.base ORDER BY b.created_at, b.id) = 1 THEN b.base
         ELSE b.base || '-' || row_number() OVER (PARTITION BY b.tenant_id, b.base ORDER BY b.created_at, b.id) END AS k
  FROM (
    SELECT id, tenant_id, created_at,
      COALESCE(NULLIF(left(trim(both '-' from regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')), 56), ''), 'role') AS base
    FROM business_roles WHERE key IS NULL
  ) b
) s
WHERE r.id = s.id AND r.key IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_business_roles_key ON business_roles (tenant_id, key) WHERE key IS NOT NULL;
