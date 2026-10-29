-- A business role's stable key (issue #650, AC-4, design docs/design/access-as-code-repo.md sections 5 and 10): the
-- name may change, the key is what a policy repository (roles/<key>.yaml) refers to. Unique per tenant, so another
-- tenant may use the same key; a row that has none yet (NULL) is not constrained. The columns are in
-- 0206_business_roles.sql; DB.upgradeRoleKeys adds them to an older SQLite database and gives each existing role the
-- slug of its name. Postgres: migration 0951.
CREATE UNIQUE INDEX IF NOT EXISTS ux_business_roles_key ON business_roles (tenant_id, key) WHERE key IS NOT NULL;
