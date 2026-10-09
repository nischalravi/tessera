-- Phase 0 PR1: tenancy foundation.
--
-- tenants is GLOBAL (listed in store.GlobalTables). Every other table is
-- tenant-owned: tenant_id TEXT NOT NULL REFERENCES tenants(id), an index on it,
-- and every UNIQUE constraint starts with tenant_id. Integer primary keys stay
-- global because the API contract and graph node keys depend on them; tenant
-- isolation makes another tenant's ids look nonexistent.
--
-- Phase 0 reseeds freely, so this file creates the whole schema. Versioned
-- migrations (goose) arrive with Postgres in PR14.

-- GLOBAL
CREATE TABLE IF NOT EXISTS tenants (
	id                TEXT PRIMARY KEY,
	slug              TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 3 AND 40 AND slug NOT GLOB '*[^a-z0-9_-]*'),
	name              TEXT NOT NULL,
	status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','recovery')),
	cell              TEXT NOT NULL DEFAULT 'local',
	min_admins        INTEGER NOT NULL DEFAULT 2 CHECK (min_admins >= 2),
	settings          TEXT NOT NULL DEFAULT '{}',
	security_contacts TEXT NOT NULL DEFAULT '[]',
	created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	external_id TEXT NOT NULL, name TEXT NOT NULL, email TEXT,
	type TEXT NOT NULL, department TEXT, title TEXT, status TEXT NOT NULL, manager_id INTEGER,
	owner_id INTEGER, source TEXT, description TEXT, hired_at TEXT, terminated_at TEXT,
	created_at TEXT NOT NULL,
	FOREIGN KEY(manager_id) REFERENCES identities (id), FOREIGN KEY(owner_id) REFERENCES identities (id));
CREATE UNIQUE INDEX IF NOT EXISTS ux_identities_tenant_external_id ON identities (tenant_id, external_id);
CREATE INDEX IF NOT EXISTS ix_identities_tenant_email ON identities (tenant_id, email);
CREATE INDEX IF NOT EXISTS ix_identities_tenant_type ON identities (tenant_id, type);
CREATE INDEX IF NOT EXISTS ix_identities_tenant_owner ON identities (tenant_id, owner_id);
CREATE INDEX IF NOT EXISTS ix_identities_tenant_manager ON identities (tenant_id, manager_id);

CREATE TABLE IF NOT EXISTS accounts (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	system TEXT NOT NULL, external_id TEXT NOT NULL, identity_id INTEGER,
	username TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT, last_login_at TEXT,
	UNIQUE (tenant_id, system, external_id), FOREIGN KEY(identity_id) REFERENCES identities (id));
CREATE INDEX IF NOT EXISTS ix_accounts_tenant_system ON accounts (tenant_id, system);
CREATE INDEX IF NOT EXISTS ix_accounts_tenant_identity ON accounts (tenant_id, identity_id);

CREATE TABLE IF NOT EXISTS groups (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	system TEXT NOT NULL, external_id TEXT NOT NULL, name TEXT NOT NULL,
	kind TEXT NOT NULL, privileged INTEGER NOT NULL, requestable INTEGER NOT NULL, description TEXT,
	UNIQUE (tenant_id, system, external_id));
CREATE INDEX IF NOT EXISTS ix_groups_tenant_system ON groups (tenant_id, system);

CREATE TABLE IF NOT EXISTS resources (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	system TEXT NOT NULL, external_id TEXT NOT NULL, name TEXT NOT NULL,
	kind TEXT NOT NULL, environment TEXT, tags TEXT NOT NULL, UNIQUE (tenant_id, system, external_id));
CREATE INDEX IF NOT EXISTS ix_resources_tenant_system ON resources (tenant_id, system);

CREATE TABLE IF NOT EXISTS permissions (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	system TEXT NOT NULL, external_id TEXT NOT NULL, action TEXT NOT NULL,
	resource_id INTEGER NOT NULL, privileged INTEGER NOT NULL, UNIQUE (tenant_id, system, external_id),
	FOREIGN KEY(resource_id) REFERENCES resources (id));
CREATE INDEX IF NOT EXISTS ix_permissions_tenant_system ON permissions (tenant_id, system);
CREATE INDEX IF NOT EXISTS ix_permissions_tenant_action ON permissions (tenant_id, action);

CREATE TABLE IF NOT EXISTS grant_edges (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	src TEXT NOT NULL, dst TEXT NOT NULL, relation TEXT NOT NULL,
	source TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL, UNIQUE (tenant_id, src, dst));
CREATE INDEX IF NOT EXISTS ix_grant_edges_tenant_src ON grant_edges (tenant_id, src);
CREATE INDEX IF NOT EXISTS ix_grant_edges_tenant_dst ON grant_edges (tenant_id, dst);

CREATE TABLE IF NOT EXISTS secrets (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	system TEXT NOT NULL, external_id TEXT NOT NULL, account_id INTEGER NOT NULL,
	kind TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, last_rotated_at TEXT,
	last_used_at TEXT, status TEXT NOT NULL, UNIQUE (tenant_id, system, external_id),
	FOREIGN KEY(account_id) REFERENCES accounts (id));
CREATE INDEX IF NOT EXISTS ix_secrets_tenant_account ON secrets (tenant_id, account_id);

CREATE TABLE IF NOT EXISTS agent_delegations (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	agent_id INTEGER NOT NULL, principal_id INTEGER NOT NULL, scopes TEXT NOT NULL,
	created_at TEXT NOT NULL, expires_at TEXT,
	FOREIGN KEY(agent_id) REFERENCES identities (id), FOREIGN KEY(principal_id) REFERENCES identities (id));
CREATE INDEX IF NOT EXISTS ix_agent_delegations_tenant ON agent_delegations (tenant_id);

CREATE TABLE IF NOT EXISTS usage_events (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	identity_id INTEGER NOT NULL, account_id INTEGER, permission_id INTEGER NOT NULL,
	day TEXT NOT NULL, count INTEGER NOT NULL,
	FOREIGN KEY(identity_id) REFERENCES identities (id), FOREIGN KEY(account_id) REFERENCES accounts (id),
	FOREIGN KEY(permission_id) REFERENCES permissions (id));
CREATE INDEX IF NOT EXISTS ix_usage_events_tenant_day ON usage_events (tenant_id, day);
-- Covering index for the per-request usage aggregate (TenantTx.UsageAggregates):
-- lets SQLite group by (identity, permission) straight off the index instead of
-- sorting ~20k rows in a temp B-tree.
CREATE INDEX IF NOT EXISTS ix_usage_events_tenant_cover ON usage_events (tenant_id, identity_id, permission_id, day, count);

CREATE TABLE IF NOT EXISTS access_requests (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	identity_id INTEGER NOT NULL, account_id INTEGER NOT NULL, group_id INTEGER NOT NULL,
	justification TEXT NOT NULL, duration_hours REAL NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL,
	decided_at TEXT, decided_by TEXT, expires_at TEXT, edge_id INTEGER,
	FOREIGN KEY(identity_id) REFERENCES identities (id), FOREIGN KEY(account_id) REFERENCES accounts (id),
	FOREIGN KEY(group_id) REFERENCES groups (id));
CREATE INDEX IF NOT EXISTS ix_access_requests_tenant_status ON access_requests (tenant_id, status);

CREATE TABLE IF NOT EXISTS review_campaigns (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	name TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL,
	unused_days INTEGER NOT NULL, total_grants INTEGER NOT NULL, auto_certified INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_review_campaigns_tenant ON review_campaigns (tenant_id);

CREATE TABLE IF NOT EXISTS review_items (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	campaign_id INTEGER NOT NULL, identity_id INTEGER NOT NULL, edge_id INTEGER,
	edge_src TEXT NOT NULL, edge_dst TEXT NOT NULL, grant_label TEXT NOT NULL, reasons TEXT NOT NULL,
	context TEXT NOT NULL, reviewer_id INTEGER, decision TEXT, comment TEXT, decided_at TEXT,
	FOREIGN KEY(campaign_id) REFERENCES review_campaigns (id), FOREIGN KEY(identity_id) REFERENCES identities (id),
	FOREIGN KEY(reviewer_id) REFERENCES identities (id));
CREATE INDEX IF NOT EXISTS ix_review_items_tenant_campaign ON review_items (tenant_id, campaign_id);

CREATE TABLE IF NOT EXISTS hris_events (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	external_id TEXT NOT NULL, type TEXT NOT NULL, identity_id INTEGER,
	payload TEXT NOT NULL, effective_at TEXT NOT NULL, status TEXT NOT NULL, executed_at TEXT,
	UNIQUE (tenant_id, external_id), FOREIGN KEY(identity_id) REFERENCES identities (id));

-- Replaced by the hash-chained audit_events in PR3; until then it is a plain,
-- tenant-scoped table.
CREATE TABLE IF NOT EXISTS audit_log (
	id INTEGER PRIMARY KEY,
	tenant_id TEXT NOT NULL REFERENCES tenants (id),
	at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_log_tenant ON audit_log (tenant_id, id);
