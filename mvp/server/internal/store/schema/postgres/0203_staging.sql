-- Postgres dialect of schema/0203_staging.sql (Phase 0 PR14). See 0001_tenancy.sql.

-- +goose Up

CREATE TABLE stg_identities (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, email TEXT, type TEXT, status TEXT, department TEXT,
  hired_at TEXT, terminated_at TEXT, attributes TEXT,
  PRIMARY KEY (tenant_id, run_id, external_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id)
);
CREATE TABLE stg_accounts (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  username TEXT, kind TEXT, status TEXT, created_at TEXT, last_login_at TEXT,
  attributes TEXT,
  correlation TEXT,
  tier BIGINT,
  identity_id BIGINT, proposed_identity_id BIGINT,
  PRIMARY KEY (tenant_id, run_id, system, external_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
  FOREIGN KEY (tenant_id, proposed_identity_id) REFERENCES identities (tenant_id, id)
);
CREATE TABLE stg_groups (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, kind TEXT, privileged BIGINT NOT NULL DEFAULT 0, in_scope BIGINT NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, run_id, system, external_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id)
);
CREATE TABLE stg_memberships (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL,
  member_kind TEXT NOT NULL, member_xid TEXT NOT NULL, group_xid TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, member_kind, member_xid, group_xid),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id)
);
CREATE TABLE stg_attr_stats (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  run_id TEXT NOT NULL, object_class TEXT NOT NULL, attribute TEXT NOT NULL,
  total BIGINT NOT NULL, present BIGINT NOT NULL, distinct_values BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, object_class, attribute),
  FOREIGN KEY (tenant_id, run_id) REFERENCES readiness_check_runs (tenant_id, id)
);
