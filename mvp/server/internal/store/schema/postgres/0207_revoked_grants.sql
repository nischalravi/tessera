-- Postgres dialect of schema/0204_revoked_grants.sql (Phase 0 PR14). The
-- SQLite file shares the number 0204 with correlation; goose needs unique
-- versions, so this one is 0207. src and dst are graph node keys, so there is
-- nothing to reference.

-- +goose Up

CREATE TABLE revoked_grants (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  src TEXT NOT NULL, dst TEXT NOT NULL, reason TEXT NOT NULL, revoked_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, src, dst)
);
