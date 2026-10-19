-- Postgres dialect of schema/0321_aws_integration.sql (AWS evaluator PR-11, issue #30, kept in parity with the
-- SQLite file by TestSchemaParity_SQLiteAndPostgres). The cross-tenant guard trigger becomes a
-- composite foreign key (tenant_id, edge_id) -> (tenant_id, id); see 0001_tenancy.sql.

-- +goose Up

CREATE TABLE aws_edge_evaluations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  edge_id BIGINT NOT NULL,
  explanation_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'conditional')),
  fidelity TEXT NOT NULL CHECK (fidelity IN ('exact', 'approximate', 'unsupported')),
  PRIMARY KEY (tenant_id, edge_id),
  FOREIGN KEY (tenant_id, edge_id) REFERENCES grant_edges (tenant_id, id)
);

CREATE TABLE aws_pr_comment_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  repo TEXT NOT NULL DEFAULT '' CHECK (length(repo) <= 140),
  token_enc BYTEA,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
