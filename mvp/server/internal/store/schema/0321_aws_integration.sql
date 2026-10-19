-- AWS evaluator MVP integration (issue #30, PR-11; design
-- docs/design/aws-effective-permission-evaluator.md §11.2).
--
-- aws_edge_evaluations holds the three additive fields of a grant edge that the
-- evaluator confirmed: the explanation id (a key of aws_explanations), the
-- outcome ('allow' or 'conditional') and the fidelity. The design adds them as
-- columns of grant_edges; this schema has no migration step (CREATE TABLE IF
-- NOT EXISTS cannot add a column to a table that exists), so they live in a
-- side table that grant_edges queries LEFT JOIN. A grant edge with no row here
-- has unset fields ("" in store.GrantEdge), which is every edge a demo or
-- manual source makes, so existing rows and fixtures are unaffected.
--
-- aws_pr_comment_settings is the per-tenant switch of the optional access-diff
-- comment on a GitHub pull request (design §11.3). It is OFF by default (a
-- tenant has no row until it is configured), and the token is sealed with
-- internal/seal (AES-256-GCM, AAD bound to tenant, table and column) and never
-- returned by the API.
CREATE TABLE IF NOT EXISTS aws_edge_evaluations (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  edge_id INTEGER NOT NULL REFERENCES grant_edges (id),
  explanation_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'conditional')),
  fidelity TEXT NOT NULL CHECK (fidelity IN ('exact', 'approximate', 'unsupported')),
  PRIMARY KEY (tenant_id, edge_id)
);

CREATE TABLE IF NOT EXISTS aws_pr_comment_settings (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  repo TEXT NOT NULL DEFAULT '' CHECK (length(repo) <= 140),   -- "owner/name"
  token_enc BLOB,                                              -- sealed; NULL until set
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Cross-tenant reference guard (same pattern as 0001_tenancy.sql): grant_edges
-- ids are unique across tenants, so the edge must belong to the row's tenant.
CREATE TRIGGER IF NOT EXISTS tg_aws_edge_evaluations_xtenant_ins BEFORE INSERT ON aws_edge_evaluations
WHEN NOT EXISTS (SELECT 1 FROM grant_edges e WHERE e.id = NEW.edge_id AND e.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_edge_evaluations'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_edge_evaluations_xtenant_upd BEFORE UPDATE OF tenant_id, edge_id ON aws_edge_evaluations
WHEN NOT EXISTS (SELECT 1 FROM grant_edges e WHERE e.id = NEW.edge_id AND e.tenant_id = NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_edge_evaluations'); END;
