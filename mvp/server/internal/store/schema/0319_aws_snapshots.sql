-- AWS evaluator persistence (issue #26, PR-7; design
-- docs/design/aws-effective-permission-evaluator.md §6.2 and §11.1).
--
-- aws_connectors holds the read-only AWS connector's settings. credentials_enc
-- is the access key pair the connector assumes its per-account role from,
-- sealed with internal/seal (AES-256-GCM, AAD bound to tenant, table, column
-- and connector id) and never returned by the API. external_id is not a
-- secret (it is the value the customer puts in the role's trust policy).
--
-- The other tables are snapshot-scoped and append-only. A snapshot's id is the
-- content hash of what the connector collected, and policy documents are
-- content-addressed, both PER TENANT: two tenants with byte-identical policies
-- get two rows, so a row's existence never leaks across tenants.
--
-- Beyond §6.2, two tables hold what §6.2 leaves out: aws_snapshot_entities
-- (principals, resources, resource-policy links, KMS grants, S3 state, VPC
-- endpoint policies, canonical ids, Identity Center assignments and the
-- organization's settings, as JSON, so a snapshot can be rebuilt) and
-- aws_collection_findings (stored policies that failed to parse or lost a
-- statement at ingest, and reads that failed; design §3.3 requires that such a
-- policy is recorded and never skipped silently).
--
-- Tenant-owned like 0001_tenancy.sql: every table has tenant_id, every unique
-- index starts with it, and the guard triggers at the end refuse a reference
-- to a row of another tenant. Ids are content hashes, so another tenant may
-- hold a row of the same id; a reference is refused only when it names an id
-- that exists in another tenant and not in the row's own.
CREATE TABLE IF NOT EXISTS aws_connectors (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  -- JSON: {"role_name","regions":[...],"account_ids":[...],"management_account_id","identity_center_region"}
  config TEXT NOT NULL CHECK (json_valid(config)),
  external_id TEXT NOT NULL,
  credentials_enc BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','ok','failed')),
  last_snapshot_id TEXT,
  last_run_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_aws_connectors_name ON aws_connectors (tenant_id, name);

CREATE TABLE IF NOT EXISTS aws_snapshots (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,                              -- content hash
  taken_at TEXT NOT NULL,                        -- RFC 3339, UTC
  org_id TEXT,
  account_ids TEXT NOT NULL CHECK (json_valid(account_ids)),
  catalog_version TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('connector', 'pr-sim', 'harness')),
  connector_id TEXT,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS aws_policy_documents (  -- immutable, content-addressed
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,                              -- PolicyDoc.ID
  kind TEXT NOT NULL,
  source_arn TEXT NOT NULL,
  version_id TEXT,
  raw_json BLOB NOT NULL,                        -- verbatim bytes
  normalized TEXT NOT NULL CHECK (json_valid(normalized)),
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_policy_documents_source ON aws_policy_documents (tenant_id, source_arn);
-- not unique and not tenant-led: it serves the cross-tenant guard triggers,
-- which look a parent up by id alone
CREATE INDEX IF NOT EXISTS aws_policy_documents_guard ON aws_policy_documents (id);
CREATE INDEX IF NOT EXISTS aws_snapshots_guard ON aws_snapshots (id);

CREATE TABLE IF NOT EXISTS aws_policy_attachments (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  target_arn TEXT NOT NULL,
  attachment_type TEXT NOT NULL,
  via TEXT NOT NULL CHECK (json_valid(via)),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES aws_policy_documents (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_policy_attachments_snapshot ON aws_policy_attachments (tenant_id, snapshot_id);
CREATE INDEX IF NOT EXISTS aws_policy_attachments_target ON aws_policy_attachments (tenant_id, target_arn);

CREATE TABLE IF NOT EXISTS aws_org_nodes (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  snapshot_id TEXT NOT NULL,
  id TEXT NOT NULL,
  kind TEXT NOT NULL,
  parent_id TEXT,
  name TEXT NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_id, id),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS aws_snapshot_entities (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  snapshot_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('principal','resource','resource_policy','kms_grant','s3_bucket','vpce_policy','canonical_id',
    'identity_center','org')),
  key TEXT NOT NULL,                             -- ARN, endpoint id or canonical id
  body TEXT NOT NULL CHECK (json_valid(body)),
  PRIMARY KEY (tenant_id, snapshot_id, kind, key),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS aws_collection_findings (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('policy_unparseable','statement_dropped','account_error')),
  source_arn TEXT NOT NULL,                      -- the policy's source ARN, or the resource or account that could not be read
  policy_kind TEXT NOT NULL DEFAULT '',
  code TEXT NOT NULL,
  detail TEXT NOT NULL,
  -- JSON {"type": ..., "targets": [...]}: which decisions the finding could affect
  scope TEXT NOT NULL CHECK (json_valid(scope)),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_collection_findings_snapshot ON aws_collection_findings (tenant_id, snapshot_id);

CREATE TABLE IF NOT EXISTS aws_trust_edges (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  from_arn TEXT NOT NULL,
  to_role_arn TEXT NOT NULL,
  mechanism TEXT NOT NULL,
  outcome TEXT NOT NULL,
  residual TEXT NOT NULL CHECK (json_valid(residual)),
  explanation_id TEXT NOT NULL,
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_trust_edges_snapshot ON aws_trust_edges (tenant_id, snapshot_id);
CREATE INDEX IF NOT EXISTS aws_trust_edges_from ON aws_trust_edges (tenant_id, from_arn);
CREATE INDEX IF NOT EXISTS aws_trust_edges_to ON aws_trust_edges (tenant_id, to_role_arn);

CREATE TABLE IF NOT EXISTS aws_effective_permissions (  -- materialized, scope-compressed (§12.4)
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  principal_arn TEXT NOT NULL,
  action_atom INTEGER NOT NULL,
  resource_atom INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  residual TEXT CHECK (residual IS NULL OR json_valid(residual)),  -- NULL unless conditional
  fidelity TEXT NOT NULL,
  explanation_id TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  catalog_version TEXT NOT NULL,
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES aws_snapshots (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS aws_eff_snapshot ON aws_effective_permissions (tenant_id, snapshot_id);
CREATE INDEX IF NOT EXISTS aws_eff_principal ON aws_effective_permissions (tenant_id, principal_arn);
CREATE INDEX IF NOT EXISTS aws_eff_action ON aws_effective_permissions (tenant_id, action_atom);
CREATE INDEX IF NOT EXISTS aws_eff_resource ON aws_effective_permissions (tenant_id, resource_atom);

CREATE TABLE IF NOT EXISTS aws_explanations (  -- content-addressed, deduplicated traces
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  id TEXT NOT NULL,                              -- sha256 of the canonical (JCS) trace
  trace TEXT NOT NULL CHECK (json_valid(trace)),
  PRIMARY KEY (tenant_id, id)
);

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql, adapted to
-- content-addressed ids: a reference is cross-tenant when the id exists in
-- another tenant and not in the row's own tenant).

CREATE TRIGGER IF NOT EXISTS tg_aws_policy_attachments_xtenant_ins BEFORE INSERT ON aws_policy_attachments
WHEN (NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
		AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id))
	OR (NOT EXISTS (SELECT 1 FROM aws_policy_documents s WHERE s.id = NEW.policy_id AND s.tenant_id = NEW.tenant_id)
		AND EXISTS (SELECT 1 FROM aws_policy_documents p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_policy_attachments'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_policy_attachments_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id, policy_id ON aws_policy_attachments
WHEN (NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
		AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id))
	OR (NOT EXISTS (SELECT 1 FROM aws_policy_documents s WHERE s.id = NEW.policy_id AND s.tenant_id = NEW.tenant_id)
		AND EXISTS (SELECT 1 FROM aws_policy_documents p WHERE p.id = NEW.policy_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_policy_attachments'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_org_nodes_xtenant_ins BEFORE INSERT ON aws_org_nodes
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_org_nodes'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_org_nodes_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id ON aws_org_nodes
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_org_nodes'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_snapshot_entities_xtenant_ins BEFORE INSERT ON aws_snapshot_entities
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_snapshot_entities'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_snapshot_entities_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id ON aws_snapshot_entities
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_snapshot_entities'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_collection_findings_xtenant_ins BEFORE INSERT ON aws_collection_findings
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_collection_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_collection_findings_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id ON aws_collection_findings
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_collection_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_trust_edges_xtenant_ins BEFORE INSERT ON aws_trust_edges
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_trust_edges'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_trust_edges_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id ON aws_trust_edges
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_trust_edges'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_effective_permissions_xtenant_ins BEFORE INSERT ON aws_effective_permissions
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_effective_permissions'); END;

CREATE TRIGGER IF NOT EXISTS tg_aws_effective_permissions_xtenant_upd BEFORE UPDATE OF tenant_id, snapshot_id ON aws_effective_permissions
WHEN NOT EXISTS (SELECT 1 FROM aws_snapshots s WHERE s.id = NEW.snapshot_id AND s.tenant_id = NEW.tenant_id)
	AND EXISTS (SELECT 1 FROM aws_snapshots p WHERE p.id = NEW.snapshot_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: aws_effective_permissions'); END;
