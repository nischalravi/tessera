-- Closed-loop provisioning (issue #103): one row per change Tessera makes in
-- a target system, and the findings a failed verification raises.
--
-- status: queued -> sent -> pending_verification -> verified | mismatch |
-- failed (cancelled by an operator from queued, failed or mismatch). An
-- operation is verified only when a re-read of the target shows the change.
-- idempotency_key names the intent ("jit:12:expire"), so enqueueing it twice
-- yields one operation; it is also sent to the target as Idempotency-Key.
-- completion is the Tessera-side change (graph edit, review decision, ...)
-- applied in the same transaction that marks the operation verified.
CREATE TABLE IF NOT EXISTS provisioning_ops (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  kind TEXT NOT NULL CHECK (kind IN ('create_account','update_account','disable_account','delete_account',
    'add_entitlement','remove_entitlement',
    'aws_detach_policy','aws_delete_inline_policy','aws_set_policy_version',
    'aws_remove_from_group','aws_delete_assignment','aws_attach_policy',
    'aws_put_inline_policy','aws_restore_policy_version','aws_add_to_group',
    'aws_create_assignment')),
  target_ref TEXT NOT NULL,
  payload TEXT NOT NULL,
  completion TEXT,
  source TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','sent','pending_verification','verified','mismatch','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0,
  verify_attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT,
  observed TEXT,
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS provisioning_ops_due ON provisioning_ops(tenant_id, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS provisioning_ops_conn ON provisioning_ops(tenant_id, connection_id);

CREATE TABLE IF NOT EXISTS provisioning_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  op_id TEXT NOT NULL REFERENCES provisioning_ops (id),
  connection_id TEXT NOT NULL REFERENCES connections (id),
  code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('high','medium','low')),
  title TEXT NOT NULL,
  expected TEXT NOT NULL,
  observed TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at TEXT NOT NULL, resolved_at TEXT,
  UNIQUE (tenant_id, op_id, code)
);
CREATE INDEX IF NOT EXISTS provisioning_findings_tenant ON provisioning_findings(tenant_id, status);

CREATE TRIGGER IF NOT EXISTS tg_provisioning_ops_xtenant_ins BEFORE INSERT ON provisioning_ops
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_ops'); END;

CREATE TRIGGER IF NOT EXISTS tg_provisioning_ops_xtenant_upd BEFORE UPDATE OF tenant_id, connection_id ON provisioning_ops
WHEN EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_ops'); END;

CREATE TRIGGER IF NOT EXISTS tg_provisioning_findings_xtenant_ins BEFORE INSERT ON provisioning_findings
WHEN EXISTS (SELECT 1 FROM provisioning_ops p WHERE p.id = NEW.op_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_findings'); END;

CREATE TRIGGER IF NOT EXISTS tg_provisioning_findings_xtenant_upd BEFORE UPDATE OF tenant_id, op_id, connection_id ON provisioning_findings
WHEN EXISTS (SELECT 1 FROM provisioning_ops p WHERE p.id = NEW.op_id AND p.tenant_id <> NEW.tenant_id)
	OR EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: provisioning_findings'); END;
