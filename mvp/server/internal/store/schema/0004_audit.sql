-- Phase 0 PR3: the audit ledger (design §7.5, §13).
--
-- Every tenant (including _platform) has its own append-only hash chain:
-- audit_events rows linked by prev_hash, a gapless seq per tenant, and a
-- head row (audit_chain_heads) that appenders lock and advance in the same
-- transaction. audit_checkpoints holds signed checkpoints of a chain head;
-- only their anchor_* columns may change after insert.
--
-- Hashes are computed in Go (internal/audit/canon). The database enforces
-- append-only with the triggers below; Postgres (PR14) adds privileges.

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  occurred_at TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user','api_client','system','operator','anonymous')),
  actor_id TEXT, actor_display TEXT, session_id TEXT, client_id TEXT,
  authn TEXT,
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
  target_type TEXT, target_id TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('success','denied','failure','error')),
  request_id TEXT, http TEXT, ip TEXT, user_agent_sha256 TEXT, policy_version TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  schema_version INTEGER NOT NULL DEFAULT 1,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  UNIQUE (tenant_id, seq),
  -- the design's global hash UNIQUE, led by tenant_id like every unique
  -- constraint (the hash covers tenant_id, so it is globally unique anyway)
  UNIQUE (tenant_id, hash)
);
CREATE INDEX IF NOT EXISTS audit_events_action ON audit_events (tenant_id, action);
CREATE INDEX IF NOT EXISTS audit_events_target ON audit_events (tenant_id, target_type, target_id);

CREATE TABLE IF NOT EXISTS audit_chain_heads (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE RESTRICT,
  last_seq INTEGER NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  head_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  jws TEXT NOT NULL,
  anchor_status TEXT NOT NULL DEFAULT 'pending' CHECK (anchor_status IN ('pending','anchored','failed')),
  anchor_ref TEXT, anchored_at TEXT,
  anchor_attempts INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, seq)
);

-- Append-only enforcement (§13.8).
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_ckpt_immutable BEFORE UPDATE OF id, seq, head_hash, created_at, jws, tenant_id ON audit_checkpoints
BEGIN SELECT RAISE(ABORT, 'audit_checkpoints core fields are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_ckpt_no_delete BEFORE DELETE ON audit_checkpoints
BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only'); END;
-- A chain head never moves to another tenant, never goes backwards and is
-- never deleted.
CREATE TRIGGER IF NOT EXISTS audit_heads_no_delete BEFORE DELETE ON audit_chain_heads
BEGIN SELECT RAISE(ABORT, 'audit_chain_heads rows are permanent'); END;
CREATE TRIGGER IF NOT EXISTS audit_heads_forward BEFORE UPDATE OF last_seq ON audit_chain_heads
WHEN NEW.last_seq <> OLD.last_seq + 1
BEGIN SELECT RAISE(ABORT, 'audit_chain_heads advance one event at a time'); END;

-- Cross-tenant reference guards (see schema/0001_tenancy.sql). A chain head
-- and a checkpoint must point at an event of their own tenant with exactly
-- that hash: a head or checkpoint can never certify another tenant's chain.
CREATE TRIGGER IF NOT EXISTS tg_audit_chain_heads_xtenant_ins BEFORE INSERT ON audit_chain_heads
WHEN NOT ((NEW.last_seq = 0)
	OR EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.last_seq AND e.hash = NEW.last_hash))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: audit_chain_heads'); END;

CREATE TRIGGER IF NOT EXISTS tg_audit_chain_heads_xtenant_upd BEFORE UPDATE OF tenant_id, last_seq, last_hash ON audit_chain_heads
WHEN NEW.tenant_id <> OLD.tenant_id
	OR NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.last_seq AND e.hash = NEW.last_hash)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: audit_chain_heads'); END;

CREATE TRIGGER IF NOT EXISTS tg_audit_checkpoints_xtenant_ins BEFORE INSERT ON audit_checkpoints
WHEN NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq AND e.hash = NEW.head_hash)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: audit_checkpoints'); END;

CREATE TRIGGER IF NOT EXISTS tg_audit_checkpoints_xtenant_upd BEFORE UPDATE OF tenant_id, seq, head_hash ON audit_checkpoints
WHEN NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq AND e.hash = NEW.head_hash)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: audit_checkpoints'); END;

-- An event's seq must follow its tenant's head, and its prev_hash must be the
-- head's hash (genesis for seq 1): a forked or out-of-order append is refused
-- even if a writer skipped the store's head lock.
CREATE TRIGGER IF NOT EXISTS tg_audit_events_xtenant_ins BEFORE INSERT ON audit_events
WHEN NOT EXISTS (SELECT 1 FROM audit_chain_heads h
	WHERE h.tenant_id = NEW.tenant_id AND NEW.seq = h.last_seq + 1 AND NEW.prev_hash = h.last_hash)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: audit_events'); END;
