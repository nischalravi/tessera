-- Postgres dialect of schema/0004_audit.sql (Phase 0 PR14, design §13.8).
--
-- Append-only enforcement is two independent layers: plpgsql triggers (also
-- BEFORE TRUNCATE) and, in 0900_roles.sql, REVOKE UPDATE, DELETE, TRUNCATE on
-- audit_events and audit_checkpoints from the application role (only the
-- anchor_* columns of audit_checkpoints stay updatable). The tables belong to
-- the migration role, never to tessera_app.

-- +goose Up

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  seq BIGINT NOT NULL CHECK (seq >= 1),
  occurred_at TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user','api_client','system','operator','anonymous')),
  actor_id TEXT, actor_display TEXT, session_id TEXT, client_id TEXT,
  authn TEXT,
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
  target_type TEXT, target_id TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('success','denied','failure','error')),
  request_id TEXT, http TEXT, ip TEXT, user_agent_sha256 TEXT, policy_version TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  schema_version BIGINT NOT NULL DEFAULT 1,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  UNIQUE (tenant_id, seq),
  UNIQUE (tenant_id, hash)
);
CREATE INDEX audit_events_action ON audit_events (tenant_id, action);
CREATE INDEX audit_events_target ON audit_events (tenant_id, target_type, target_id);

CREATE TABLE audit_chain_heads (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE RESTRICT,
  last_seq BIGINT NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE audit_checkpoints (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  seq BIGINT NOT NULL CHECK (seq >= 1),
  head_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  jws TEXT NOT NULL,
  anchor_status TEXT NOT NULL DEFAULT 'pending' CHECK (anchor_status IN ('pending','anchored','failed')),
  anchor_ref TEXT, anchored_at TEXT,
  anchor_attempts BIGINT NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, seq)
);

-- Append-only enforcement (§13.8).
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('audit_events is append-only');
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('audit_events is append-only');
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
	FOR EACH STATEMENT EXECUTE FUNCTION tessera_abort('audit_events is append-only');
CREATE TRIGGER audit_ckpt_immutable BEFORE UPDATE OF id, seq, head_hash, created_at, jws, tenant_id ON audit_checkpoints
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('audit_checkpoints core fields are immutable');
CREATE TRIGGER audit_ckpt_no_delete BEFORE DELETE ON audit_checkpoints
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('audit_checkpoints is append-only');
CREATE TRIGGER audit_ckpt_no_truncate BEFORE TRUNCATE ON audit_checkpoints
	FOR EACH STATEMENT EXECUTE FUNCTION tessera_abort('audit_checkpoints is append-only');
-- A chain head never moves to another tenant, never goes backwards and is
-- never deleted.
CREATE TRIGGER audit_heads_no_delete BEFORE DELETE ON audit_chain_heads
	FOR EACH ROW EXECUTE FUNCTION tessera_abort('audit_chain_heads rows are permanent');
CREATE TRIGGER audit_heads_forward BEFORE UPDATE OF last_seq ON audit_chain_heads
	FOR EACH ROW WHEN (NEW.last_seq <> OLD.last_seq + 1)
	EXECUTE FUNCTION tessera_abort('audit_chain_heads advance one event at a time');

-- Chain guards (see schema/0004_audit.sql). They only read the row's own
-- tenant, so they work under row-level security.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_audit_heads() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF TG_OP = 'INSERT' THEN
		IF NOT (NEW.last_seq = 0 OR EXISTS (SELECT 1 FROM audit_events e
				WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.last_seq AND e.hash = NEW.last_hash)) THEN
			RAISE EXCEPTION 'cross-tenant reference: audit_chain_heads' USING ERRCODE = 'integrity_constraint_violation';
		END IF;
	ELSIF NEW.tenant_id <> OLD.tenant_id OR NOT EXISTS (SELECT 1 FROM audit_events e
			WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.last_seq AND e.hash = NEW.last_hash) THEN
		RAISE EXCEPTION 'cross-tenant reference: audit_chain_heads' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_audit_checkpoints() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM audit_events e
			WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq AND e.hash = NEW.head_hash) THEN
		RAISE EXCEPTION 'cross-tenant reference: audit_checkpoints' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

-- An event's seq must follow its tenant's head, and its prev_hash must be the
-- head's hash (genesis for seq 1).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tessera_guard_audit_events() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM audit_chain_heads h
			WHERE h.tenant_id = NEW.tenant_id AND NEW.seq = h.last_seq + 1 AND NEW.prev_hash = h.last_hash) THEN
		RAISE EXCEPTION 'cross-tenant reference: audit_events' USING ERRCODE = 'integrity_constraint_violation';
	END IF;
	RETURN NEW;
END
$fn$;
-- +goose StatementEnd

CREATE TRIGGER tg_audit_chain_heads_xtenant_ins BEFORE INSERT ON audit_chain_heads
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_audit_heads();
CREATE TRIGGER tg_audit_chain_heads_xtenant_upd BEFORE UPDATE OF tenant_id, last_seq, last_hash ON audit_chain_heads
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_audit_heads();
CREATE TRIGGER tg_audit_checkpoints_xtenant_ins BEFORE INSERT ON audit_checkpoints
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_audit_checkpoints();
CREATE TRIGGER tg_audit_checkpoints_xtenant_upd BEFORE UPDATE OF tenant_id, seq, head_hash ON audit_checkpoints
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_audit_checkpoints();
CREATE TRIGGER tg_audit_events_xtenant_ins BEFORE INSERT ON audit_events
	FOR EACH ROW EXECUTE FUNCTION tessera_guard_audit_events();
