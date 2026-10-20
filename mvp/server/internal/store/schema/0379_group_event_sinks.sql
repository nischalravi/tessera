-- Group event sinks (issue #61, GR-18; design docs/design/groups-grouper-parity.md
-- §10.1 and §13 "GR-18"). A sink delivers the group change events of 0282's
-- outbox (grp_events) to an external broker as CloudEvents 1.0 JSON: AWS SQS,
-- AWS SNS, RabbitMQ or Kafka. Delivery is at least once and in seq order, so
-- ordered per group; the position of a sink is its grp_event_cursors row
-- ("sink:<id>").
--
-- config holds the broker's non-secret settings (queue URL, topic, exchange,
-- brokers); secret_enc holds the credentials, sealed with internal/seal
-- (AES-256-GCM, AAD bound to tenant, table, column and sink id) and never
-- returned by the API. The remaining columns are the sink's health: while an
-- event cannot be delivered the sink is 'retrying' with backoff and the cursor
-- does not move; after the retry limit the event goes to grp_sink_dead_letters
-- and the cursor moves on.
--
-- Tenant-owned like 0001_tenancy.sql: the guard triggers at the end refuse a
-- dead letter that names another tenant's sink.
CREATE TABLE IF NOT EXISTS grp_event_sinks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  kind TEXT NOT NULL CHECK (kind IN ('sqs','sns','rabbitmq','kafka')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  config TEXT NOT NULL CHECK (json_valid(config)),
  -- JSON array of event types or prefixes ("membership.", "group.created"); [] = every event
  event_types TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(event_types)),
  secret_enc BLOB,
  state TEXT NOT NULL DEFAULT 'idle' CHECK (state IN ('idle','ok','retrying')),
  -- failed attempts at the event after the cursor
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  last_delivered_seq INTEGER NOT NULL DEFAULT 0,
  last_delivered_at TEXT,
  delivered_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_grp_event_sinks_name ON grp_event_sinks (tenant_id, name);

-- an event that could not be delivered after the retry limit, with the exact
-- message that was tried; 'requeued' rows are sent again by the runner
CREATE TABLE IF NOT EXISTS grp_sink_dead_letters (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  sink_id TEXT NOT NULL REFERENCES grp_event_sinks (id),
  seq INTEGER NOT NULL CHECK (seq > 0),
  event_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  last_error TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'dead' CHECK (status IN ('dead','requeued','delivered','discarded')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, sink_id, seq)
);
CREATE INDEX IF NOT EXISTS ix_grp_sink_dead_letters_status ON grp_sink_dead_letters (tenant_id, sink_id, status, seq);

CREATE TRIGGER IF NOT EXISTS tg_grp_sink_dead_letters_xtenant_ins BEFORE INSERT ON grp_sink_dead_letters
WHEN EXISTS (SELECT 1 FROM grp_event_sinks p WHERE p.id = NEW.sink_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sink_dead_letters'); END;

CREATE TRIGGER IF NOT EXISTS tg_grp_sink_dead_letters_xtenant_upd BEFORE UPDATE OF tenant_id, sink_id ON grp_sink_dead_letters
WHEN EXISTS (SELECT 1 FROM grp_event_sinks p WHERE p.id = NEW.sink_id AND p.tenant_id <> NEW.tenant_id)
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: grp_sink_dead_letters'); END;
