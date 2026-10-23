-- Admin > Notifications: the tenant's chat workspace, a Slack or Microsoft Teams
-- incoming webhook that receives the notifications of the kinds chosen here. One
-- row per tenant.
--
-- webhook_sealed is the webhook URL sealed under the KEK (it is a credential: whoever
-- holds it can post to the channel); the API only says whether one is set, and
-- shows the host. kinds is a JSON list of notification kinds posted. The posting
-- cursor is (cursor_at, cursor_id): notifications created after it are posted once
-- per event and the cursor then moves on, so a restart never posts twice (cursor_key is the event
-- last posted, so a second recipient of it is not posted again) and a
-- newly enabled webhook does not replay history. fail_count and last_error describe
-- the event the dispatcher is retrying; an event is given up after five failures.
--
-- Tenant-owned like 0001_tenancy.sql.
CREATE TABLE IF NOT EXISTS tenant_chat_webhook (
  tenant_id TEXT NOT NULL PRIMARY KEY REFERENCES tenants (id),
  provider TEXT NOT NULL CHECK (provider IN ('slack', 'teams')),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  webhook_sealed BLOB NOT NULL,
  webhook_host TEXT NOT NULL CHECK (length(webhook_host) BETWEEN 1 AND 253),
  kinds TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(kinds)),
  cursor_at TEXT NOT NULL,
  cursor_id TEXT NOT NULL DEFAULT '',
  cursor_key TEXT NOT NULL DEFAULT '',
  fail_count INTEGER NOT NULL DEFAULT 0 CHECK (fail_count >= 0),
  last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 300),
  last_post_at TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
