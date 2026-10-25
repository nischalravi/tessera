-- Postgres dialect of schema/0915_aws_usage.sql (issue #644, kept in parity with the SQLite file by
-- TestSchemaParity_SQLiteAndPostgres). connector_id is deliberately not a foreign key (usage outlives a
-- deleted connector); see 0001_tenancy.sql for the tenant rules.

-- +goose Up

CREATE TABLE aws_usage_daily (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_id TEXT NOT NULL,
  principal_arn TEXT NOT NULL CHECK (length(principal_arn) BETWEEN 1 AND 2048),
  action TEXT NOT NULL CHECK (length(action) BETWEEN 3 AND 256),
  resource_scope TEXT NOT NULL CHECK (length(resource_scope) BETWEEN 1 AND 2048),
  day TEXT NOT NULL CHECK (length(day) = 10),                      -- YYYY-MM-DD, UTC
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'access_advisor')),
  count BIGINT NOT NULL CHECK (count >= 0),
  last_seen TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connector_id, principal_arn, action, resource_scope, day, source)
);
CREATE INDEX aws_usage_daily_day ON aws_usage_daily (tenant_id, connector_id, day);

CREATE TABLE aws_usage_state (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'access_advisor')),
  cursor TEXT NOT NULL DEFAULT '{}' CHECK (cursor IS JSON),
  covered_from TEXT NOT NULL DEFAULT '',                           -- earliest day ingested, or ''
  covered_to TEXT NOT NULL DEFAULT '',                             -- latest day ingested, or ''
  s3_data_events TEXT NOT NULL DEFAULT 'unknown' CHECK (s3_data_events IN ('enabled', 'disabled', 'unknown')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connector_id, source)
);

CREATE TABLE aws_usage_gaps (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'access_advisor')),
  ref TEXT NOT NULL CHECK (length(ref) BETWEEN 1 AND 1100),
  code TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  day TEXT NOT NULL DEFAULT '',                                    -- the day the gap affects, or ''
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connector_id, source, ref)
);
CREATE INDEX aws_usage_gaps_recorded ON aws_usage_gaps (tenant_id, recorded_at);
