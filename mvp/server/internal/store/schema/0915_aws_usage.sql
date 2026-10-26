-- AWS usage (issue #644, LP-1; design docs/design/differentiators-plan.md section 3).
--
-- aws_usage_daily: what each principal did, per day, from the org CloudTrail
-- (source 'cloudtrail': management events, count = events) and from IAM Access
-- Advisor (source 'access_advisor': count is 1, "used at least once that day";
-- Access Advisor does not count calls). action is an IAM action in the
-- evaluator's spelling ("s3:GetObject"), or "<service>:*" when only the
-- service was seen (service-level Access Advisor data). resource_scope is a
-- resource ARN or '*'. The key adds source and connector to the issue's
-- (principal, action, scope, day), so the two sources never overwrite each
-- other. connector_id is not a foreign key: usage outlives a deleted connector,
-- like aws_snapshots.connector_id.
--
-- aws_usage_state: one row per connector and source with the ingest cursor (a
-- JSON object, opaque to the store), the window of days covered, and for
-- 'cloudtrail' whether S3 data events are enabled on the trail (LP-2 marks
-- object actions unknown when they are not).
--
-- aws_usage_gaps: what could not be ingested (a refused log file, a principal
-- Access Advisor could not read, a trail with no data events), so a missing
-- usage row is never read as "unused". ref names the thing (an S3 key, a
-- principal ARN, 'trail').
--
-- Tenant-owned like 0001_tenancy.sql: tenant_id on the row, every unique index
-- starts with it, every statement binds it.
CREATE TABLE IF NOT EXISTS aws_usage_daily (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_id TEXT NOT NULL,
  principal_arn TEXT NOT NULL CHECK (length(principal_arn) BETWEEN 1 AND 2048),
  action TEXT NOT NULL CHECK (length(action) BETWEEN 3 AND 256),
  resource_scope TEXT NOT NULL CHECK (length(resource_scope) BETWEEN 1 AND 2048),
  day TEXT NOT NULL CHECK (length(day) = 10),                      -- YYYY-MM-DD, UTC
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'access_advisor')),
  count INTEGER NOT NULL CHECK (count >= 0),
  last_seen TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connector_id, principal_arn, action, resource_scope, day, source)
);
CREATE INDEX IF NOT EXISTS aws_usage_daily_day ON aws_usage_daily (tenant_id, connector_id, day);

CREATE TABLE IF NOT EXISTS aws_usage_state (
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  connector_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cloudtrail', 'access_advisor')),
  cursor TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(cursor)),
  covered_from TEXT NOT NULL DEFAULT '',                           -- earliest day ingested, or ''
  covered_to TEXT NOT NULL DEFAULT '',                             -- latest day ingested, or ''
  s3_data_events TEXT NOT NULL DEFAULT 'unknown' CHECK (s3_data_events IN ('enabled', 'disabled', 'unknown')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connector_id, source)
);

CREATE TABLE IF NOT EXISTS aws_usage_gaps (
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
CREATE INDEX IF NOT EXISTS aws_usage_gaps_recorded ON aws_usage_gaps (tenant_id, recorded_at);
