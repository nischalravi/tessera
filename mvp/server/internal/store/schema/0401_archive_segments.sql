-- Archive segments (issue #298): one row per sealed segment of records that
-- passed their retention. The segment itself is a blob (internal/archive) in
-- the archive store, sealed under the KEK with an AAD that binds tenant,
-- class and range; this row is its catalogue entry.
--
-- status is the crash-safe order of the archival job and only moves forward:
--   written   the sealed blob is in the store (not yet read back)
--   verified  it was read back, opened and checked against this row
--   purged    the online records were deleted (same transaction as this change)
--   failed    the blob could not be read back or did not match (a dead end: the
--             online records stay, and the next run archives them again)
-- Online records are deleted only while their segment is verified (triggers
-- here and in 0402), never earlier.
--
-- audit segments: seq_from..seq_to is the range of the tenant's hash chain,
-- prev_hash the hash before seq_from (genesis for 1), first_hash and last_hash
-- the hashes of its ends. The chain verifier (internal/audit) walks the purged
-- audit segments from seq 1 and then the online chain, so no range is skipped.
-- Other classes keep seq_from = seq_to = 0 and the time range.
CREATE TABLE IF NOT EXISTS archive_segments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  class TEXT NOT NULL CHECK (class IN ('audit','review_campaigns','requests','job_runs','notifications')),
  status TEXT NOT NULL CHECK (status IN ('written','verified','purged','failed')),
  seq_from INTEGER NOT NULL DEFAULT 0,
  seq_to INTEGER NOT NULL DEFAULT 0,
  range_from TEXT NOT NULL,
  range_to TEXT NOT NULL,
  item_count INTEGER NOT NULL CHECK (item_count >= 1),
  prev_hash TEXT NOT NULL DEFAULT '',
  first_hash TEXT NOT NULL DEFAULT '',
  last_hash TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL CHECK (location IN ('local','remote')),
  object_key TEXT NOT NULL CHECK (length(object_key) BETWEEN 1 AND 300),
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 1),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  created_at TEXT NOT NULL,
  verified_at TEXT,
  purged_at TEXT,
  UNIQUE (tenant_id, id),
  CHECK (class <> 'audit' OR (seq_from >= 1 AND seq_to >= seq_from)),
  CHECK ((status IN ('verified','purged')) = (verified_at IS NOT NULL)),
  CHECK ((status = 'purged') = (purged_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS archive_segments_tenant_class ON archive_segments (tenant_id, class, seq_from, created_at);
-- one audit segment per start seq: two segments cannot claim the same range start
CREATE UNIQUE INDEX IF NOT EXISTS archive_segments_audit_seq ON archive_segments (tenant_id, seq_from) WHERE class = 'audit' AND status <> 'failed';

-- A segment is never deleted, and only its progress columns change, forward.
CREATE TRIGGER IF NOT EXISTS archive_segments_no_delete BEFORE DELETE ON archive_segments
BEGIN SELECT RAISE(ABORT, 'archive_segments is append-only'); END;
CREATE TRIGGER IF NOT EXISTS archive_segments_immutable BEFORE UPDATE OF id, tenant_id, class, seq_from, seq_to,
    range_from, range_to, item_count, prev_hash, first_hash, last_hash, location, object_key, size_bytes, sha256, created_at
  ON archive_segments
BEGIN SELECT RAISE(ABORT, 'archive_segments core fields are immutable'); END;
CREATE TRIGGER IF NOT EXISTS archive_segments_forward BEFORE UPDATE OF status ON archive_segments
WHEN NOT ((OLD.status = 'written' AND NEW.status IN ('verified','failed')) OR (OLD.status = 'verified' AND NEW.status IN ('purged','failed')))
BEGIN SELECT RAISE(ABORT, 'archive_segments status moves forward only'); END;
