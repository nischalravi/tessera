-- Phase 0 PR9: one-time-use identifiers (design §9.2, §10.5).
--
-- replay_cache is a GLOBAL table: it holds keys that must be accepted at most
-- once until they expire (a SAML assertion ID per IdP; DPoP proof jti values
-- from PR10). The key is a SHA-256 hex of the kind-specific value, so no
-- tenant data is stored. Rows past expires_at are purged.

CREATE TABLE IF NOT EXISTS replay_cache (
  kind TEXT NOT NULL CHECK (kind IN ('saml_assertion','dpop_jti')),
  key_hash TEXT NOT NULL CHECK (length(key_hash) = 64),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (kind, key_hash)
);
CREATE INDEX IF NOT EXISTS replay_cache_expires ON replay_cache(expires_at);
