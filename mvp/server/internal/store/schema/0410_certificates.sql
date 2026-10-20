-- Admin > Certificates: the certificates and sealed keys a tenant uploads or
-- generates for SAML service-provider signing, connector mutual TLS and other
-- signing or encryption uses, with the rotation state of each.
--
-- The SP key a SAML connection signs with today lives on idp_connections
-- (sp_key_enc, sp_cert_pem, 0005_auth.sql) and stays the "active" one. A row
-- here with purpose saml_sp is a key being rotated in: 'next' is published in the
-- SP metadata beside the active certificate (the overlap window), promoting it
-- copies it onto the connection and keeps the old certificate as a 'retired'
-- row without its key. A row never leaves the table: retired certificates stay
-- as evidence, their key blob emptied.
--
-- key_sealed is the PKCS#8 private key sealed under the KEK (internal/seal)
-- with an AAD that binds tenant, table, column and id (store.CertKeyAAD). No
-- API returns it. cert_pem is the public certificate. subject, issuer, sans
-- (JSON list), not_before, not_after and fingerprint (SHA-256 of the DER, hex)
-- are read from the certificate when it is stored, so listing never parses.
--
-- Tenant-owned like 0001_tenancy.sql; the guard triggers at the end refuse a
-- reference to another tenant's connection.
CREATE TABLE IF NOT EXISTS tenant_certificates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants (id),
  purpose TEXT NOT NULL CHECK (purpose IN ('saml_sp','mtls_client','signing','encryption')),
  label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  idp_connection_id TEXT REFERENCES idp_connections (id),
  connection_id TEXT REFERENCES connections (id),
  status TEXT NOT NULL CHECK (status IN ('next','active','retired')),
  cert_pem TEXT NOT NULL,
  key_sealed BLOB,
  subject TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sans TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sans)),
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  key_algorithm TEXT NOT NULL,
  sig_algorithm TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  retired_at TEXT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, purpose, fingerprint),
  CHECK ((purpose = 'saml_sp') = (idp_connection_id IS NOT NULL)),
  CHECK (purpose = 'mtls_client' OR connection_id IS NULL),
  CHECK (status <> 'retired' OR key_sealed IS NULL)
);
CREATE INDEX IF NOT EXISTS tenant_certificates_tenant ON tenant_certificates(tenant_id, purpose, status);
-- at most one certificate waiting to be promoted per SAML connection
CREATE UNIQUE INDEX IF NOT EXISTS tenant_certificates_one_next ON tenant_certificates(tenant_id, idp_connection_id) WHERE status = 'next';

-- Cross-tenant reference guards (same pattern as 0001_tenancy.sql).

CREATE TRIGGER IF NOT EXISTS tg_tenant_certificates_xtenant_ins BEFORE INSERT ON tenant_certificates
WHEN (NEW.idp_connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: tenant_certificates'); END;

CREATE TRIGGER IF NOT EXISTS tg_tenant_certificates_xtenant_upd BEFORE UPDATE OF tenant_id, idp_connection_id, connection_id ON tenant_certificates
WHEN (NEW.idp_connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM idp_connections p WHERE p.id = NEW.idp_connection_id AND p.tenant_id <> NEW.tenant_id))
	OR (NEW.connection_id IS NOT NULL AND EXISTS (SELECT 1 FROM connections p WHERE p.id = NEW.connection_id AND p.tenant_id <> NEW.tenant_id))
BEGIN SELECT RAISE(ABORT, 'cross-tenant reference: tenant_certificates'); END;
