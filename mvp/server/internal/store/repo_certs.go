package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Certificates (schema/0410_certificates.sql). Private keys are stored only
// sealed (internal/seal); no statement here selects key_sealed for a list.

// Certificate purposes and statuses.
const (
	CertSAMLSP     = "saml_sp"
	CertMTLSClient = "mtls_client"
	CertSigning    = "signing"
	CertEncryption = "encryption"

	CertNext    = "next"
	CertActive  = "active"
	CertRetired = "retired"
)

// TenantCertificate is a certificate a tenant uploaded or generated. KeySealed
// is empty for a retired certificate; it is set by the stores that read one
// row (Certificate) and is never loaded by the list.
type TenantCertificate struct {
	ID              string
	Purpose         string
	Label           string
	IdPConnectionID *string
	ConnectionID    *string
	Status          string
	CertPEM         string // the certificate; for an mtls_client one, the chain: the leaf first, then its intermediates
	TrustPEM        string // mtls_client: the CA certificates the target's server certificate must chain to (empty: the system roots)
	KeySealed       []byte
	Subject         string
	Issuer          string
	SANs            []string
	NotBefore       time.Time
	NotAfter        time.Time
	Fingerprint     string
	KeyAlgorithm    string
	SigAlgorithm    string
	CreatedBy       string
	CreatedAt       time.Time
	ActivatedAt     *time.Time
	RetiredAt       *time.Time
}

const certCols = `c.id, c.purpose, c.label, c.idp_connection_id, c.connection_id, c.status, c.cert_pem, c.trust_pem, c.subject, c.issuer,
	c.sans, c.not_before, c.not_after, c.fingerprint, c.key_algorithm, c.sig_algorithm, c.created_by, c.created_at,
	c.activated_at, c.retired_at`

var (
	certsList = tq("tenant_certificates.list", `
		SELECT `+certCols+` FROM tenant_certificates c WHERE c.tenant_id = @tenant ORDER BY c.purpose, c.created_at, c.id`)
	certsGet = tq("tenant_certificates.get", `
		SELECT `+certCols+` FROM tenant_certificates c WHERE c.tenant_id = @tenant AND c.id = @id`)
	certsKey = tq("tenant_certificates.key", `
		SELECT c.key_sealed FROM tenant_certificates c WHERE c.tenant_id = @tenant AND c.id = @id`)
	certsNextOf = tq("tenant_certificates.next_of", `
		SELECT `+certCols+` FROM tenant_certificates c
		WHERE c.tenant_id = @tenant AND c.idp_connection_id = @idp AND c.status = 'next'`)
	certsMTLSOf = tq("tenant_certificates.mtls_of", `
		SELECT `+certCols+` FROM tenant_certificates c
		WHERE c.tenant_id = @tenant AND c.purpose = 'mtls_client' AND c.status = 'active' AND c.connection_id = @connection
		ORDER BY c.activated_at DESC, c.id LIMIT 1`)
	certsInsert = tq("tenant_certificates.insert", `
		INSERT INTO tenant_certificates (id, tenant_id, purpose, label, idp_connection_id, connection_id, status, cert_pem,
			trust_pem, key_sealed, subject, issuer, sans, not_before, not_after, fingerprint, key_algorithm, sig_algorithm, created_by,
			created_at, activated_at, retired_at)
		VALUES (@id, @tenant, @purpose, @label, @idp, @connection, @status, @cert_pem, @trust_pem, @key_sealed, @subject, @issuer, @sans,
			@not_before, @not_after, @fingerprint, @key_algorithm, @sig_algorithm, @created_by, @created_at, @activated_at,
			@retired_at)`)
	certsActivate = tq("tenant_certificates.activate", `
		UPDATE tenant_certificates SET status = 'active', activated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'next'`)
	certsRetire = tq("tenant_certificates.retire", `
		UPDATE tenant_certificates SET status = 'retired', retired_at = @now, key_sealed = NULL
		WHERE tenant_id = @tenant AND id = @id AND status IN ('next', 'active')`)
	idpSetSPKey = tq("idp_connections.set_sp_key", `
		UPDATE idp_connections SET sp_key_enc = @key, sp_cert_pem = @cert, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND protocol = 'saml'`)
)

func scanCert(s scanner) (*TenantCertificate, error) {
	var c TenantCertificate
	var idp, conn sql.NullString
	var sans string
	var nb, na, created string
	var act, ret sql.NullString
	if err := s.Scan(&c.ID, &c.Purpose, &c.Label, &idp, &conn, &c.Status, &c.CertPEM, &c.TrustPEM, &c.Subject, &c.Issuer, &sans, &nb, &na,
		&c.Fingerprint, &c.KeyAlgorithm, &c.SigAlgorithm, &c.CreatedBy, &created, &act, &ret); err != nil {
		return nil, err
	}
	c.IdPConnectionID, c.ConnectionID = strp(idp), strp(conn)
	if err := json.Unmarshal([]byte(sans), &c.SANs); err != nil {
		return nil, err
	}
	var err error
	if c.NotBefore, err = ParseRT(nb); err != nil {
		return nil, err
	}
	if c.NotAfter, err = ParseRT(na); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if c.ActivatedAt, err = rtp(act); err != nil {
		return nil, err
	}
	c.RetiredAt, err = rtp(ret)
	return &c, err
}

// Certificates lists the tenant's certificates (no key material).
func (tx *TenantTx) Certificates() ([]*TenantCertificate, error) {
	return collect(tx, scanCert, certsList)
}

// Certificate returns one certificate (no key material), or ErrNotFound.
func (tx *TenantTx) Certificate(id string) (*TenantCertificate, error) {
	return one(tx, scanCert, certsGet, sql.Named("id", id))
}

// CertificateKey returns the sealed private key of a certificate (nil once it is retired).
func (tx *TenantTx) CertificateKey(id string) ([]byte, error) {
	var b []byte
	err := tx.queryRow(certsKey, sql.Named("id", id)).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return b, err
}

// ActiveMTLSCertificate returns the mutual-TLS certificate a connection presents (the newest active one that
// names it), or ErrNotFound. Its key is read with CertificateKey.
func (tx *TenantTx) ActiveMTLSCertificate(connectionID string) (*TenantCertificate, error) {
	return one(tx, scanCert, certsMTLSOf, sql.Named("connection", connectionID))
}

// NextSAMLCertificate returns the key waiting to be promoted on a SAML connection, or ErrNotFound.
func (tx *TenantTx) NextSAMLCertificate(idp uuid.UUID) (*TenantCertificate, error) {
	return one(tx, scanCert, certsNextOf, sql.Named("idp", idp.String()))
}

// InsertCertificate adds a certificate (ErrDuplicate if this tenant already holds it for that purpose, or a
// SAML connection already has one waiting).
func (tx *TenantTx) InsertCertificate(c *TenantCertificate) error {
	sans, err := json.Marshal(append([]string{}, c.SANs...))
	if err != nil {
		return err
	}
	var key any
	if len(c.KeySealed) > 0 {
		key = c.KeySealed
	}
	_, err = tx.exec(certsInsert, sql.Named("id", c.ID), sql.Named("purpose", c.Purpose), sql.Named("label", c.Label),
		sql.Named("idp", SP(c.IdPConnectionID)), sql.Named("connection", SP(c.ConnectionID)), sql.Named("status", c.Status),
		sql.Named("cert_pem", c.CertPEM), sql.Named("trust_pem", c.TrustPEM), sql.Named("key_sealed", key), sql.Named("subject", c.Subject),
		sql.Named("issuer", c.Issuer), sql.Named("sans", string(sans)), sql.Named("not_before", RT(c.NotBefore)),
		sql.Named("not_after", RT(c.NotAfter)), sql.Named("fingerprint", c.Fingerprint),
		sql.Named("key_algorithm", c.KeyAlgorithm), sql.Named("sig_algorithm", c.SigAlgorithm),
		sql.Named("created_by", c.CreatedBy), sql.Named("created_at", RT(c.CreatedAt)), sql.Named("activated_at", RTP(c.ActivatedAt)),
		sql.Named("retired_at", RTP(c.RetiredAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// ActivateCertificate makes a 'next' certificate 'active' (ErrNotFound if it is not 'next').
func (tx *TenantTx) ActivateCertificate(id string, now time.Time) error {
	return tx.execOne(certsActivate, sql.Named("id", id), sql.Named("now", RT(now)))
}

// RetireCertificate retires a 'next' or 'active' certificate and empties its key (ErrNotFound otherwise).
func (tx *TenantTx) RetireCertificate(id string, now time.Time) error {
	return tx.execOne(certsRetire, sql.Named("id", id), sql.Named("now", RT(now)))
}

// SetIdPSPKey replaces the SP signing key and certificate of a SAML connection (the promotion of a rotated key).
func (tx *TenantTx) SetIdPSPKey(id uuid.UUID, keyEnc []byte, certPEM string, now time.Time) error {
	return tx.execOne(idpSetSPKey, sql.Named("id", id.String()), sql.Named("key", keyEnc), sql.Named("cert", certPEM),
		sql.Named("now", RT(now)))
}
