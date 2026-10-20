package certs

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// KeyAAD binds a sealed certificate key (tenant_certificates.key_sealed) to its tenant and row.
func KeyAAD(t tenancy.ID, id string) []byte {
	return seal.AAD(t, "tenant_certificates", "key_sealed", id)
}

// Upload is an uploaded certificate with its private key.
type Upload struct {
	Purpose         string
	Label           string
	CertPEM         string
	KeyPEM          string
	IdPConnectionID *uuid.UUID // saml_sp: the connection it will sign for
	ConnectionID    *string    // mtls_client: the connector that uses it (optional)
}

func conflict(code, msg string) error {
	return &Error{Status: http.StatusConflict, Code: code, Msg: msg}
}

func notFound(what string) error {
	return &Error{Status: http.StatusNotFound, Code: "not_found", Msg: what + " not found"}
}

func cleanLabel(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > MaxLabel {
		return "", refuse("invalid_label", "the label is 1 to %d characters", MaxLabel)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", refuse("invalid_label", "the label cannot contain control characters")
		}
	}
	return s, nil
}

func sealKey(sl *seal.Sealer, tenant tenancy.ID, id string, keyPEM []byte) ([]byte, error) {
	if sl == nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Code: "sealing_unavailable", Msg: "no key-encryption key is configured, so a private key cannot be stored"}
	}
	return sl.Seal(keyPEM, KeyAAD(tenant, id))
}

func detail(c *store.TenantCertificate, extra ...ojson.KV) ojson.Object {
	d := ojson.Object{{Key: "certificate_id", Value: c.ID}, {Key: "purpose", Value: c.Purpose}, {Key: "label", Value: c.Label},
		{Key: "fingerprint", Value: c.Fingerprint}, {Key: "not_after", Value: store.RT(c.NotAfter)}}
	if c.IdPConnectionID != nil {
		d = append(d, ojson.KV{Key: "connection_id", Value: *c.IdPConnectionID})
	}
	return append(d, extra...)
}

func record(tx *store.TenantTx, id, label, purpose string, p *Parsed, by string, now time.Time) *store.TenantCertificate {
	i := p.Info
	return &store.TenantCertificate{ID: id, Purpose: purpose, Label: label, Subject: i.Subject, Issuer: i.Issuer, SANs: i.SANs,
		NotBefore: i.NotBefore, NotAfter: i.NotAfter, Fingerprint: i.Fingerprint, KeyAlgorithm: i.KeyAlgorithm,
		SigAlgorithm: i.SigAlgorithm, CertPEM: p.CertPEM, CreatedBy: by, CreatedAt: now}
}

func samlConnection(tx *store.TenantTx, id uuid.UUID) (*store.IdPConnection, error) {
	c, err := tx.IdPConnection(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("SAML connection")
	} else if err != nil {
		return nil, err
	}
	if c.Protocol != "saml" {
		return nil, refuse("not_saml", "%q is not a SAML connection", c.Name)
	}
	return c, nil
}

func insert(tx *store.TenantTx, c *store.TenantCertificate) error {
	if err := tx.InsertCertificate(c); errors.Is(err, store.ErrDuplicate) {
		if c.Purpose == store.CertSAMLSP {
			return conflict("rotation_in_progress", "this connection already has a certificate waiting to be promoted, or this certificate was used before")
		}
		return conflict("duplicate_certificate", "this certificate is already stored")
	} else if err != nil {
		return err
	}
	return nil
}

// UploadCertificate validates and stores an uploaded certificate with its key. A SAML SP certificate becomes
// 'next' (published in the SP metadata beside the active one until it is promoted); the other purposes are
// active at once. The audit event is written in the caller's transaction.
func UploadCertificate(tx *store.TenantTx, sl *seal.Sealer, u Upload, by string, now time.Time) (*store.TenantCertificate, error) {
	switch u.Purpose {
	case store.CertSAMLSP, store.CertMTLSClient, store.CertSigning, store.CertEncryption:
	default:
		return nil, refuse("invalid_purpose", "purpose is saml_sp, mtls_client, signing or encryption")
	}
	label, err := cleanLabel(u.Label)
	if err != nil {
		return nil, err
	}
	if (u.Purpose == store.CertSAMLSP) != (u.IdPConnectionID != nil) {
		return nil, refuse("invalid_connection", "a saml_sp certificate names its SAML connection, and no other purpose does")
	}
	if u.ConnectionID != nil && u.Purpose != store.CertMTLSClient {
		return nil, refuse("invalid_connection", "only an mtls_client certificate names a connector")
	}
	p, err := Parse(u.CertPEM, u.KeyPEM, now, u.Purpose == store.CertSAMLSP)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	c := record(tx, id, label, u.Purpose, p, by, now)
	switch u.Purpose {
	case store.CertSAMLSP:
		conn, err := samlConnection(tx, *u.IdPConnectionID)
		if err != nil {
			return nil, err
		}
		if cur, ok := firstCert(deref(conn.SPCertPEM)); ok && Describe(cur).Fingerprint == c.Fingerprint {
			return nil, conflict("same_certificate", "this is the certificate the connection already signs with")
		}
		s := u.IdPConnectionID.String()
		c.IdPConnectionID, c.Status = &s, store.CertNext
	case store.CertMTLSClient:
		if u.ConnectionID != nil {
			if _, err := tx.Connection(*u.ConnectionID); errors.Is(err, store.ErrNotFound) {
				return nil, notFound("connector")
			} else if err != nil {
				return nil, err
			}
			c.ConnectionID = u.ConnectionID
		}
		fallthrough
	default:
		c.Status = store.CertActive
		c.ActivatedAt = &now
	}
	if c.KeySealed, err = sealKey(sl, tx.Tenant(), id, p.KeyPEM); err != nil {
		return nil, err
	}
	if err := insert(tx, c); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "certificate.uploaded", detail(c, ojson.KV{Key: "status", Value: c.Status},
		ojson.KV{Key: "key_algorithm", Value: c.KeyAlgorithm})); err != nil {
		return nil, err
	}
	c.KeySealed = nil
	return c, nil
}

// GenerateSAML creates a new SP key pair for a SAML connection as 'next': it is published in the SP metadata
// beside the active certificate (the overlap window) until it is promoted.
func GenerateSAML(tx *store.TenantTx, sl *seal.Sealer, conn uuid.UUID, by string, now time.Time) (*store.TenantCertificate, error) {
	c, err := samlConnection(tx, conn)
	if err != nil {
		return nil, err
	}
	keyPEM, certPEM, err := samlsp.GenerateSPKey(c.Name, now)
	if err != nil {
		return nil, err
	}
	p, err := Parse(certPEM, string(keyPEM), now, true)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	row := record(tx, id, "SP key generated "+now.UTC().Format("2006-01-02"), store.CertSAMLSP, p, by, now)
	s := conn.String()
	row.IdPConnectionID, row.Status = &s, store.CertNext
	if row.KeySealed, err = sealKey(sl, tx.Tenant(), id, p.KeyPEM); err != nil {
		return nil, err
	}
	if err := insert(tx, row); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "certificate.generated", detail(row, ojson.KV{Key: "status", Value: row.Status})); err != nil {
		return nil, err
	}
	row.KeySealed = nil
	return row, nil
}

// Promote makes a waiting SAML SP certificate the one its connection signs with and retires the old one. Both
// were published in the SP metadata until now, so identity providers that imported the metadata keep working.
func Promote(tx *store.TenantTx, sl *seal.Sealer, id string, by string, now time.Time) (*store.TenantCertificate, error) {
	c, err := tx.Certificate(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("certificate")
	} else if err != nil {
		return nil, err
	}
	if c.Purpose != store.CertSAMLSP || c.Status != store.CertNext || c.IdPConnectionID == nil {
		return nil, conflict("not_waiting", "only a SAML SP certificate waiting to be promoted can be promoted")
	}
	connID, err := uuid.Parse(*c.IdPConnectionID)
	if err != nil {
		return nil, err
	}
	conn, err := samlConnection(tx, connID)
	if err != nil {
		return nil, err
	}
	if sl == nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Code: "sealing_unavailable", Msg: "no key-encryption key is configured"}
	}
	sealed, err := tx.CertificateKey(id)
	if err != nil {
		return nil, err
	}
	keyPEM, err := sl.Open(sealed, KeyAAD(tx.Tenant(), id))
	if err != nil {
		return nil, err
	}
	resealed, err := sl.Seal(keyPEM, auth.SPKeyAAD(tx.Tenant(), connID))
	if err != nil {
		return nil, err
	}
	// the old certificate becomes (or, if it came from an earlier promotion, already is) a row, then retires
	var oldFP string
	if old, ok := firstCert(deref(conn.SPCertPEM)); ok {
		oldFP = Describe(old).Fingerprint
		rows, err := tx.Certificates()
		if err != nil {
			return nil, err
		}
		found := false
		for _, r := range rows {
			if r.Purpose == store.CertSAMLSP && r.Fingerprint == oldFP && r.IdPConnectionID != nil && *r.IdPConnectionID == *c.IdPConnectionID && r.Status == store.CertActive {
				found = true
				if err := tx.RetireCertificate(r.ID, now); err != nil {
					return nil, err
				}
			}
		}
		if !found {
			i := Describe(old)
			s := connID.String()
			ret := &store.TenantCertificate{ID: uuid.NewString(), Purpose: store.CertSAMLSP, Label: "Previous SP certificate of " + conn.Name,
				IdPConnectionID: &s, Status: store.CertRetired, CertPEM: deref(conn.SPCertPEM), Subject: i.Subject, Issuer: i.Issuer,
				SANs: i.SANs, NotBefore: i.NotBefore, NotAfter: i.NotAfter, Fingerprint: i.Fingerprint, KeyAlgorithm: i.KeyAlgorithm,
				SigAlgorithm: i.SigAlgorithm, CreatedBy: by, CreatedAt: now, RetiredAt: &now}
			if len(ret.Label) > MaxLabel {
				ret.Label = ret.Label[:MaxLabel]
			}
			if err := insert(tx, ret); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.ActivateCertificate(id, now); err != nil {
		return nil, err
	}
	if err := tx.SetIdPSPKey(connID, resealed, c.CertPEM, now); err != nil {
		return nil, err
	}
	c.Status, c.ActivatedAt = store.CertActive, &now
	if err := tx.Audit(now, by, "certificate.promoted", detail(c, ojson.KV{Key: "retired_fingerprint", Value: oldFP})); err != nil {
		return nil, err
	}
	return c, nil
}

// Retire retires an uploaded certificate (or discards one waiting to be promoted) and destroys its stored key.
// The certificate a SAML connection signs with now cannot be retired: promote a replacement first.
func Retire(tx *store.TenantTx, id string, by string, now time.Time) (*store.TenantCertificate, error) {
	c, err := tx.Certificate(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("certificate")
	} else if err != nil {
		return nil, err
	}
	if c.Status == store.CertRetired {
		return nil, conflict("already_retired", "the certificate is already retired")
	}
	if c.Purpose == store.CertSAMLSP && c.Status == store.CertActive {
		return nil, conflict("in_use", "this is the certificate the connection signs with; promote a replacement first")
	}
	if err := tx.RetireCertificate(id, now); err != nil {
		return nil, err
	}
	c.Status, c.RetiredAt = store.CertRetired, &now
	if err := tx.Audit(now, by, "certificate.retired", detail(c)); err != nil {
		return nil, err
	}
	return c, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
