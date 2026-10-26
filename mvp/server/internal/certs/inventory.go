package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Sources of an inventory entry.
const (
	SourceSAMLConnection = "saml_connection" // the SP key a SAML connection signs with now
	SourceUploaded       = "uploaded"        // tenant_certificates
	SourceSigningKey     = "signing_key"     // tenant_signing_keys (internal/keys): a public key only
	SourceDirectoryAgent = "directory_agent" // the pinned mTLS client key of a directory agent
)

// Entry is one certificate or key Tessera holds. Key material is never part of it.
type Entry struct {
	ID           string // conn:<idp connection id> | cert:<id> | key:<kid> | agent:<id>
	Source       string
	Purpose      string // saml_sp | mtls_client | signing | encryption
	Label        string
	Status       string // next | active | retired
	UsedBy       string // where it is used, for a person to read
	Subject      string
	Issuer       string
	SANs         []string
	NotBefore    *time.Time // nil for a key without a certificate
	NotAfter     *time.Time
	Fingerprint  string
	KeyAlgorithm string
	SigAlgorithm string
	IdPConnID    *string // the SAML connection of a saml_sp entry
	Manageable   bool    // an uploaded row: it can be promoted or retired
	// Chain is how many certificates an mtls_client upload holds (the leaf and its intermediates); Anchors are the
	// subjects of its trust anchors. Both are zero for every other entry.
	Chain   int
	Anchors []string
}

// Inventory lists every certificate and key Tessera holds for the tenant, ordered by purpose and label.
func Inventory(tx *store.TenantTx, now time.Time) ([]Entry, error) {
	idps, err := tx.IdPConnections()
	if err != nil {
		return nil, err
	}
	idpName := map[string]string{}
	var out []Entry
	live := map[string]bool{} // purpose/connection/fingerprint of the certificate a connection signs with now
	for _, c := range idps {
		idpName[c.ID.String()] = c.Name
		if c.Protocol != "saml" || c.SPCertPEM == nil || *c.SPCertPEM == "" {
			continue
		}
		id := c.ID.String()
		e := Entry{ID: "conn:" + id, Source: SourceSAMLConnection, Purpose: store.CertSAMLSP, Label: c.Name + " SP signing",
			Status: store.CertActive, UsedBy: "Signs SAML requests for " + c.Name + "; published in its SP metadata", IdPConnID: &id}
		if cert, ok := firstCert(*c.SPCertPEM); ok {
			fill(&e, Describe(cert))
			live[id+"/"+e.Fingerprint] = true
		} else {
			e.Subject = "(certificate unreadable)"
		}
		out = append(out, e)
	}
	conns, err := tx.Connections()
	if err != nil {
		return nil, err
	}
	connName := map[string]string{}
	for _, c := range conns {
		connName[c.ID] = c.Name
	}
	rows, err := tx.Certificates()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Purpose == store.CertSAMLSP && r.IdPConnectionID != nil && r.Status == store.CertActive && live[*r.IdPConnectionID+"/"+r.Fingerprint] {
			continue // the connection entry above is this certificate
		}
		nb, na := r.NotBefore, r.NotAfter
		e := Entry{ID: "cert:" + r.ID, Source: SourceUploaded, Purpose: r.Purpose, Label: r.Label, Status: r.Status, Subject: r.Subject,
			Issuer: r.Issuer, SANs: r.SANs, NotBefore: &nb, NotAfter: &na, Fingerprint: r.Fingerprint, KeyAlgorithm: r.KeyAlgorithm,
			SigAlgorithm: r.SigAlgorithm, IdPConnID: r.IdPConnectionID, Manageable: true, UsedBy: usedBy(r, idpName, connName)}
		if r.Purpose == store.CertMTLSClient {
			chain, _ := parseBundle("chain", r.CertPEM, MaxChainCerts)
			e.Chain = len(chain)
			anchors, _ := parseBundle("anchors", r.TrustPEM, MaxTrustAnchors)
			e.Anchors = []string{}
			for _, a := range anchors {
				e.Anchors = append(e.Anchors, a.Subject.String())
			}
		}
		out = append(out, e)
	}
	for _, purpose := range []string{"access_token", "idp_client_auth", "aws_federation"} {
		ks, err := tx.SigningKeys(purpose)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			if k.Status == store.KeyRevoked {
				continue
			}
			sum := sha256.Sum256(k.PublicJWK)
			use := "Signs access tokens Tessera issues; the public key is in the tenant JWKS"
			switch purpose {
			case "idp_client_auth":
				use = "Signs client assertions to identity providers (private_key_jwt)"
			case "aws_federation":
				use = "Signs the web identity tokens AWS federation exchanges for read-only roles; the public key is in the AWS issuer JWKS"
			}
			out = append(out, Entry{ID: "key:" + k.KID, Source: SourceSigningKey, Purpose: store.CertSigning, Label: k.KID, Status: k.Status,
				UsedBy: use, Subject: "JWK " + k.KID, Fingerprint: hex.EncodeToString(sum[:]), KeyAlgorithm: k.Alg})
		}
	}
	agents, err := tx.DirectoryAgents()
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		if a.Status != "active" || a.CertPin == "" {
			continue
		}
		out = append(out, Entry{ID: "agent:" + a.ID, Source: SourceDirectoryAgent, Purpose: store.CertMTLSClient, Label: a.Name,
			Status: store.CertActive, UsedBy: "Mutual TLS from directory agent " + a.Name + " (Tessera pins its public key)",
			Subject: "SPKI pin of " + a.Name, Fingerprint: a.CertPin, KeyAlgorithm: "pinned public key"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Purpose != out[j].Purpose {
			return out[i].Purpose < out[j].Purpose
		}
		return out[i].Label < out[j].Label
	})
	return out, nil
}

func usedBy(r *store.TenantCertificate, idpName, connName map[string]string) string {
	switch r.Purpose {
	case store.CertSAMLSP:
		name := "a SAML connection"
		if r.IdPConnectionID != nil && idpName[*r.IdPConnectionID] != "" {
			name = idpName[*r.IdPConnectionID]
		}
		switch r.Status {
		case store.CertNext:
			return "Published in the SP metadata of " + name + " beside the active certificate, waiting to be promoted"
		case store.CertRetired:
			return "Was the SP signing certificate of " + name
		}
		return "SP signing certificate of " + name
	case store.CertMTLSClient:
		if r.ConnectionID != nil && connName[*r.ConnectionID] != "" {
			return "Mutual TLS client certificate presented by the target of connection " + connName[*r.ConnectionID]
		}
		return "Mutual TLS client certificate (not assigned to a connector)"
	case store.CertEncryption:
		return "Encryption certificate"
	}
	return "Signing certificate"
}

func fill(e *Entry, i Info) {
	nb, na := i.NotBefore, i.NotAfter
	e.Subject, e.Issuer, e.SANs, e.NotBefore, e.NotAfter = i.Subject, i.Issuer, i.SANs, &nb, &na
	e.Fingerprint, e.KeyAlgorithm, e.SigAlgorithm = i.Fingerprint, i.KeyAlgorithm, i.SigAlgorithm
}

func firstCert(p string) (*x509.Certificate, bool) {
	b, _ := pem.Decode([]byte(p))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, false
	}
	c, err := x509.ParseCertificate(b.Bytes)
	return c, err == nil
}

// Expiring lists the certificates in use (active or waiting) that expire within 30 days or already have.
func Expiring(tx *store.TenantTx, now time.Time) ([]Entry, error) {
	all, err := Inventory(tx, now)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if e.NotAfter == nil || e.Status == store.CertRetired || Bucket(now, *e.NotAfter) == 0 {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ExpiryTitle is the alert title of an expiring certificate.
func ExpiryTitle(e Entry, now time.Time) string {
	d := DaysLeft(now, *e.NotAfter)
	if d < 0 {
		return fmt.Sprintf("Certificate %q expired %d days ago", e.Label, -d)
	}
	return fmt.Sprintf("Certificate %q expires in %d days", e.Label, d)
}
