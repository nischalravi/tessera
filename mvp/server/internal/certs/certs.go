// Package certs is the certificate inventory behind Admin > Certificates: it
// validates a certificate and private key an administrator uploads, lists
// every certificate Tessera holds (SAML SP keys on connections, uploaded and
// rotating certificates, signing keys, directory agent pins), rotates a SAML SP
// key through an overlap window and finds the ones about to expire.
//
// Rules for an upload: PEM only, one certificate, a private key that matches
// it, not expired, no SHA-1 or MD5 signature, RSA of at least 2048 bits (EC at
// least P-256), and a size cap. A SAML SP key must be RSA (internal/auth/samlsp
// signs with RSA). The private key is re-encoded as PKCS#8, sealed under the KEK
// (internal/seal) and never returned.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// Limits.
const (
	MaxPEMBytes  = 16 << 10 // each of the certificate and the key
	MinRSABits   = 2048
	MaxLabel     = 100
	ExpiryWarn30 = 30 // days: the first expiry warning
	ExpiryWarn7  = 7  // days: the last one
)

// Error is a refused upload or rotation; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Info is what is shown about a certificate.
type Info struct {
	Subject      string
	Issuer       string
	SANs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	Fingerprint  string // SHA-256 of the DER, lower-case hex
	KeyAlgorithm string // "RSA-2048", "ECDSA-P256", "Ed25519"
	SigAlgorithm string
}

// Describe reads the display fields of a certificate.
func Describe(c *x509.Certificate) Info {
	sum := sha256.Sum256(c.Raw)
	sans := []string{}
	for _, d := range c.DNSNames {
		sans = append(sans, "DNS:"+d)
	}
	for _, e := range c.EmailAddresses {
		sans = append(sans, "email:"+e)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, u := range c.URIs {
		sans = append(sans, "URI:"+u.String())
	}
	return Info{Subject: c.Subject.String(), Issuer: c.Issuer.String(), SANs: sans, NotBefore: c.NotBefore.UTC(),
		NotAfter: c.NotAfter.UTC(), Fingerprint: hex.EncodeToString(sum[:]), KeyAlgorithm: keyAlgorithm(c.PublicKey),
		SigAlgorithm: c.SignatureAlgorithm.String()}
}

func keyAlgorithm(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

// Parsed is a validated upload.
type Parsed struct {
	Cert    *x509.Certificate
	CertPEM string
	KeyPEM  []byte // PKCS#8 PEM: seal it, never return it
	Info    Info
}

// Parse validates an uploaded certificate and private key (PEM). now is the
// time "expired" is judged at. samlSP additionally requires an RSA key.
func Parse(certPEM, keyPEM string, now time.Time, samlSP bool) (*Parsed, error) {
	if len(certPEM) > MaxPEMBytes || len(keyPEM) > MaxPEMBytes {
		return nil, &Error{Status: http.StatusRequestEntityTooLarge, Code: "cert_too_large",
			Msg: fmt.Sprintf("the certificate and the key are each at most %d KiB", MaxPEMBytes>>10)}
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	if err := CheckStrength(cert, now); err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeyMatches(cert.PublicKey, key.Public()) {
		return nil, refuse("key_mismatch", "the private key does not belong to the certificate")
	}
	if samlSP {
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, refuse("key_not_rsa", "a SAML service-provider key must be RSA")
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, refuse("bad_key", "the private key cannot be used")
	}
	return &Parsed{Cert: cert, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), Info: Describe(cert)}, nil
}

func parseCert(s string) (*x509.Certificate, error) {
	rest, n := []byte(strings.TrimSpace(s)), 0
	var cert *x509.Certificate
	for len(rest) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, refuse("bad_pem", "the certificate is not PEM")
		}
		if b.Type != "CERTIFICATE" {
			return nil, refuse("bad_pem", "the certificate field holds a %q block; send the certificate only, never the key", b.Type)
		}
		n++
		if n > 1 {
			return nil, refuse("bad_pem", "send one certificate (the leaf), not a chain")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, refuse("bad_cert", "the certificate cannot be parsed: %v", err)
		}
		cert = c
		rest = []byte(strings.TrimSpace(string(rest)))
	}
	if cert == nil {
		return nil, refuse("bad_pem", "a PEM certificate is required")
	}
	return cert, nil
}

func parseKey(s string) (crypto.Signer, error) {
	b, rest := pem.Decode([]byte(strings.TrimSpace(s)))
	if b == nil || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, refuse("bad_pem", "the private key must be one PEM block")
	}
	if strings.Contains(b.Type, "ENCRYPTED") || b.Headers["Proc-Type"] != "" {
		return nil, refuse("bad_key", "an encrypted private key is not accepted; remove its passphrase first")
	}
	var k any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, refuse("bad_key", "unsupported private key type %q", b.Type)
	}
	if err != nil {
		return nil, refuse("bad_key", "the private key cannot be parsed")
	}
	s2, ok := k.(crypto.Signer)
	if !ok {
		return nil, refuse("bad_key", "the private key cannot sign")
	}
	return s2, nil
}

func publicKeyMatches(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	k, ok := a.(eq)
	return ok && k.Equal(b)
}

// CheckStrength refuses an expired certificate, a weak key and a SHA-1 or MD5 signature.
func CheckStrength(c *x509.Certificate, now time.Time) error {
	if !now.Before(c.NotAfter) {
		return refuse("cert_expired", "the certificate expired on %s", c.NotAfter.UTC().Format("2006-01-02"))
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return refuse("weak_key", "RSA keys must be at least %d bits (this one is %d)", MinRSABits, k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return refuse("weak_key", "EC keys must use P-256 or stronger")
		}
	case ed25519.PublicKey:
	default:
		return refuse("weak_key", "unsupported key type")
	}
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return refuse("weak_signature", "the certificate is signed with %s; SHA-1 and MD5 signatures are not accepted", c.SignatureAlgorithm)
	}
	return nil
}

// DaysLeft is the whole days until notAfter (negative once expired).
func DaysLeft(now, notAfter time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

// Bucket is the expiry warning a certificate is in: ExpiryWarn7 (7 days or
// fewer left, or expired), ExpiryWarn30 (30 days or fewer), or 0.
func Bucket(now, notAfter time.Time) int {
	left := notAfter.Sub(now)
	switch {
	case left <= ExpiryWarn7*24*time.Hour:
		return ExpiryWarn7
	case left <= ExpiryWarn30*24*time.Hour:
		return ExpiryWarn30
	}
	return 0
}
