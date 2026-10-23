package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// A mutual-TLS certificate is uploaded as a chain (the leaf first, then the
// intermediates its issuer needs to be trusted), and may come with trust
// anchors: the CA certificates the target's server certificate must chain to.
// Without trust anchors the system roots apply.

// Limits of a chain and of a trust-anchor bundle.
const (
	MaxChainCerts   = 5
	MaxTrustAnchors = 10
)

// parseBundle reads every certificate of a PEM bundle, refusing anything else in it.
func parseBundle(field, s string, max int) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(s))
	var out []*x509.Certificate
	for len(rest) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, refuse("bad_pem", "%s is not PEM", field)
		}
		if b.Type != "CERTIFICATE" {
			return nil, refuse("bad_pem", "%s holds a %q block; send certificates only, never a key", field, b.Type)
		}
		if len(out) == max {
			return nil, refuse("bad_pem", "%s has more than %d certificates", field, max)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, refuse("bad_cert", "%s: a certificate cannot be parsed: %v", field, err)
		}
		out = append(out, c)
		rest = []byte(strings.TrimSpace(string(rest)))
	}
	return out, nil
}

func encodeBundle(cs []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range cs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

func selfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// ParseMTLS validates a mutual-TLS upload: the chain (the leaf first) with its
// private key, and optional trust anchors. Beyond the rules of Parse for the
// leaf: each certificate after the leaf must be a CA that signed the one before
// it and must not be expired, a self-signed root may stay out (the target
// trusts it already), and every trust anchor must be a CA certificate that has
// not expired. The returned Parsed has the chain in CertPEM and the anchors in TrustPEM.
func ParseMTLS(chainPEM, trustPEM, keyPEM string, now time.Time) (*Parsed, error) {
	if len(chainPEM) > MaxPEMBytes || len(trustPEM) > MaxPEMBytes {
		return nil, &Error{Status: 413, Code: "cert_too_large", Msg: fmt.Sprintf("the chain and the trust anchors are each at most %d KiB", MaxPEMBytes>>10)}
	}
	chain, err := parseBundle("the certificate", chainPEM, MaxChainCerts)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, refuse("bad_pem", "a PEM certificate is required")
	}
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		if !c.IsCA {
			return nil, refuse("bad_chain", "certificate %d of the chain is not a CA certificate", i+1)
		}
		if !now.Before(c.NotAfter) {
			return nil, refuse("cert_expired", "certificate %d of the chain expired on %s", i+1, c.NotAfter.UTC().Format("2006-01-02"))
		}
		if err := chain[i-1].CheckSignatureFrom(c); err != nil {
			return nil, refuse("bad_chain", "certificate %d of the chain did not sign certificate %d: send the leaf first, then each issuer", i+1, i)
		}
	}
	// the leaf goes through the same checks as a single upload
	p, err := Parse(encodeBundle(chain[:1]), keyPEM, now, false)
	if err != nil {
		return nil, err
	}
	p.CertPEM = encodeBundle(chain)
	anchors, err := parseBundle("the trust anchors", trustPEM, MaxTrustAnchors)
	if err != nil {
		return nil, err
	}
	for i, a := range anchors {
		if !a.IsCA || !a.BasicConstraintsValid {
			return nil, refuse("bad_trust_anchor", "trust anchor %d is not a CA certificate", i+1)
		}
		if !now.Before(a.NotAfter) {
			return nil, refuse("cert_expired", "trust anchor %d expired on %s", i+1, a.NotAfter.UTC().Format("2006-01-02"))
		}
	}
	p.TrustPEM = encodeBundle(anchors)
	return p, nil
}

// TrustPool returns the pool of a stored trust-anchor bundle, or nil (use the system roots) for none.
func TrustPool(trustPEM string) (*x509.CertPool, error) {
	if strings.TrimSpace(trustPEM) == "" {
		return nil, nil
	}
	return ParseCAs(trustPEM)
}

// ParseCAs reads a PEM bundle into a pool.
func ParseCAs(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, fmt.Errorf("no certificates in the trust anchors")
	}
	return pool, nil
}
