// Package ghapp is Tessera's GitHub App client for policy pull requests (issue #656, AC-10): it signs a short-lived
// App JWT, exchanges it for an installation token limited to one repository and the two permissions the check needs,
// and posts a check run and one pull request comment that it updates in place. It replaces the stored personal token
// of internal/prcomment.
//
// Everything goes through a client from internal/safehttp. The private key lives in memory only while a JWT is signed;
// the key, the JWT and the installation token never appear in an error, a log line or a returned value (errors carry a
// status or a fixed code, never a response body).
package ghapp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"time"
)

// Bounds.
const (
	// MaxKeyPEMBytes bounds an uploaded private key (a 4096-bit RSA key in PEM is about 3.3 KiB).
	MaxKeyPEMBytes = 8 << 10
	// MinKeyBits is the smallest RSA key accepted (GitHub issues 2048-bit keys).
	MinKeyBits = 2048
	// MaxKeyBits bounds signing cost.
	MaxKeyBits = 8192

	// JWTBackdate is how far iat is set in the past, to absorb clock drift (GitHub: "60 seconds in the past").
	JWTBackdate = 60 * time.Second
	// JWTLifetime is exp - iat, so exp is JWTLifetime - JWTBackdate (8 minutes) after the signer's clock. GitHub allows
	// exp at most 10 minutes after its own clock: this stays inside that even when the local clock runs up to 60 s
	// fast (iat is backdated by that much, and exp is measured from iat, not from now).
	JWTLifetime = 9 * time.Minute
)

var appIDRE = regexp.MustCompile(`^[0-9]{1,20}$`)

// Errors of the key and the App id.
var (
	ErrAppID = errors.New("ghapp: app id must be the digits GitHub shows on the App's page")
	ErrKey   = errors.New("ghapp: not a usable RSA private key (PEM, PKCS#1 or PKCS#8, 2048 bits or more)")
)

// ValidAppID reports whether id is a GitHub App id.
func ValidAppID(id string) bool { return appIDRE.MatchString(id) }

// ParseKey reads the PEM of an App's private key. Only an RSA key of MinKeyBits to MaxKeyBits is accepted; the error
// never carries the input.
func ParseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	if len(pemBytes) == 0 || len(pemBytes) > MaxKeyPEMBytes {
		return nil, ErrKey
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrKey
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrKey
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrKey
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrKey
		}
		key = rk
	default:
		return nil, ErrKey
	}
	if bits := key.N.BitLen(); bits < MinKeyBits || bits > MaxKeyBits || key.Validate() != nil {
		return nil, ErrKey
	}
	return key, nil
}

// Fingerprint is the SHA-256 fingerprint GitHub shows next to a private key of an App: the digest of the key's
// PKCS#8 DER, base64 encoded ("SHA256:..."). It identifies a key without revealing it, so the settings can say which
// key is stored and an operator can compare it with the App's page after a rotation.
func Fingerprint(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// AppJWT signs the JWT that authenticates as the App (RS256): iss is the App id, iat is JWTBackdate in the past and
// exp is JWTLifetime after iat (8 minutes after now), so it is valid for under 10 minutes. It is signed in memory and meant to be used at once.
func AppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	if !ValidAppID(appID) {
		return "", ErrAppID
	}
	if key == nil {
		return "", ErrKey
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	iat := now.Add(-JWTBackdate)
	claims, err := json.Marshal(map[string]any{"iat": iat.Unix(), "exp": iat.Add(JWTLifetime).Unix(), "iss": appID})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("ghapp: signing failed")
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
