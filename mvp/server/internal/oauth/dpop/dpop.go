// Package dpop validates DPoP proofs (RFC 9449 §4.3; design
// docs/design/phase-0-platform-security.md §10.5). Neither zitadel/oidc nor
// fosite implements RFC 9449, so this is our own, on go-jose v4.
//
// A proof is a compact JWS whose protected header carries the public key
// (jwk) and typ dpop+jwt. ValidateProof checks, in this order: one DPoP
// header of at most 4 KiB; a compact JWS with exactly one signature and an
// ES256 or EdDSA algorithm; typ; a public EC P-256 or OKP Ed25519 jwk that
// matches alg, and no kid, jku, x5u, x5c or crit; the signature; jti, htm,
// htu and iat; the server nonce when required; ath when an access token is
// presented; the key thumbprint against the bound one; and finally that the
// (key, jti) pair was not seen in the last 120 s. A proof that fails any
// earlier check never reaches the replay cache.
package dpop

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Limits and windows (§10.2).
const (
	MaxProofBytes = 4 << 10
	MaxJTIBytes   = 64
	// IATPast and IATFuture bound the proof's iat around the server clock.
	IATPast   = 60 * time.Second
	IATFuture = 5 * time.Second
	// ReplayTTL is how long a (key, jti) pair is remembered.
	ReplayTTL = 120 * time.Second
	// NonceBucket is the nonce rotation period; the current and the previous
	// nonce are accepted.
	NonceBucket = 5 * time.Minute
)

// Error codes (RFC 9449 §5, §8).
const (
	CodeInvalidProof = "invalid_dpop_proof"
	CodeUseNonce     = "use_dpop_nonce"
)

// ProofError is a refused proof. NewNonce is set for use_dpop_nonce (the
// caller sends it in the DPoP-Nonce header).
type ProofError struct {
	Code        string
	Description string
	NewNonce    string
}

func (e *ProofError) Error() string { return e.Code + ": " + e.Description }

func invalid(format string, a ...any) *ProofError {
	return &ProofError{Code: CodeInvalidProof, Description: fmt.Sprintf(format, a...)}
}

// ErrReplay is returned by a ReplayCache for a key it has already seen.
var ErrReplay = errors.New("dpop: proof already used")

// ReplayCache remembers (key, jti) pairs until they expire. UseOnce returns
// ErrReplay when keyHash (SHA-256 hex) was already recorded and has not
// expired; any other error is an infrastructure failure.
type ReplayCache interface {
	UseOnce(ctx context.Context, keyHash string, now, expires time.Time) error
}

// Validator validates proofs.
type Validator struct {
	Replay ReplayCache
	// NonceKey is the HMAC key of the stateless server nonces (derived from
	// the KEK with the label "dpop-nonce"). Empty: nonces are never required.
	NonceKey []byte
}

// ProofParams describe the request a proof must be bound to.
type ProofParams struct {
	Method string // r.Method
	// URL is TESSERA_PUBLIC_URL + r.URL.Path; never built from the Host header.
	URL         string
	AccessToken string // "" at /token
	ExpectedJKT string // "" when not bound yet
	// RequireNonce makes a proof without a current server nonce fail with
	// use_dpop_nonce.
	RequireNonce bool
	Now          time.Time
}

// forbiddenHeaders are protected-header members a proof must not carry.
var forbiddenHeaders = []string{"kid", "jku", "x5u", "x5c", "x5t", "x5t#S256", "crit"}

// privateMembers are JWK members of private and symmetric keys (RFC 7518 §6).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ValidateProof validates the DPoP header of a request against p and returns
// the RFC 7638 thumbprint of the proof key. Errors are *ProofError, except an
// infrastructure failure of the replay cache, which is returned as is.
func (v *Validator) ValidateProof(ctx context.Context, headers http.Header, p ProofParams) (string, error) {
	vals := headers.Values("DPoP")
	if len(vals) != 1 {
		return "", invalid("exactly one DPoP header is required")
	}
	return v.validate(ctx, vals[0], p)
}

func (v *Validator) validate(ctx context.Context, proof string, p ProofParams) (string, error) {
	if len(proof) == 0 || len(proof) > MaxProofBytes {
		return "", invalid("the proof is empty or larger than %d bytes", MaxProofBytes)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", invalid("the proof is not a compact JWS")
	}
	// the protected header, read raw: go-jose drops x5c and keeps no raw view
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", invalid("the proof header is not base64url")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(hdrJSON, &raw); err != nil {
		return "", invalid("the proof header is not a JSON object")
	}
	for _, k := range forbiddenHeaders {
		if _, ok := raw[k]; ok {
			return "", invalid("the proof header must not contain %q", k)
		}
	}
	var jwkRaw map[string]json.RawMessage
	if b, ok := raw["jwk"]; ok && json.Unmarshal(b, &jwkRaw) == nil {
		for _, k := range privateMembers {
			if _, ok := jwkRaw[k]; ok {
				return "", invalid("the proof jwk must be a public key (it has the private member %q)", k)
			}
		}
	}
	var typ string
	if b, ok := raw["typ"]; !ok || json.Unmarshal(b, &typ) != nil || typ != "dpop+jwt" {
		return "", invalid("the proof header typ must be dpop+jwt")
	}
	jws, err := jose.ParseSignedCompact(proof, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA})
	if err != nil {
		return "", invalid("the proof is not a signed JWT with ES256 or EdDSA")
	}
	if len(jws.Signatures) != 1 {
		return "", invalid("the proof must have exactly one signature")
	}
	h := jws.Signatures[0].Header
	jwk := h.JSONWebKey
	if jwk == nil {
		return "", invalid("the proof header has no jwk")
	}
	if !jwk.IsPublic() || !jwk.Valid() {
		return "", invalid("the proof jwk must be a valid public key")
	}
	if err := checkKeyForAlg(jwk, h.Algorithm); err != nil {
		return "", err
	}
	payload, err := jws.Verify(jwk.Key)
	if err != nil {
		return "", invalid("the proof signature is invalid")
	}
	var c struct {
		JTI   *string  `json:"jti"`
		HTM   *string  `json:"htm"`
		HTU   *string  `json:"htu"`
		IAT   *float64 `json:"iat"`
		ATH   *string  `json:"ath"`
		Nonce *string  `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", invalid("the proof claims are not a JSON object")
	}
	if c.JTI == nil || *c.JTI == "" || len(*c.JTI) > MaxJTIBytes {
		return "", invalid("jti is missing or longer than %d characters", MaxJTIBytes)
	}
	if c.HTM == nil || *c.HTM != p.Method {
		return "", invalid("htm does not match the request method")
	}
	want, err := NormalizeHTU(p.URL)
	if err != nil {
		return "", invalid("the request URL cannot be normalized")
	}
	if c.HTU == nil {
		return "", invalid("htu is missing")
	}
	got, err := NormalizeHTU(*c.HTU)
	if err != nil || got != want {
		return "", invalid("htu does not match the request URL")
	}
	if c.IAT == nil {
		return "", invalid("iat is missing")
	}
	iat := time.Unix(int64(*c.IAT), 0)
	if iat.Before(p.Now.Add(-IATPast)) || iat.After(p.Now.Add(IATFuture)) {
		return "", invalid("iat is outside the accepted window")
	}
	if p.RequireNonce && len(v.NonceKey) > 0 {
		if c.Nonce == nil || !v.nonceValid(*c.Nonce, p.Now) {
			return "", &ProofError{Code: CodeUseNonce, Description: "a current server-provided nonce is required",
				NewNonce: v.NewNonce(p.Now)}
		}
	}
	if p.AccessToken != "" {
		if c.ATH == nil || subtle.ConstantTimeCompare([]byte(*c.ATH), []byte(AccessTokenHash(p.AccessToken))) != 1 {
			return "", invalid("ath does not match the access token")
		}
	}
	jkt, err := Thumbprint(jwk)
	if err != nil {
		return "", invalid("the proof key has no thumbprint")
	}
	if p.ExpectedJKT != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(p.ExpectedJKT)) != 1 {
		return "", invalid("the proof key is not the key the token is bound to")
	}
	if v.Replay != nil {
		sum := sha256.Sum256([]byte(jkt + "|" + *c.JTI))
		switch err := v.Replay.UseOnce(ctx, fmt.Sprintf("%x", sum), p.Now, p.Now.Add(ReplayTTL)); {
		case errors.Is(err, ErrReplay):
			return "", invalid("the proof was already used")
		case err != nil:
			return "", err
		}
	}
	return jkt, nil
}

// checkKeyForAlg requires an EC P-256 key for ES256 and an Ed25519 key for
// EdDSA, and nothing else.
func checkKeyForAlg(k *jose.JSONWebKey, alg string) error {
	switch alg {
	case string(jose.ES256):
		if k.Algorithm != "" && k.Algorithm != alg {
			return invalid("the proof jwk alg does not match")
		}
		if kt := jwkType(k); kt != "EC/P-256" {
			return invalid("an ES256 proof needs an EC P-256 key")
		}
	case string(jose.EdDSA):
		if k.Algorithm != "" && k.Algorithm != alg {
			return invalid("the proof jwk alg does not match")
		}
		if kt := jwkType(k); kt != "OKP/Ed25519" {
			return invalid("an EdDSA proof needs an Ed25519 key")
		}
	default:
		return invalid("unsupported proof algorithm")
	}
	return nil
}

// jwkType names the key family of k, "" for anything unexpected.
func jwkType(k *jose.JSONWebKey) string {
	b, err := k.MarshalJSON()
	if err != nil {
		return ""
	}
	var m struct{ Kty, Crv string }
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return m.Kty + "/" + m.Crv
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a key, base64url.
func Thumbprint(k *jose.JSONWebKey) (string, error) {
	b, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AccessTokenHash is the ath claim of an access token: base64url(SHA-256).
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NormalizeHTU reduces a URL to scheme://host[:port]/path: lower-case scheme
// and host, the default port dropped, no user info, query or fragment.
func NormalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" || u.User != nil {
		return "", errors.New("dpop: htu must be an absolute http(s) URL")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// ---------------------------------------------------------------- server nonces

// NewNonce returns the current server nonce:
// base64url(bucket || HMAC-SHA256(NonceKey, bucket)), bucket = floor(unix/300)
// as 8 big-endian bytes. It is "" without a NonceKey.
func (v *Validator) NewNonce(now time.Time) string {
	if len(v.NonceKey) == 0 {
		return ""
	}
	return v.nonceFor(now.Unix() / int64(NonceBucket/time.Second))
}

func (v *Validator) nonceFor(bucket int64) string {
	b := make([]byte, 8, 8+sha256.Size)
	binary.BigEndian.PutUint64(b, uint64(bucket)) // #nosec G115 -- bucket is a positive Unix time quotient
	m := hmac.New(sha256.New, v.NonceKey)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(m.Sum(b))
}

// nonceValid accepts the nonces of the current and the previous bucket.
func (v *Validator) nonceValid(nonce string, now time.Time) bool {
	if len(nonce) > 128 {
		return false
	}
	cur := now.Unix() / int64(NonceBucket/time.Second)
	for _, b := range []int64{cur, cur - 1} {
		if subtle.ConstantTimeCompare([]byte(nonce), []byte(v.nonceFor(b))) == 1 {
			return true
		}
	}
	return false
}
