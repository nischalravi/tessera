package oauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Client authentication with a signed JWT (RFC 7523 §2.2, OpenID Connect Core
// §9 private_key_jwt; design §9.5, §19 PR11). A machine client holds a private
// key and registers the public key (api_clients.jwks); each request to the
// token or introspection endpoint carries a short-lived assertion signed with
// it. No client secret exists, so there is nothing to store hashed or leak.
//
// The checks, each of which has a test (client_credentials_test.go):
//   - the algorithm is ES256 or EdDSA, and nothing else (no HS*, RS*, none);
//   - the header carries no jku, x5u, jwk, x5c or crit (a token never names or
//     carries its own key) and is not an at+jwt or dpop+jwt;
//   - the signature verifies with a key registered for this client;
//   - iss and sub are the client_id; aud is the URL of the endpoint the
//     assertion is sent to, exactly, as a single string;
//   - exp and iat are present, exp is in the future and exp - iat is at most
//     five minutes;
//   - jti is present and is accepted once (replay_cache, until exp).

// Limits of a client assertion.
const (
	// ClientAssertionType is the client_assertion_type of RFC 7523 §2.2.
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// MaxAssertionBytes bounds an assertion (a P-256 or Ed25519 signature
	// assertion is a few hundred bytes).
	MaxAssertionBytes = 4 << 10
	// MaxAssertionLifetime is the longest exp - iat accepted.
	MaxAssertionLifetime = 300 * time.Second
	// MaxJTIBytes bounds the jti claim.
	MaxJTIBytes = 128
	// assertionSkew is how far in the future iat and nbf may be.
	assertionSkew = 60 * time.Second
	// MaxClientKeys is the most keys a client may register (room for rotation).
	MaxClientKeys = 8
	// maxJWKSBytes bounds a registered key set.
	maxJWKSBytes = 16 << 10
)

// AssertionAlgs are the signature algorithms of a client assertion.
var AssertionAlgs = []string{"ES256", "EdDSA"}

var assertionJOSEAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA}

// forbiddenAssertionHeaders must not appear in an assertion's header.
var forbiddenAssertionHeaders = []string{"jku", "x5u", "jwk", "x5c", "x5t", "x5t#S256", "crit"}

// AssertionError is a refused client assertion. Reason is for the audit
// event and the operator; the client is only told invalid_client.
type AssertionError struct{ Reason string }

func (e *AssertionError) Error() string { return "client assertion refused: " + e.Reason }

func refused(format string, a ...any) *AssertionError {
	return &AssertionError{Reason: fmt.Sprintf(format, a...)}
}

// ClientAssertion is a parsed, not yet verified client assertion.
type ClientAssertion struct {
	tok *jwt.JSONWebToken
	// Alg and KeyID are the header's, as claimed (not yet trusted).
	Alg   string
	KeyID string
}

// ParseClientAssertion parses a compact JWS without trusting it: size,
// structure, header members and the algorithm allow-list. It never panics and
// never verifies a signature (Verify does).
func ParseClientAssertion(raw string) (*ClientAssertion, error) {
	if raw == "" || len(raw) > MaxAssertionBytes {
		return nil, refused("the assertion is empty or larger than %d bytes", MaxAssertionBytes)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, refused("the assertion is not a compact JWS")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, refused("the assertion header is not base64url")
	}
	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil || hdr == nil {
		return nil, refused("the assertion header is not a JSON object")
	}
	for _, k := range forbiddenAssertionHeaders {
		if _, ok := hdr[k]; ok {
			return nil, refused("the assertion header must not contain %s", k)
		}
	}
	var typ, alg, kid string
	_ = json.Unmarshal(hdr["typ"], &typ)
	_ = json.Unmarshal(hdr["alg"], &alg)
	_ = json.Unmarshal(hdr["kid"], &kid)
	if t := strings.ToLower(typ); t == "at+jwt" || t == "dpop+jwt" || t == "application/at+jwt" {
		return nil, refused("the assertion has the type of another kind of token") // RFC 8725 §3.11
	}
	if alg != "ES256" && alg != "EdDSA" {
		return nil, refused("the assertion algorithm must be ES256 or EdDSA")
	}
	if len(kid) > 64 {
		return nil, refused("the assertion kid is too long")
	}
	tok, err := jwt.ParseSigned(raw, assertionJOSEAlgs)
	if err != nil {
		return nil, refused("the assertion cannot be parsed")
	}
	return &ClientAssertion{tok: tok, Alg: alg, KeyID: kid}, nil
}

// AssertionClaims are the verified claims of a client assertion.
type AssertionClaims struct {
	Issuer, Subject string
	Audience        string
	IssuedAt        time.Time
	Expiry          time.Time
	NotBefore       time.Time // zero when absent
	JTI             string
}

type rawAssertionClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	IssuedAt  *float64        `json:"iat"`
	Expiry    *float64        `json:"exp"`
	NotBefore *float64        `json:"nbf"`
	JTI       string          `json:"jti"`
}

// UnverifiedIssuer returns the iss claim without verifying the signature, only
// to find which client the assertion claims to be (a request may omit
// client_id). Nothing may be trusted on it before Verify.
func (a *ClientAssertion) UnverifiedIssuer() string {
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := a.tok.UnsafeClaimsWithoutVerification(&c); err != nil {
		return ""
	}
	return c.Issuer
}

// Verify checks the signature against the client's registered keys (kid, when
// the assertion names one, selects the key; otherwise each key is tried) and
// reads the claims. An unregistered key, a key of another type than the
// algorithm and a bad signature are all the same refusal.
func (a *ClientAssertion) Verify(set jose.JSONWebKeySet) (*AssertionClaims, error) {
	var cands []jose.JSONWebKey
	if a.KeyID != "" {
		cands = set.Key(a.KeyID)
	} else {
		cands = set.Keys
	}
	var raw rawAssertionClaims
	verified := false
	for i := range cands {
		k := cands[i]
		if !keyFitsAlg(&k, a.Alg) || (k.Use != "" && k.Use != "sig") {
			continue
		}
		var c rawAssertionClaims
		if err := a.tok.Claims(k.Key, &c); err == nil {
			raw, verified = c, true
			break
		}
	}
	if !verified {
		return nil, refused("the assertion is not signed by a key registered for this client")
	}
	c := &AssertionClaims{Issuer: raw.Issuer, Subject: raw.Subject, JTI: raw.JTI}
	if json.Unmarshal(raw.Audience, &c.Audience) != nil {
		c.Audience = "" // absent, a list or another type: never equal to an endpoint
	}
	var err error
	if c.IssuedAt, err = numericDate(raw.IssuedAt, "iat"); err != nil {
		return nil, err
	}
	if c.Expiry, err = numericDate(raw.Expiry, "exp"); err != nil {
		return nil, err
	}
	if raw.NotBefore != nil {
		if c.NotBefore, err = numericDate(raw.NotBefore, "nbf"); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// numericDate reads a required NumericDate, refusing a missing, negative or
// absurdly large value (so that the conversion cannot overflow).
func numericDate(v *float64, name string) (time.Time, error) {
	if v == nil {
		return time.Time{}, refused("the assertion has no %s", name)
	}
	if !(*v >= 0 && *v < 1e11) {
		return time.Time{}, refused("the assertion %s is not a valid time", name)
	}
	return time.Unix(int64(*v), 0).UTC(), nil
}

// Check applies the claim rules for client clientID at the endpoint whose URL
// is audience: iss = sub = client_id, aud exactly the endpoint, exp in the
// future, exp - iat at most five minutes, iat and nbf not in the future, jti
// present.
func (c *AssertionClaims) Check(clientID, audience string, now time.Time) error {
	switch {
	case c.Issuer != clientID || c.Subject != clientID:
		return refused("iss and sub must both be the client_id")
	case audience == "" || c.Audience != audience:
		return refused("aud must be the URL of this endpoint")
	case !now.Before(c.Expiry):
		return refused("the assertion has expired")
	case !c.Expiry.After(c.IssuedAt):
		return refused("exp must be after iat")
	case c.Expiry.Sub(c.IssuedAt) > MaxAssertionLifetime:
		return refused("exp is more than %d seconds after iat", int(MaxAssertionLifetime/time.Second))
	case c.IssuedAt.After(now.Add(assertionSkew)):
		return refused("the assertion was issued in the future")
	case !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(assertionSkew)):
		return refused("the assertion is not yet valid")
	case c.JTI == "" || len(c.JTI) > MaxJTIBytes:
		return refused("the assertion needs a jti of at most %d bytes", MaxJTIBytes)
	}
	return nil
}

// replayKey is the replay_cache key of an assertion: the tenant, the client and
// the jti, hashed, so no client or tenant name is stored.
func replayKey(t tenancy.ID, clientID, jti string) string {
	sum := sha256.Sum256([]byte("client_assertion\x00" + t.String() + "\x00" + clientID + "\x00" + jti))
	return hex.EncodeToString(sum[:])
}

// keyFitsAlg reports whether k can verify alg: an EC P-256 key for ES256, an
// Ed25519 key for EdDSA, with a matching alg member when it has one.
func keyFitsAlg(k *jose.JSONWebKey, alg string) bool {
	if k.Algorithm != "" && k.Algorithm != alg {
		return false
	}
	switch pub := k.Key.(type) {
	case *ecdsa.PublicKey:
		return alg == "ES256" && pub.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

// ParseClientJWKS validates a machine client's public key set for
// registration and returns it with its canonical JSON: one to MaxClientKeys
// public keys, each EC P-256 or Ed25519 with a unique kid (so that a key can
// be rotated by adding the new one first), and no certificate chain or key
// URL.
func ParseClientJWKS(raw []byte) (jose.JSONWebKeySet, []byte, error) {
	var set jose.JSONWebKeySet
	if len(raw) == 0 || len(raw) > maxJWKSBytes {
		return set, nil, fmt.Errorf("the key set must be 1 to %d bytes", maxJWKSBytes)
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return set, nil, fmt.Errorf("the key set is not a JWKS: %w", err)
	}
	if n := len(set.Keys); n == 0 || n > MaxClientKeys {
		return set, nil, fmt.Errorf("the key set must hold 1 to %d keys", MaxClientKeys)
	}
	seen := map[string]bool{}
	for i := range set.Keys {
		k := &set.Keys[i]
		switch {
		case !k.Valid():
			return set, nil, fmt.Errorf("key %d is not a valid key", i)
		case !k.IsPublic():
			return set, nil, fmt.Errorf("key %d is a private key: register only public keys", i)
		case k.KeyID == "" || len(k.KeyID) > 64:
			return set, nil, fmt.Errorf("key %d needs a kid of 1 to 64 characters", i)
		case seen[k.KeyID]:
			return set, nil, fmt.Errorf("kid %q is used twice", k.KeyID)
		case len(k.Certificates) > 0 || k.CertificatesURL != nil:
			return set, nil, fmt.Errorf("key %d must not carry a certificate chain or URL", i)
		case k.Use != "" && k.Use != "sig":
			return set, nil, fmt.Errorf("key %d is not a signature key", i)
		case !keyFitsAlg(k, "ES256") && !keyFitsAlg(k, "EdDSA"):
			return set, nil, fmt.Errorf("key %d must be EC P-256 or Ed25519", i)
		}
		seen[k.KeyID] = true
	}
	out, err := json.Marshal(set)
	if err != nil {
		return set, nil, err
	}
	return set, out, nil
}

// ---------------------------------------------------------------- the endpoint side

// clientAuthParams are the client-authentication parameters of a request.
type clientAuthParams struct {
	assertion string
	clientID  string // as sent, or the assertion's iss when omitted
}

// readClientAuth reads and validates the form parameters of private_key_jwt
// client authentication. ok is false with msg when the request is malformed
// (an invalid_request, not a failed authentication).
func readClientAuth(r *http.Request) (p clientAuthParams, msg string) {
	typ, ok1 := formValue(r, "client_assertion_type")
	assertion, ok2 := formValue(r, "client_assertion")
	clientID, ok3 := formValue(r, "client_id")
	switch {
	case !ok1 || !ok2 || !ok3:
		return p, "client authentication parameters must not repeat"
	case typ != ClientAssertionType || assertion == "":
		return p, "client_assertion_type and client_assertion are required (private_key_jwt)"
	case len(r.Header.Values("Authorization")) > 0 || len(r.PostForm["client_secret"]) > 0:
		return p, "this client authenticates with private_key_jwt only"
	case len(clientID) > 64:
		return p, "client_id is too long"
	}
	return clientAuthParams{assertion: assertion, clientID: clientID}, ""
}

// authenticateClient verifies the assertion of client for the endpoint at
// audience and consumes its jti. reason is "" when the client is
// authenticated, else why not (for the audit event); err is only an
// infrastructure failure.
func (s *Service) authenticateClient(r *http.Request, t tenancy.ID, client *store.APIClient, assertion, audience string, now time.Time) (reason string, err error) {
	if client.Status != store.ClientActive || client.Kind != store.ClientMachine || client.TokenEndpointAuthMethod != "private_key_jwt" {
		return "the client is not an active private_key_jwt client", nil
	}
	set, _, jerr := ParseClientJWKS(client.JWKS)
	if jerr != nil {
		return "the client has no usable registered keys", nil
	}
	a, perr := ParseClientAssertion(assertion)
	var ae *AssertionError
	if errors.As(perr, &ae) {
		return ae.Reason, nil
	}
	claims, verr := a.Verify(set)
	if errors.As(verr, &ae) {
		return ae.Reason, nil
	}
	if cerr := claims.Check(client.ClientID, audience, now); errors.As(cerr, &ae) {
		return ae.Reason, nil
	}
	// the jti is consumed only for an assertion that passed every other check,
	// so that nobody can burn a client's jti values without its key
	err = s.db.InSystem(r.Context(), "client assertion replay", func(st *store.SystemTx) error {
		// the table's kind column also holds DPoP jti values; the key hash is
		// namespaced ("client_assertion") so the two never collide
		return st.UseOnce(store.ReplayDPoPJTI, replayKey(t, client.ClientID, claims.JTI), now, claims.Expiry)
	})
	if errors.Is(err, store.ErrDuplicate) {
		return "the assertion's jti was already used (replay)", nil
	}
	return "", err
}
