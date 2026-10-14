package ssf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

const (
	testIssuer   = "https://larkspur.okta.com"
	testAudience = "https://tessera.example/public/t/larkspur/ssf/1"
)

// signer is a test transmitter key.
type signer struct {
	jwk jose.JSONWebKey // the public key
	s   jose.Signer
}

func newSigner(t testing.TB, alg jose.SignatureAlgorithm, kid string) *signer {
	t.Helper()
	var priv, pub any
	switch alg {
	case jose.ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, &k.PublicKey
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, &k.PublicKey
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: priv, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("secevent+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	return &signer{jwk: jose.JSONWebKey{Key: pub, KeyID: kid, Use: "sig", Algorithm: string(alg)}, s: sg}
}

func (s *signer) sign(t testing.TB, claims any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// claimsFor is a valid session-revoked SET for the test transmitter.
func claimsFor(mod func(map[string]any)) map[string]any {
	c := map[string]any{
		"iss": testIssuer, "aud": testAudience, "iat": now.Add(-time.Minute).Unix(), "jti": "jti-1",
		"events": map[string]any{EventSessionRevoked: map[string]any{
			"subject": map[string]any{"format": "iss_sub", "iss": testIssuer, "sub": "00u1alice"}, "event_timestamp": now.Unix()}},
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func expect() Expect { return Expect{Issuer: testIssuer, Audience: testAudience, Now: now} }

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func newPrivate(t testing.TB) jose.JSONWebKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: k, KeyID: "priv"}
}
