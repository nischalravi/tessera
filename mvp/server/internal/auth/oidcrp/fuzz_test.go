package oidcrp_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
)

const fuzzIss, fuzzAud = "https://idp.example", "client"

func signed(t testing.TB, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// FuzzValidateIDToken: no input panics, and nothing but a token signed by the
// configured key with every claim right is accepted.
func FuzzValidateIDToken(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	good := map[string]any{"iss": fuzzIss, "aud": fuzzAud, "sub": "u1", "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(), "nonce": "n1", "auth_time": now.Unix()}
	valid := signed(f, key, good)
	f.Add(valid)
	f.Add(valid + "x")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.")
	f.Add("a.b.c")
	f.Add("")
	ks := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	v := oidc.NewVerifier(fuzzIss, ks, &oidc.Config{ClientID: fuzzAud, SupportedSigningAlgs: []string{oidc.RS256},
		Now: func() time.Time { return now }})
	e := oidcrp.Expect{Issuer: fuzzIss, ClientID: fuzzAud, Algs: []string{oidc.RS256}, Nonce: "n1", Now: now}
	if _, err := oidcrp.ValidateIDToken(context.Background(), v, valid, e); err != nil {
		f.Fatalf("the seed token is refused: %v", err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		tok, err := oidcrp.ValidateIDToken(context.Background(), v, raw, e)
		if err == nil && (tok.Subject == "" || raw != valid) {
			t.Fatalf("accepted %q", raw)
		}
	})
}
