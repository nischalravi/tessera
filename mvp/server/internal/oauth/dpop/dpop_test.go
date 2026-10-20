package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	now      = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tokenURL = "https://tessera.example/t/acme/oauth/token"
)

// memReplay is an in-memory ReplayCache.
type memReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (m *memReplay) UseOnce(_ context.Context, key string, at, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]time.Time{}
	}
	if exp, ok := m.seen[key]; ok && at.Before(exp) {
		return ErrReplay
	}
	m.seen[key] = expires
	return nil
}

type failingReplay struct{}

func (failingReplay) UseOnce(context.Context, string, time.Time, time.Time) error {
	return errors.New("database is down")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func publicJWK(t testing.TB, k any) map[string]any {
	t.Helper()
	b, err := (&jose.JSONWebKey{Key: k}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// opts describe a proof; zero values give a valid ES256 proof for POST tokenURL.
type opts struct {
	alg     string // default ES256
	key     any    // *ecdsa.PrivateKey or ed25519.PrivateKey; default a fresh P-256 key
	header  func(h map[string]any)
	claims  func(c map[string]any)
	tamper  func(proof string) string
	nowAt   time.Time
	rawSign func(input string) string // overrides the signature (alg none, HS256)
}

var jtiCounter int

func makeProof(t testing.TB, o opts) string {
	t.Helper()
	if o.alg == "" {
		o.alg = "ES256"
	}
	if o.key == nil {
		switch o.alg {
		case "EdDSA":
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			o.key = priv
		default:
			o.key = mustKey(t)
		}
	}
	if o.nowAt.IsZero() {
		o.nowAt = now
	}
	var pub any
	switch k := o.key.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	}
	jtiCounter++
	h := map[string]any{"typ": "dpop+jwt", "alg": o.alg, "jwk": publicJWK(t, pub)}
	c := map[string]any{"jti": fmt.Sprintf("jti-%d-%s", jtiCounter, b64(randBytes(6))), "htm": "POST", "htu": tokenURL, "iat": o.nowAt.Unix()}
	if o.header != nil {
		o.header(h)
	}
	if o.claims != nil {
		o.claims(c)
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(c)
	input := b64(hb) + "." + b64(cb)
	var sig string
	switch {
	case o.rawSign != nil:
		sig = o.rawSign(input)
	default:
		switch k := o.key.(type) {
		case *ecdsa.PrivateKey:
			sum := sha256.Sum256([]byte(input))
			r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			sig = b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
		case ed25519.PrivateKey:
			sig = b64(ed25519.Sign(k, []byte(input)))
		}
	}
	proof := input + "." + sig
	if o.tamper != nil {
		proof = o.tamper(proof)
	}
	return proof
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func newValidator() *Validator {
	return &Validator{Replay: &memReplay{}, NonceKey: []byte("0123456789abcdef0123456789abcdef")}
}

func params() ProofParams {
	return ProofParams{Method: "POST", URL: tokenURL, Now: now}
}

func headersOf(proofs ...string) http.Header {
	h := http.Header{}
	for _, p := range proofs {
		h.Add("DPoP", p)
	}
	return h
}

// TestValidateProof is RFC 9449 §4.3, check by check.
func TestValidateProof(t *testing.T) {
	edKey := func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }()
	p256 := mustKey(t)
	hmacSign := func(input string) string {
		m := hmac.New(sha256.New, []byte("secret"))
		m.Write([]byte(input))
		return b64(m.Sum(nil))
	}
	setHdr := func(k string, v any) func(map[string]any) { return func(h map[string]any) { h[k] = v } }
	setClaim := func(k string, v any) func(map[string]any) { return func(c map[string]any) { c[k] = v } }
	delClaim := func(k string) func(map[string]any) { return func(c map[string]any) { delete(c, k) } }
	delHdr := func(k string) func(map[string]any) { return func(h map[string]any) { delete(h, k) } }
	otherKeyJWK := publicJWK(t, &mustKey(t).PublicKey)
	rsaLike := map[string]any{"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB"}

	tests := []struct {
		name    string
		headers func() http.Header
		p       func(*ProofParams)
		wantErr string // "" = valid; else the ProofError code
		wantMsg string // substring of the description
	}{
		{name: "valid ES256", headers: func() http.Header { return headersOf(makeProof(t, opts{})) }},
		{name: "valid EdDSA", headers: func() http.Header { return headersOf(makeProof(t, opts{alg: "EdDSA", key: edKey})) }},
		{name: "no DPoP header", headers: func() http.Header { return http.Header{} }, wantErr: CodeInvalidProof, wantMsg: "exactly one"},
		{name: "two DPoP headers", headers: func() http.Header {
			return headersOf(makeProof(t, opts{}), makeProof(t, opts{}))
		}, wantErr: CodeInvalidProof, wantMsg: "exactly one"},
		{name: "one header with two comma-joined proofs", headers: func() http.Header {
			return headersOf(makeProof(t, opts{}) + ", " + makeProof(t, opts{}))
		}, wantErr: CodeInvalidProof},
		{name: "empty proof", headers: func() http.Header { return headersOf("") }, wantErr: CodeInvalidProof},
		{name: "proof over 4 KiB", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("pad", strings.Repeat("a", MaxProofBytes))}))
		}, wantErr: CodeInvalidProof, wantMsg: "larger"},
		{name: "not a JWS", headers: func() http.Header { return headersOf("not-a-jwt") }, wantErr: CodeInvalidProof},
		{name: "JSON serialization", headers: func() http.Header {
			p := strings.Split(makeProof(t, opts{}), ".")
			return headersOf(fmt.Sprintf(`{"protected":%q,"payload":%q,"signature":%q}`, p[0], p[1], p[2]))
		}, wantErr: CodeInvalidProof},
		{name: "header is not base64url", headers: func() http.Header { return headersOf("!!!.e30.e30") }, wantErr: CodeInvalidProof},
		{name: "header is not JSON", headers: func() http.Header { return headersOf(b64([]byte("[1]")) + ".e30.e30") }, wantErr: CodeInvalidProof},
		// typ
		{name: "typ missing", headers: func() http.Header { return headersOf(makeProof(t, opts{header: delHdr("typ")})) },
			wantErr: CodeInvalidProof, wantMsg: "typ"},
		{name: "typ JWT", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("typ", "JWT")})) },
			wantErr: CodeInvalidProof, wantMsg: "typ"},
		{name: "typ at+jwt", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("typ", "at+jwt")})) },
			wantErr: CodeInvalidProof, wantMsg: "typ"},
		// alg
		{name: "alg none", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("alg", "none"), rawSign: func(string) string { return "" }}))
		}, wantErr: CodeInvalidProof},
		{name: "alg HS256 with a shared secret", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("alg", "HS256"), rawSign: hmacSign}))
		}, wantErr: CodeInvalidProof},
		{name: "alg HS256 keyed with the public key bytes", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("alg", "HS256"), rawSign: hmacSign}))
		}, wantErr: CodeInvalidProof},
		{name: "alg RS256", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: func(h map[string]any) { h["alg"] = "RS256"; h["jwk"] = rsaLike }}))
		}, wantErr: CodeInvalidProof},
		{name: "alg ES384", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("alg", "ES384")})) },
			wantErr: CodeInvalidProof},
		// jwk
		{name: "jwk missing", headers: func() http.Header { return headersOf(makeProof(t, opts{header: delHdr("jwk")})) },
			wantErr: CodeInvalidProof, wantMsg: "jwk"},
		{name: "private key in jwk", headers: func() http.Header {
			return headersOf(makeProof(t, opts{key: p256, header: func(h map[string]any) {
				b, _ := (&jose.JSONWebKey{Key: p256}).MarshalJSON()
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				h["jwk"] = m
			}}))
		}, wantErr: CodeInvalidProof, wantMsg: "public"},
		{name: "symmetric key in jwk", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("jwk", map[string]any{"kty": "oct", "k": "c2VjcmV0"})}))
		}, wantErr: CodeInvalidProof},
		{name: "RSA key under ES256", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("jwk", rsaLike)}))
		}, wantErr: CodeInvalidProof},
		{name: "Ed25519 key under ES256", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("jwk", publicJWK(t, edKey.Public()))}))
		}, wantErr: CodeInvalidProof},
		{name: "P-256 key under EdDSA", headers: func() http.Header {
			return headersOf(makeProof(t, opts{alg: "EdDSA", key: edKey, header: setHdr("jwk", publicJWK(t, &p256.PublicKey))}))
		}, wantErr: CodeInvalidProof},
		{name: "jwk of another key than the signer", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("jwk", otherKeyJWK)}))
		}, wantErr: CodeInvalidProof, wantMsg: "signature"},
		{name: "jwk alg disagrees", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: func(h map[string]any) {
				j := h["jwk"].(map[string]any)
				j["alg"] = "ES512"
			}}))
		}, wantErr: CodeInvalidProof},
		// forbidden header members
		{name: "kid", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("kid", "k1")})) }, wantErr: CodeInvalidProof, wantMsg: "kid"},
		{name: "jku", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("jku", "https://evil.example/jwks")}))
		}, wantErr: CodeInvalidProof, wantMsg: "jku"},
		{name: "x5u", headers: func() http.Header {
			return headersOf(makeProof(t, opts{header: setHdr("x5u", "https://evil.example/c")}))
		}, wantErr: CodeInvalidProof, wantMsg: "x5u"},
		{name: "x5c", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("x5c", []string{"AAAA"})})) },
			wantErr: CodeInvalidProof, wantMsg: "x5c"},
		{name: "crit", headers: func() http.Header { return headersOf(makeProof(t, opts{header: setHdr("crit", []string{"exp"})})) },
			wantErr: CodeInvalidProof, wantMsg: "crit"},
		// signature
		{name: "payload tampered after signing", headers: func() http.Header {
			return headersOf(makeProof(t, opts{tamper: func(p string) string {
				s := strings.Split(p, ".")
				s[1] = b64([]byte(`{"jti":"x","htm":"POST","htu":"` + tokenURL + `","iat":` + fmt.Sprint(now.Unix()) + `,"evil":1}`))
				return strings.Join(s, ".")
			}}))
		}, wantErr: CodeInvalidProof, wantMsg: "signature"},
		{name: "signature truncated", headers: func() http.Header {
			return headersOf(makeProof(t, opts{tamper: func(p string) string { return p[:len(p)-8] }}))
		}, wantErr: CodeInvalidProof},
		// htm
		{name: "htm GET for a POST", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: setClaim("htm", "GET")})) },
			wantErr: CodeInvalidProof, wantMsg: "htm"},
		{name: "htm lower case", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: setClaim("htm", "post")})) },
			wantErr: CodeInvalidProof, wantMsg: "htm"},
		{name: "htm missing", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: delClaim("htm")})) },
			wantErr: CodeInvalidProof, wantMsg: "htm"},
		// htu
		{name: "htu with a query is compared without it", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", tokenURL+"?a=b#frag")}))
		}},
		{name: "request URL with a query", headers: func() http.Header { return headersOf(makeProof(t, opts{})) },
			p: func(p *ProofParams) { p.URL = tokenURL + "?x=1" }},
		{name: "htu host case and default port", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "HTTPS://Tessera.Example:443/t/acme/oauth/token")}))
		}},
		{name: "htu wrong host", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "https://evil.example/t/acme/oauth/token")}))
		}, wantErr: CodeInvalidProof, wantMsg: "htu"},
		{name: "htu wrong path", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "https://tessera.example/t/acme/oauth/revoke")}))
		}, wantErr: CodeInvalidProof, wantMsg: "htu"},
		{name: "htu wrong scheme", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "http://tessera.example/t/acme/oauth/token")}))
		}, wantErr: CodeInvalidProof, wantMsg: "htu"},
		{name: "htu wrong port", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "https://tessera.example:8443/t/acme/oauth/token")}))
		}, wantErr: CodeInvalidProof, wantMsg: "htu"},
		{name: "htu relative", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("htu", "/t/acme/oauth/token")}))
		},
			wantErr: CodeInvalidProof, wantMsg: "htu"},
		{name: "htu missing", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: delClaim("htu")})) },
			wantErr: CodeInvalidProof, wantMsg: "htu"},
		// iat
		{name: "iat 59 s old", headers: func() http.Header { return headersOf(makeProof(t, opts{nowAt: now.Add(-59 * time.Second)})) }},
		{name: "iat stale by 61 s", headers: func() http.Header { return headersOf(makeProof(t, opts{nowAt: now.Add(-61 * time.Second)})) },
			wantErr: CodeInvalidProof, wantMsg: "iat"},
		{name: "iat 4 s ahead", headers: func() http.Header { return headersOf(makeProof(t, opts{nowAt: now.Add(4 * time.Second)})) }},
		{name: "iat in the future by 6 s", headers: func() http.Header { return headersOf(makeProof(t, opts{nowAt: now.Add(6 * time.Second)})) },
			wantErr: CodeInvalidProof, wantMsg: "iat"},
		{name: "iat missing", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: delClaim("iat")})) },
			wantErr: CodeInvalidProof, wantMsg: "iat"},
		{name: "iat is a string", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: setClaim("iat", "now")})) },
			wantErr: CodeInvalidProof},
		// jti
		{name: "jti missing", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: delClaim("jti")})) },
			wantErr: CodeInvalidProof, wantMsg: "jti"},
		{name: "jti empty", headers: func() http.Header { return headersOf(makeProof(t, opts{claims: setClaim("jti", "")})) },
			wantErr: CodeInvalidProof, wantMsg: "jti"},
		{name: "jti of 65 characters", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("jti", strings.Repeat("j", 65))}))
		}, wantErr: CodeInvalidProof, wantMsg: "jti"},
		{name: "jti of 64 characters", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("jti", strings.Repeat("k", 64))}))
		}},
		// ath
		{name: "ath missing with an access token", headers: func() http.Header { return headersOf(makeProof(t, opts{})) },
			p: func(p *ProofParams) { p.AccessToken = "the-token" }, wantErr: CodeInvalidProof, wantMsg: "ath"},
		{name: "ath of another token", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("ath", AccessTokenHash("other-token"))}))
		}, p: func(p *ProofParams) { p.AccessToken = "the-token" }, wantErr: CodeInvalidProof, wantMsg: "ath"},
		{name: "ath of the token", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("ath", AccessTokenHash("the-token"))}))
		}, p: func(p *ProofParams) { p.AccessToken = "the-token" }},
		{name: "ath present at the token endpoint is ignored", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("ath", "whatever")}))
		}},
		// nonce
		{name: "nonce required, none sent", headers: func() http.Header { return headersOf(makeProof(t, opts{})) },
			p: func(p *ProofParams) { p.RequireNonce = true }, wantErr: CodeUseNonce},
		{name: "nonce required, wrong nonce", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", "AAAA")}))
		}, p: func(p *ProofParams) { p.RequireNonce = true }, wantErr: CodeUseNonce},
		{name: "nonce required, current nonce", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", newValidator().NewNonce(now))}))
		}, p: func(p *ProofParams) { p.RequireNonce = true }},
		{name: "nonce required, previous nonce", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", newValidator().NewNonce(now.Add(-NonceBucket)))}))
		}, p: func(p *ProofParams) { p.RequireNonce = true }},
		{name: "nonce required, nonce two buckets old", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", newValidator().NewNonce(now.Add(-2*NonceBucket)))}))
		}, p: func(p *ProofParams) { p.RequireNonce = true }, wantErr: CodeUseNonce},
		{name: "nonce from another key", headers: func() http.Header {
			v := &Validator{NonceKey: []byte("another-key-another-key-another!")}
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", v.NewNonce(now))}))
		}, p: func(p *ProofParams) { p.RequireNonce = true }, wantErr: CodeUseNonce},
		{name: "nonce sent but not required", headers: func() http.Header {
			return headersOf(makeProof(t, opts{claims: setClaim("nonce", "stale")}))
		}},
		// jkt binding
		{name: "bound key matches", headers: func() http.Header { return headersOf(makeProof(t, opts{key: p256})) },
			p: func(p *ProofParams) { p.ExpectedJKT = jktOf(t, p256) }},
		{name: "bound key differs", headers: func() http.Header { return headersOf(makeProof(t, opts{})) },
			p: func(p *ProofParams) { p.ExpectedJKT = jktOf(t, p256) }, wantErr: CodeInvalidProof, wantMsg: "bound"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newValidator()
			p := params()
			if tt.p != nil {
				tt.p(&p)
			}
			jkt, err := v.ValidateProof(context.Background(), tt.headers(), p)
			if tt.wantErr == "" {
				if err != nil || jkt == "" {
					t.Fatalf("got %q, %v; want a valid proof", jkt, err)
				}
				return
			}
			var pe *ProofError
			if !errors.As(err, &pe) {
				t.Fatalf("got %q, %v; want ProofError %s", jkt, err, tt.wantErr)
			}
			if pe.Code != tt.wantErr || !strings.Contains(pe.Description, tt.wantMsg) {
				t.Errorf("got %q (%s); want code %s containing %q", pe.Code, pe.Description, tt.wantErr, tt.wantMsg)
			}
			if jkt != "" {
				t.Errorf("a refused proof returned the thumbprint %q", jkt)
			}
			if (pe.Code == CodeUseNonce) != (pe.NewNonce != "") {
				t.Errorf("code %s with NewNonce %q", pe.Code, pe.NewNonce)
			}
		})
	}
}

func jktOf(t testing.TB, k *ecdsa.PrivateKey) string {
	t.Helper()
	j, err := Thumbprint(&jose.JSONWebKey{Key: &k.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// TestReplayedJTI: the same proof is accepted once; a new jti from the same
// key is fine; the entry expires after 120 s; a refused proof does not use up
// its jti.
func TestReplayedJTI(t *testing.T) {
	v := newValidator()
	k := mustKey(t)
	proof := makeProof(t, opts{key: k, claims: func(c map[string]any) { c["jti"] = "fixed-jti" }})
	validate := func(proof string, at time.Time) error {
		p := params()
		p.Now = at
		_, err := v.ValidateProof(context.Background(), headersOf(proof), p)
		return err
	}
	if err := validate(proof, now); err != nil {
		t.Fatal(err)
	}
	var pe *ProofError
	if err := validate(proof, now); !errors.As(err, &pe) || !strings.Contains(pe.Description, "already used") {
		t.Errorf("replay: %v", err)
	}
	// the same jti from another key is another proof
	if err := validate(makeProof(t, opts{claims: func(c map[string]any) { c["jti"] = "fixed-jti" }}), now); err != nil {
		t.Errorf("same jti, other key: %v", err)
	}
	// after ReplayTTL (and still inside the iat window of a later proof) it may be seen again
	later := now.Add(ReplayTTL + time.Second)
	if err := validate(makeProof(t, opts{key: k, nowAt: later, claims: func(c map[string]any) { c["jti"] = "fixed-jti" }}), later); err != nil {
		t.Errorf("after the replay window: %v", err)
	}
	// a proof refused for another reason (wrong htm) leaves its jti unused
	bad := makeProof(t, opts{key: k, claims: func(c map[string]any) { c["jti"] = "bad-jti"; c["htm"] = "GET" }})
	if err := validate(bad, now); err == nil {
		t.Fatal("wrong htm accepted")
	}
	// entries: (k, fixed-jti) and (other key, fixed-jti); the refused proof left none
	if got := len(v.Replay.(*memReplay).seen); got != 2 {
		t.Errorf("%d replay entries, want 2 (a refused proof must not be recorded)", got)
	}
}

// TestNonceFlow: use_dpop_nonce carries a nonce that the retry then uses.
func TestNonceFlow(t *testing.T) {
	v := newValidator()
	k := mustKey(t)
	p := params()
	p.RequireNonce = true
	_, err := v.ValidateProof(context.Background(), headersOf(makeProof(t, opts{key: k})), p)
	var pe *ProofError
	if !errors.As(err, &pe) || pe.Code != CodeUseNonce || pe.NewNonce == "" {
		t.Fatalf("first request: %v", err)
	}
	retry := makeProof(t, opts{key: k, claims: func(c map[string]any) { c["nonce"] = pe.NewNonce }})
	if jkt, err := v.ValidateProof(context.Background(), headersOf(retry), p); err != nil || jkt != jktOf(t, k) {
		t.Fatalf("retry with the nonce: %q %v", jkt, err)
	}
	// without a NonceKey nonces are never required
	v2 := &Validator{Replay: &memReplay{}}
	if _, err := v2.ValidateProof(context.Background(), headersOf(makeProof(t, opts{})), p); err != nil {
		t.Errorf("no nonce key: %v", err)
	}
	if v2.NewNonce(now) != "" {
		t.Error("NewNonce without a key")
	}
}

// TestReplayCacheFailure: a database failure is not an invalid proof (the
// caller answers 500, never 401).
func TestReplayCacheFailure(t *testing.T) {
	v := &Validator{Replay: failingReplay{}}
	_, err := v.ValidateProof(context.Background(), headersOf(makeProof(t, opts{})), params())
	var pe *ProofError
	if err == nil || errors.As(err, &pe) {
		t.Errorf("got %v, want an infrastructure error", err)
	}
}

func TestNormalizeHTU(t *testing.T) {
	for in, want := range map[string]string{
		"https://tessera.example/t/acme/oauth/token":    "https://tessera.example/t/acme/oauth/token",
		"HTTPS://Tessera.Example:443/api/summary?x=1#f": "https://tessera.example/api/summary",
		"http://localhost:8000":                         "http://localhost:8000/",
		"http://localhost:80/a":                         "http://localhost/a",
		"https://[::1]:8443/a%2Fb":                      "https://[::1]:8443/a%2Fb",
	} {
		if got, err := NormalizeHTU(in); err != nil || got != want {
			t.Errorf("NormalizeHTU(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/relative", "ftp://x/y", "https://user@x/y", "https:///nohost", "://bad", "https://x/%zz"} {
		if got, err := NormalizeHTU(in); err == nil {
			t.Errorf("NormalizeHTU(%q) = %q, want an error", in, got)
		}
	}
}

// TestRFC9449Example validates the example proof of RFC 9449 §4.1 at its own
// iat: a POST to https://server.example.com/token by the example key.
func TestRFC9449Example(t *testing.T) {
	const proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	v := newValidator()
	p := ProofParams{Method: "POST", URL: "https://server.example.com/token", Now: time.Unix(1562262616, 0)}
	jkt, err := v.ValidateProof(context.Background(), headersOf(proof), p)
	if err != nil {
		t.Fatal(err)
	}
	if jkt != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
		t.Errorf("jkt = %q, want the thumbprint RFC 9449 §6.1 shows", jkt)
	}
	// the same proof for another method or endpoint is refused
	p.Method = "GET"
	if _, err := newValidator().ValidateProof(context.Background(), headersOf(proof), p); err == nil {
		t.Error("the example proof was accepted for a GET")
	}
}

// FuzzValidateProof: whatever arrives in the DPoP header, validation returns a
// ProofError or a thumbprint, and never panics.
func FuzzValidateProof(f *testing.F) {
	k := mustKey(f)
	valid := makeProof(f, opts{key: k})
	f.Add(valid)
	f.Add(makeProof(f, opts{alg: "EdDSA"}))
	f.Add(makeProof(f, opts{header: func(h map[string]any) { h["kid"] = "x" }}))
	f.Add(makeProof(f, opts{claims: func(c map[string]any) { c["iat"] = 1e300 }}))
	f.Add(makeProof(f, opts{claims: func(c map[string]any) { c["htu"] = "https://[::1" }}))
	f.Add(makeProof(f, opts{header: func(h map[string]any) { h["alg"] = "none" }, rawSign: func(string) string { return "" }}))
	f.Add(strings.Replace(valid, ".", ".\x00", 1))
	f.Add("..")
	f.Add("")
	f.Add(`{"protected":"e30","payload":"e30","signature":"e30"}`)
	f.Add(strings.Repeat("a.", 5000))
	f.Fuzz(func(t *testing.T, proof string) {
		v := newValidator()
		p := params()
		p.RequireNonce = len(proof)%2 == 0
		p.AccessToken = map[bool]string{true: "tok", false: ""}[len(proof)%3 == 0]
		jkt, err := v.validate(context.Background(), proof, p)
		var pe *ProofError
		switch {
		case err == nil:
			if jkt == "" {
				t.Fatal("a valid proof without a thumbprint")
			}
		case !errors.As(err, &pe):
			t.Fatalf("unexpected infrastructure error %v", err)
		case jkt != "":
			t.Fatal("an error with a thumbprint")
		}
	})
}
