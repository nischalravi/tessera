package ssf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestParseSET_Valid(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256} {
		t.Run(string(alg), func(t *testing.T) {
			sg := newSigner(t, alg, "k1")
			set, err := ParseSET(sg.sign(t, claimsFor(nil)), []Key{sg.jwk}, expect())
			if err != nil {
				t.Fatal(err)
			}
			if set.JTI != "jti-1" || set.EventType != EventSessionRevoked || !set.Known || set.ExpiresAt != nil ||
				set.IssuedAt != now.Add(-time.Minute) || set.Subject.Format != "iss_sub" || set.Subject.ID != "00u1alice" {
				t.Errorf("set = %+v", set)
			}
		})
	}
}

func TestParseSET_Refusals(t *testing.T) {
	sg := newSigner(t, jose.ES256, "k1")
	other := newSigner(t, jose.ES256, "k1") // same kid, another key
	keys := []Key{sg.jwk}
	in := func(d time.Duration) int64 { return now.Add(d).Unix() }
	cases := []struct {
		name  string
		token func() string
		code  string
		msg   string
	}{
		{"bad signature (another key, same kid)", func() string { return other.sign(t, claimsFor(nil)) }, ErrInvalidKey, "does not verify"},
		{"unknown kid", func() string {
			u := newSigner(t, jose.ES256, "other-kid")
			return u.sign(t, claimsFor(nil))
		}, ErrInvalidKey, "no key"},
		{"wrong issuer", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["iss"] = "https://evil.example" }))
		}, ErrInvalidRequest, "iss"},
		{"no issuer", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { delete(c, "iss") })) }, ErrInvalidRequest, "iss"},
		{"wrong audience", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["aud"] = "https://other.example" }))
		}, ErrInvalidRequest, "aud"},
		{"audience list without ours", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["aud"] = []string{"a", "b"} }))
		}, ErrInvalidRequest, "aud"},
		{"no audience", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { delete(c, "aud") })) }, ErrInvalidRequest, "aud"},
		{"no iat", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { delete(c, "iat") })) }, ErrInvalidRequest, "iat"},
		{"iat in the future", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["iat"] = in(10 * time.Minute) }))
		}, ErrInvalidRequest, "future"},
		{"iat too old", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["iat"] = in(-25 * time.Hour) }))
		}, ErrInvalidRequest, "older"},
		{"expired", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { c["exp"] = in(-time.Second) })) }, ErrInvalidRequest, "expired"},
		{"expires now", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { c["exp"] = in(0) })) }, ErrInvalidRequest, "expired"},
		{"nbf in the future", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { c["nbf"] = in(time.Hour) })) }, ErrInvalidRequest, "nbf"},
		{"no jti", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { delete(c, "jti") })) }, ErrInvalidRequest, "jti"},
		{"jti too long", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["jti"] = strings.Repeat("j", 300) }))
		}, ErrInvalidRequest, "jti"},
		{"no events", func() string { return sg.sign(t, claimsFor(func(c map[string]any) { delete(c, "events") })) }, ErrInvalidRequest, "events"},
		{"empty events", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["events"] = map[string]any{} }))
		}, ErrInvalidRequest, "events"},
		{"two events", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) {
				c["events"] = map[string]any{EventSessionRevoked: map[string]any{}, EventAccountDisabled: map[string]any{}}
			}))
		}, ErrInvalidRequest, "exactly one"},
		{"event payload is not an object", func() string {
			return sg.sign(t, claimsFor(func(c map[string]any) { c["events"] = map[string]any{EventSessionRevoked: "x"} }))
		}, ErrInvalidRequest, "payload"},
		{"claims are not an object", func() string {
			jws, _ := sg.s.Sign([]byte(`["x"]`))
			s, _ := jws.CompactSerialize()
			return s
		}, ErrInvalidRequest, "claims"},
		{"alg none", func() string {
			return b64(`{"alg":"none","typ":"secevent+jwt"}`) + "." + b64(mustJSON(claimsFor(nil))) + "."
		}, ErrInvalidRequest, "compact form"},
		{"alg none with a signature", func() string {
			return b64(`{"alg":"none"}`) + "." + b64(mustJSON(claimsFor(nil))) + ".c2ln"
		}, ErrInvalidRequest, "compact form"},
		{"HS256 signed with the public key as the secret", func() string {
			der, _ := x509.MarshalPKIXPublicKey(sg.jwk.Key)
			pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			h := b64(`{"alg":"HS256","kid":"k1"}`) + "." + b64(mustJSON(claimsFor(nil)))
			m := hmac.New(sha256.New, pemKey)
			m.Write([]byte(h))
			return h + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
		}, ErrInvalidRequest, "compact form"},
		{"HS512", func() string {
			return b64(`{"alg":"HS512"}`) + "." + b64(mustJSON(claimsFor(nil))) + ".c2ln"
		}, ErrInvalidRequest, "compact form"},
		{"RS512 is not allowed", func() string {
			return b64(`{"alg":"RS512","kid":"k1"}`) + "." + b64(mustJSON(claimsFor(nil))) + ".c2ln"
		}, ErrInvalidRequest, "compact form"},
		{"JSON serialization", func() string {
			c := sg.sign(t, claimsFor(nil))
			p := strings.Split(c, ".")
			return `{"payload":"` + p[1] + `","protected":"` + p[0] + `","signature":"` + p[2] + `"}`
		}, ErrInvalidRequest, "compact form"},
		{"empty", func() string { return "  " }, ErrInvalidRequest, "no SET"},
		{"too large", func() string { return strings.Repeat("a", MaxSETBytes+1) }, ErrInvalidRequest, "larger"},
		{"garbage", func() string { return "not.a.jwt" }, ErrInvalidRequest, "compact form"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := ParseSET(tc.token(), keys, expect())
			if err == nil {
				t.Fatalf("accepted: %+v", set)
			}
			if code(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
				t.Errorf("error %v, want %s containing %q", err, tc.code, tc.msg)
			}
		})
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestParseSET_KeySelection(t *testing.T) {
	a, b := newSigner(t, jose.ES256, "a"), newSigner(t, jose.RS256, "b")
	tok := b.sign(t, claimsFor(nil))
	if _, err := ParseSET(tok, []Key{a.jwk, b.jwk}, expect()); err != nil {
		t.Errorf("the key named by kid: %v", err)
	}
	// an algorithm pinned on the key must match the header
	pinned := b.jwk
	pinned.Algorithm = "PS256"
	if _, err := ParseSET(tok, []Key{pinned}, expect()); code(err) != ErrInvalidKey {
		t.Errorf("a key pinned to another algorithm: %v", err)
	}
	// a token without a kid tries each key
	nokid := newSigner(t, jose.ES256, "")
	if _, err := ParseSET(nokid.sign(t, claimsFor(nil)), []Key{a.jwk, nokid.jwk}, expect()); err != nil {
		t.Errorf("no kid: %v", err)
	}
	// exp in the future and nbf in the past are fine
	ok := b.sign(t, claimsFor(func(c map[string]any) {
		c["exp"] = now.Add(time.Hour).Unix()
		c["nbf"] = now.Add(-time.Hour).Unix()
		c["aud"] = []string{"other", testAudience}
	}))
	set, err := ParseSET(ok, []Key{b.jwk}, expect())
	if err != nil || set.ExpiresAt == nil || !set.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("exp/nbf/aud list: %+v %v", set, err)
	}
	// an iat a minute ahead is inside the skew
	if _, err := ParseSET(b.sign(t, claimsFor(func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() })), []Key{b.jwk}, expect()); err != nil {
		t.Errorf("iat inside the skew: %v", err)
	}
	// fractional numeric dates are accepted
	if _, err := ParseSET(b.sign(t, claimsFor(func(c map[string]any) { c["iat"] = float64(now.Unix()) - 30.5 })), []Key{b.jwk}, expect()); err != nil {
		t.Errorf("fractional iat: %v", err)
	}
}

func TestParseSET_EventsAndSubjects(t *testing.T) {
	sg := newSigner(t, jose.ES256, "k1")
	parse := func(events map[string]any, mod func(map[string]any)) *SET {
		t.Helper()
		set, err := ParseSET(sg.sign(t, claimsFor(func(c map[string]any) {
			c["events"] = events
			if mod != nil {
				mod(c)
			}
		})), []Key{sg.jwk}, expect())
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	subj := func(m map[string]any) map[string]any { return map[string]any{"subject": m} }
	cases := []struct {
		name   string
		events map[string]any
		mod    func(map[string]any)
		check  func(*SET) string
	}{
		{"unknown event type", map[string]any{"https://example.test/event/x": map[string]any{}}, nil,
			func(s *SET) string {
				if s.Known || Actionable(s.EventType) || s.EventType != "https://example.test/event/x" {
					return "unknown event classified as known"
				}
				return ""
			}},
		{"credential-change", map[string]any{EventCredentialChange: subj(map[string]any{"format": "email", "email": "alice@larkspur.example"})}, nil,
			func(s *SET) string {
				if !Actionable(s.EventType) || s.Subject.Format != "email" || s.Subject.ID != "alice@larkspur.example" {
					return "credential-change"
				}
				return ""
			}},
		{"account-disabled with opaque", map[string]any{EventAccountDisabled: subj(map[string]any{"format": "opaque", "id": "x-1"})}, nil,
			func(s *SET) string {
				if s.EventType != EventAccountDisabled || s.Subject.Format != "opaque" || s.Subject.ID != "x-1" {
					return "opaque"
				}
				return ""
			}},
		{"verification", map[string]any{EventVerification: map[string]any{"state": "abc"}}, nil,
			func(s *SET) string {
				if s.EventType != EventVerification || Actionable(s.EventType) || s.Payload["state"] != "abc" || s.Subject.Problem == "" {
					return "verification"
				}
				return ""
			}},
		{"complex subject with a user and a session", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "complex",
			"user":    map[string]any{"format": "iss_sub", "iss": testIssuer, "sub": "00u1"},
			"session": map[string]any{"format": "opaque", "id": "sess-9"}})}, nil,
			func(s *SET) string {
				if s.Subject.Format != "complex" || s.Subject.User == nil || s.Subject.User.ID != "00u1" || s.Subject.Session != "sess-9" ||
					s.Subject.Label() != "00u1 (session sess-9)" {
					return "complex"
				}
				return ""
			}},
		{"complex subject without a format", map[string]any{EventSessionRevoked: subj(map[string]any{
			"user": map[string]any{"format": "email", "email": "a@b.example"}})}, nil,
			func(s *SET) string {
				if s.Subject.Format != "complex" || s.Subject.User == nil || s.Subject.User.ID != "a@b.example" {
					return "implied complex"
				}
				return ""
			}},
		{"complex subject without a user", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "complex",
			"session": map[string]any{"format": "opaque", "id": "s"}})}, nil,
			func(s *SET) string {
				if s.Subject.Problem == "" {
					return "complex without user is usable"
				}
				return ""
			}},
		{"nested complex", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "complex",
			"user": map[string]any{"format": "complex", "user": map[string]any{"format": "email", "email": "a@b"}}})}, nil,
			func(s *SET) string {
				if s.Subject.User == nil || s.Subject.User.Problem == "" {
					return "nested complex accepted"
				}
				return ""
			}},
		{"account uri", map[string]any{EventAccountDisabled: subj(map[string]any{"format": "account", "uri": "acct:alice@larkspur.example"})}, nil,
			func(s *SET) string {
				if s.Subject.ID != "alice@larkspur.example" {
					return "account uri " + s.Subject.ID
				}
				return ""
			}},
		{"unknown subject format", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "phone_number", "phone_number": "+1"})}, nil,
			func(s *SET) string {
				if s.Subject.Problem != "unsupported subject format" {
					return "phone number accepted"
				}
				return ""
			}},
		{"iss_sub without sub", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "iss_sub", "iss": "x"})}, nil,
			func(s *SET) string {
				if s.Subject.Problem == "" {
					return "iss_sub without sub accepted"
				}
				return ""
			}},
		{"subject too long", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "email", "email": strings.Repeat("a", 600)})}, nil,
			func(s *SET) string {
				if s.Subject.ID != "" || s.Subject.Problem == "" {
					return "long subject accepted"
				}
				return ""
			}},
		{"top-level sub_id", map[string]any{EventSessionRevoked: map[string]any{}},
			func(c map[string]any) { c["sub_id"] = map[string]any{"format": "email", "email": "top@x.example"} },
			func(s *SET) string {
				if s.Subject.ID != "top@x.example" {
					return "sub_id"
				}
				return ""
			}},
		{"legacy sub claim", map[string]any{EventSessionRevoked: map[string]any{}},
			func(c map[string]any) { c["sub"] = "00uLegacy" },
			func(s *SET) string {
				if s.Subject.Format != "iss_sub" || s.Subject.ID != "00uLegacy" || s.Subject.Issuer != testIssuer {
					return "legacy sub"
				}
				return ""
			}},
		{"the event's subject wins over sub_id", map[string]any{EventSessionRevoked: subj(map[string]any{"format": "opaque", "id": "inner"})},
			func(c map[string]any) { c["sub_id"] = map[string]any{"format": "opaque", "id": "outer"} },
			func(s *SET) string {
				if s.Subject.ID != "inner" {
					return "precedence"
				}
				return ""
			}},
		{"no subject at all", map[string]any{EventSessionRevoked: map[string]any{}}, nil,
			func(s *SET) string {
				if s.Subject.Problem == "" || s.Subject.Label() != "(none)" {
					return "missing subject"
				}
				return ""
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if msg := tc.check(parse(tc.events, tc.mod)); msg != "" {
				t.Error(msg)
			}
		})
	}
}

func TestParseJWKS(t *testing.T) {
	sg := newSigner(t, jose.ES256, "k1")
	good, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sg.jwk}})
	keys, err := ParseJWKS(good)
	if err != nil || len(keys) != 1 || keys[0].KeyID != "k1" {
		t.Fatalf("ParseJWKS = %v, %v", keys, err)
	}
	priv := newSigner(t, jose.RS256, "p")
	_ = priv
	for name, raw := range map[string]string{
		"not json":  `x`,
		"no keys":   `{"keys":[]}`,
		"symmetric": `{"keys":[{"kty":"oct","k":"c2VjcmV0c2VjcmV0c2VjcmV0","kid":"h"}]}`,
		"private":   privateJWKS(t),
		"enc only":  `{"keys":[` + encOnly(t, sg) + `]}`,
	} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func privateJWKS(t *testing.T) string {
	t.Helper()
	k := newPrivate(t)
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func encOnly(t *testing.T, sg *signer) string {
	k := sg.jwk
	k.Use = "enc"
	raw, _ := json.Marshal(k)
	return string(raw)
}
