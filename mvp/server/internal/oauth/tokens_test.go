package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (h *harness) signingKey(slug string) *keys.SigningKey {
	h.tb.Helper()
	var sk *keys.SigningKey
	if err := h.db.ReadTenant(context.Background(), h.tenantID(slug), func(tx *store.TenantTx) error {
		var err error
		sk, err = keys.ActiveSigningKey(tx, store.KeyPurposeAccessToken, h.sealer)
		return err
	}); err != nil {
		h.tb.Fatal(err)
	}
	return sk
}

// forged describes an access token minted by the test, signed with a real
// tenant key so that only the property under test is wrong.
type forged struct {
	signer string // tenant whose key signs (default slugA)
	header func(map[string]any)
	claims func(map[string]any)
	sign   func(input string) string // overrides the signature
}

// forge builds a token like the one in real (same session, user, client and
// DPoP key) with the given changes.
func (h *harness) forge(real tokens, f forged) string {
	h.tb.Helper()
	_, c := decodeJWT(h.tb, real.Access)
	if f.signer == "" {
		f.signer = slugA
	}
	sk := h.signingKey(f.signer)
	hdr := map[string]any{"typ": "at+jwt", "alg": "ES256", "kid": sk.KID}
	now := h.clock.Now()
	claims := map[string]any{"iss": c["iss"], "sub": c["sub"], "aud": c["aud"], "client_id": c["client_id"], "iat": now.Unix(),
		"nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": "at_forged", "scope": c["scope"], "tid": c["tid"],
		"sid": c["sid"], "auth_time": now.Unix(), "cnf": c["cnf"]}
	if f.header != nil {
		f.header(hdr)
	}
	if f.claims != nil {
		f.claims(claims)
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	input := b64u(hb) + "." + b64u(cb)
	if f.sign != nil {
		return input + "." + f.sign(input)
	}
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, sk.Key.(*ecdsa.PrivateKey), sum[:])
	if err != nil {
		h.tb.Fatal(err)
	}
	return input + "." + b64u(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func set(k string, v any) func(map[string]any) { return func(m map[string]any) { m[k] = v } }
func del(k string) func(map[string]any)        { return func(m map[string]any) { delete(m, k) } }

// TestVerifyAccessToken: every rule of §10.4 at the resource server, with a
// signed token that is otherwise valid (the "valid" case is the control).
func TestVerifyAccessToken(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	real, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	realB, _ := h.signInCLI(slugB, "bob@b.example", viewer, authtest.Phr, newKey(t))
	_, rc := decodeJWT(t, real.Access)
	hmacSign := func(input string) string {
		m := hmac.New(sha256.New, []byte("a shared secret"))
		m.Write([]byte(input))
		return b64u(m.Sum(nil))
	}
	other := uuid.New().String()
	tests := []struct {
		name   string
		f      forged
		reason string // "" = accepted
	}{
		{name: "valid"},
		{name: "typ in capitals", f: forged{header: set("typ", "AT+JWT")}},
		{name: "typ JWT", f: forged{header: set("typ", "JWT")}, reason: auth.FailInvalidToken},
		{name: "typ missing", f: forged{header: del("typ")}, reason: auth.FailInvalidToken},
		{name: "alg none", f: forged{header: set("alg", "none"), sign: func(string) string { return "" }}, reason: auth.FailInvalidToken},
		{name: "alg HS256", f: forged{header: set("alg", "HS256"), sign: hmacSign}, reason: auth.FailInvalidToken},
		{name: "alg RS256", f: forged{header: set("alg", "RS256")}, reason: auth.FailInvalidToken},
		{name: "alg ES384", f: forged{header: set("alg", "ES384")}, reason: auth.FailInvalidToken},
		{name: "kid missing", f: forged{header: del("kid")}, reason: auth.FailInvalidToken},
		{name: "kid unknown", f: forged{header: set("kid", "tenant-a-20200101-abcdef")}, reason: auth.FailInvalidToken},
		{name: "kid of 65 characters", f: forged{header: set("kid", strings.Repeat("k", 65))}, reason: auth.FailInvalidToken},
		{name: "jku header", f: forged{header: set("jku", "https://evil.example/jwks")}, reason: auth.FailInvalidToken},
		{name: "jwk header", f: forged{header: set("jwk", map[string]any{"kty": "EC"})}, reason: auth.FailInvalidToken},
		{name: "x5u header", f: forged{header: set("x5u", "https://evil.example/c")}, reason: auth.FailInvalidToken},
		{name: "x5c header", f: forged{header: set("x5c", []string{"AAAA"})}, reason: auth.FailInvalidToken},
		{name: "crit header", f: forged{header: set("crit", []string{"exp"})}, reason: auth.FailInvalidToken},
		// the tenant's key and the issuer
		{name: "signed with tenant B's key under tenant A's issuer", f: forged{signer: slugB}, reason: auth.FailInvalidToken},
		{name: "tenant B's issuer, tenant A's key", f: forged{claims: set("iss", h.srv.URL+"/t/"+slugB)}, reason: auth.FailInvalidToken},
		{name: "tenant B's tid", f: forged{claims: set("tid", tenantBID.String())}, reason: auth.FailInvalidToken},
		{name: "issuer with a path suffix", f: forged{claims: set("iss", h.srv.URL+"/t/"+slugA+"/x")}, reason: auth.FailInvalidToken},
		{name: "issuer of another host", f: forged{claims: set("iss", "https://evil.example/t/"+slugA)}, reason: auth.FailInvalidToken},
		{name: "issuer of an unknown tenant", f: forged{claims: set("iss", h.srv.URL+"/t/nobody")}, reason: auth.FailInvalidToken},
		{name: "issuer is the platform tenant", f: forged{claims: set("iss", h.srv.URL+"/t/_platform")}, reason: auth.FailInvalidToken},
		{name: "issuer missing", f: forged{claims: del("iss")}, reason: auth.FailInvalidToken},
		// claims
		{name: "audience of another API", f: forged{claims: set("aud", "https://evil.example/api")}, reason: auth.FailInvalidToken},
		{name: "audience list", f: forged{claims: set("aud", []string{h.srv.URL + "/api"})}, reason: auth.FailInvalidToken},
		{name: "audience missing", f: forged{claims: del("aud")}, reason: auth.FailInvalidToken},
		{name: "expired 20 s ago (inside the leeway)", f: forged{claims: func(m map[string]any) { m["exp"] = h.clock.Now().Add(-20 * time.Second).Unix() }}},
		{name: "expired 40 s ago", f: forged{claims: func(m map[string]any) { m["exp"] = h.clock.Now().Add(-40 * time.Second).Unix() }}, reason: auth.FailInvalidToken},
		{name: "exp missing", f: forged{claims: del("exp")}, reason: auth.FailInvalidToken},
		{name: "issued 20 s in the future", f: forged{claims: func(m map[string]any) { m["iat"] = h.clock.Now().Add(20 * time.Second).Unix() }}},
		{name: "issued 40 s in the future", f: forged{claims: func(m map[string]any) { m["iat"] = h.clock.Now().Add(40 * time.Second).Unix() }}, reason: auth.FailInvalidToken},
		{name: "iat missing", f: forged{claims: del("iat")}, reason: auth.FailInvalidToken},
		{name: "not before 40 s ahead", f: forged{claims: func(m map[string]any) { m["nbf"] = h.clock.Now().Add(40 * time.Second).Unix() }}, reason: auth.FailInvalidToken},
		{name: "nbf missing is fine", f: forged{claims: del("nbf")}},
		{name: "client unknown", f: forged{claims: set("client_id", "nobody")}, reason: auth.FailInvalidToken},
		{name: "client missing", f: forged{claims: del("client_id")}, reason: auth.FailInvalidToken},
		{name: "scope empty", f: forged{claims: set("scope", " ")}, reason: auth.FailInvalidToken},
		{name: "scope missing", f: forged{claims: del("scope")}, reason: auth.FailInvalidToken},
		{name: "not DPoP-bound", f: forged{claims: del("cnf")}, reason: auth.FailInvalidToken},
		{name: "cnf without jkt", f: forged{claims: set("cnf", map[string]any{})}, reason: auth.FailInvalidToken},
		{name: "bound to another key", f: forged{claims: set("cnf", map[string]any{"jkt": jktOf(t, newKey(t))})}, reason: auth.FailInvalidDPoP},
		{name: "no session (a machine token)", f: forged{claims: del("sid")}, reason: auth.FailInvalidToken},
		{name: "sid not a uuid", f: forged{claims: set("sid", "x")}, reason: auth.FailInvalidToken},
		{name: "sub not a user", f: forged{claims: set("sub", "cli_"+other)}, reason: auth.FailInvalidToken},
		{name: "sub of another user", f: forged{claims: set("sub", SubjectPrefix+other)}, reason: auth.FailInvalidSession},
		{name: "sid of no session", f: forged{claims: set("sid", other)}, reason: auth.FailInvalidSession},
		{name: "sid of tenant B's session", f: forged{claims: set("sid", realBsid(t, realB))}, reason: auth.FailInvalidSession},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := h.forge(real, tt.f)
			w := h.whoamiReq(k, tok)
			if tt.reason == "" {
				if w.Status != 200 || w.str("user_id") != strings.TrimPrefix(rc["sub"].(string), SubjectPrefix) {
					t.Errorf("want accepted, got %d %s", w.Status, w.Raw)
				}
				return
			}
			if w.Status != 401 || w.str("error") != "login_required" || w.str("reason") != tt.reason {
				t.Errorf("want 401 with reason %s, got %d %s", tt.reason, w.Status, w.Raw)
			}
			if w.Header.Get("WWW-Authenticate") == "" || !strings.HasPrefix(w.Header.Get("WWW-Authenticate"), "DPoP ") {
				t.Errorf("WWW-Authenticate = %q", w.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

func realBsid(t testing.TB, b tokens) string {
	_, c := decodeJWT(t, b.Access)
	return c["sid"].(string)
}

// TestVerifyTransport: the Authorization scheme, the DPoP header and the
// proof's binding to this request and this token (§10.4 rules 1 and 7).
func TestVerifyTransport(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	tok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	target := h.srv.URL + "/api/whoami"
	proof := func() string { return h.proof(k, "GET", target, tok.Access, "") }
	reason := func(w resp) string { return w.str("reason") }

	t.Run("control", func(t *testing.T) {
		if w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": proof()}); w.Status != 200 {
			t.Fatalf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("a bound token under the Bearer scheme", func(t *testing.T) {
		for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
			w := h.whoamiWith(tok.Access, scheme, map[string]string{"DPoP": proof()})
			if w.Status != 401 || reason(w) != auth.FailInvalidToken || !strings.Contains(w.Header.Get("WWW-Authenticate"), "DPoP") {
				t.Errorf("%s: %d %s %q", scheme, w.Status, w.Raw, w.Header.Get("WWW-Authenticate"))
			}
		}
	})
	t.Run("the scheme is case-insensitive", func(t *testing.T) {
		if w := h.whoamiWith(tok.Access, "dpop", map[string]string{"DPoP": proof()}); w.Status != 200 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("another scheme", func(t *testing.T) {
		if w := h.whoamiWith(tok.Access, "Basic", map[string]string{"DPoP": proof()}); w.Status != 401 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("no DPoP header", func(t *testing.T) {
		if w := h.whoamiWith(tok.Access, "DPoP", nil); w.Status != 401 || reason(w) != auth.FailInvalidDPoP ||
			!strings.Contains(w.Header.Get("WWW-Authenticate"), `error="invalid_dpop_proof"`) {
			t.Errorf("%d %s %q", w.Status, w.Raw, w.Header.Get("WWW-Authenticate"))
		}
	})
	t.Run("two DPoP headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "DPoP "+tok.Access)
		req.Header.Add("DPoP", proof())
		req.Header.Add("DPoP", proof())
		if w := do(t, req); w.Status != 401 || reason(w) != auth.FailInvalidDPoP {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("two Authorization headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.Header.Add("Authorization", "DPoP "+tok.Access)
		req.Header.Add("Authorization", "DPoP "+tok.Access)
		req.Header.Set("DPoP", proof())
		if w := do(t, req); w.Status != 401 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("an empty token and an oversized one", func(t *testing.T) {
		for name, token := range map[string]string{"empty": "", "huge": strings.Repeat("a", MaxTokenBytes+1), "two words": "a b"} {
			if w := h.whoamiWith(token, "DPoP", map[string]string{"DPoP": proof()}); w.Status != 401 || reason(w) != auth.FailInvalidToken {
				t.Errorf("%s: %d %s", name, w.Status, w.Raw)
			}
		}
	})
	t.Run("a proof for another URL, method or token", func(t *testing.T) {
		for name, p := range map[string]string{
			"htu":       h.proof(k, "GET", h.srv.URL+"/api/other", tok.Access, ""),
			"host":      h.proof(k, "GET", "https://evil.example/api/whoami", tok.Access, ""),
			"htm":       h.proof(k, "POST", target, tok.Access, ""),
			"ath":       h.proof(k, "GET", target, "another-token", ""),
			"no ath":    h.proof(k, "GET", target, "", ""),
			"stale":     h.proofAt(k, "GET", target, tok.Access, "", h.clock.Now().Add(-2*time.Minute)),
			"future":    h.proofAt(k, "GET", target, tok.Access, "", h.clock.Now().Add(time.Minute)),
			"other key": h.proof(newKey(t), "GET", target, tok.Access, ""),
		} {
			if w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": p}); w.Status != 401 || reason(w) != auth.FailInvalidDPoP {
				t.Errorf("%s: %d %s", name, w.Status, w.Raw)
			}
		}
	})
	t.Run("a replayed proof", func(t *testing.T) {
		p := proof()
		if w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": p}); w.Status != 200 {
			t.Fatalf("first use: %d %s", w.Status, w.Raw)
		}
		if w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": p}); w.Status != 401 || reason(w) != auth.FailInvalidDPoP {
			t.Errorf("replay: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("the query string is not part of htu", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, target+"?a=1", nil)
		req.Header.Set("Authorization", "DPoP "+tok.Access)
		req.Header.Set("DPoP", proof())
		if w := do(t, req); w.Status != 200 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("a cookie does not rescue a bad token", func(t *testing.T) {
		l := h.login(slugA, "carol@a.example", viewer, authtest.Phr)
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		l.Apply(req)
		req.Header.Set("Authorization", "DPoP garbage")
		if w := do(t, req); w.Status != 401 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("a token cannot be a session cookie", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.AddCookie(auth.Cookies{}.Session(tok.Access))
		if w := do(t, req); w.Status != 401 {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
}

// TestVerifySessionState: the live session and user decide, not the token
// (§10.4 rule 6): revoking the session or disabling the user ends the
// token's use at once.
func TestVerifySessionState(t *testing.T) {
	tokenFor := func(h *harness, email string, k *ecdsa.PrivateKey) (tokens, uuid.UUID) {
		tok, _ := h.signInCLI(slugA, email, viewer, authtest.Phr, k)
		return tok, sidOf(t, tok.Access)
	}
	t.Run("sid revoked", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, sid := tokenFor(h, "alice@a.example", k)
		if w := h.whoamiReq(k, tok.Access); w.Status != 200 {
			t.Fatalf("%d %s", w.Status, w.Raw)
		}
		h.mutateTenant(slugA, func(tx *store.TenantTx) error { return auth.RevokeSession(tx, sid, auth.RevokedAdmin, h.clock.Now()) })
		if w := h.whoamiReq(k, tok.Access); w.Status != 401 || w.str("reason") != auth.FailRevoked {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("user disabled", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tx.DisableUser(userOf(t, tok.Access), "x", h.clock.Now()) })
		if w := h.whoamiReq(k, tok.Access); w.Status != 401 || w.str("reason") != auth.FailUserDisabled {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("session past its absolute expiry", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		h.clock.Advance(25 * time.Hour)
		long := h.forge(tok, forged{claims: func(m map[string]any) { m["exp"] = h.clock.Now().Add(time.Hour).Unix() }})
		if w := h.whoamiReq(k, long); w.Status != 401 || w.str("reason") != auth.FailExpired {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("session idle", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		h.clock.Advance(13 * time.Hour)
		long := h.forge(tok, forged{claims: func(m map[string]any) { m["exp"] = h.clock.Now().Add(time.Hour).Unix() }})
		if w := h.whoamiReq(k, long); w.Status != 401 || w.str("reason") != auth.FailExpired {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("a browser session is not a token session", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		l := h.login(slugA, "alice@a.example", viewer, authtest.Phr)
		browser := h.forge(tok, forged{claims: set("sid", l.SessionID.String())})
		if w := h.whoamiReq(k, browser); w.Status != 401 || w.str("reason") != auth.FailInvalidSession {
			t.Errorf("%d %s", w.Status, w.Raw)
		}
	})
	t.Run("a revoked signing key", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		if w := h.whoamiReq(k, tok.Access); w.Status != 200 {
			t.Fatalf("%d %s", w.Status, w.Raw)
		}
		h.mutateTenant(slugA, func(tx *store.TenantTx) error {
			return keys.RevokeKey(tx, slugA, h.signingKey(slugA).KID, h.sealer, h.clock.Now())
		})
		if w := h.whoamiReq(k, tok.Access); w.Status != 401 {
			t.Errorf("a token of a revoked key: %d %s", w.Status, w.Raw)
		}
		// a token signed with the new key works
		if w := h.whoamiReq(k, h.forge(tok, forged{})); w.Status != 200 {
			t.Errorf("a token of the new key: %d %s", w.Status, w.Raw)
		}
	})
	t.Run("roles come from the database, not the token", func(t *testing.T) {
		h := newHarness(t)
		k := newKey(t)
		tok, _ := tokenFor(h, "alice@a.example", k)
		if w := h.whoamiReq(k, tok.Access); fmt.Sprint(w.Body["active_roles"]) != "[viewer]" {
			t.Fatalf("%d %s", w.Status, w.Raw)
		}
		h.mutateTenant(slugA, func(tx *store.TenantTx) error {
			as, err := tx.RoleAssignments(userOf(t, tok.Access))
			if err != nil {
				return err
			}
			for _, a := range as {
				if err := tx.DeleteRoleAssignment(a.ID); err != nil {
					return err
				}
			}
			return nil
		})
		if w := h.whoamiReq(k, tok.Access); w.Status != 200 || len(w.Body["active_roles"].([]any)) != 0 {
			t.Errorf("after removing the role: %d %s", w.Status, w.Raw)
		}
	})
}

// TestVerifyRSNonce: with TESSERA_DPOP_RS_NONCE the resource server also
// requires its nonce.
func TestVerifyRSNonce(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.RSNonce = true })
	k := newKey(t)
	tok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	target := h.srv.URL + "/api/whoami"
	w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": h.proof(k, "GET", target, tok.Access, "")})
	nonce := w.Header.Get("DPoP-Nonce")
	if w.Status != 401 || w.str("reason") != auth.FailDPoPNonce || nonce == "" ||
		!strings.Contains(w.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Fatalf("without a nonce: %d %s nonce=%q %q", w.Status, w.Raw, nonce, w.Header.Get("WWW-Authenticate"))
	}
	if w := h.whoamiWith(tok.Access, "DPoP", map[string]string{"DPoP": h.proof(k, "GET", target, tok.Access, nonce)}); w.Status != 200 {
		t.Errorf("with the nonce: %d %s", w.Status, w.Raw)
	}
}

// TestAccessTokenLifetimes: 600 s, and 300 s with tessera:admin.
func TestAccessTokenExpiry(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AccessTokenTTL = 60 * time.Second })
	k := newKey(t)
	tok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	if tok.ExpiresIn != 60 {
		t.Errorf("expires_in = %d", tok.ExpiresIn)
	}
	h.clock.Advance(80 * time.Second) // 60 s and under the 30 s leeway
	if w := h.whoamiReq(k, tok.Access); w.Status != 200 {
		t.Errorf("inside the leeway: %d %s", w.Status, w.Raw)
	}
	h.clock.Advance(20 * time.Second)
	if w := h.whoamiReq(k, tok.Access); w.Status != 401 {
		t.Errorf("past the leeway: %d %s", w.Status, w.Raw)
	}
}

// FuzzVerifyAccessToken: whatever arrives in Authorization and DPoP, the
// verifier answers a failure or a principal, never panics and never reports
// an infrastructure error for malformed input.
func FuzzVerifyAccessToken(f *testing.F) {
	h := newHarness(f)
	k := newKey(f)
	tok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, k)
	target := h.srv.URL + "/api/whoami"
	seedProof := h.proof(k, "GET", target, tok.Access, "")
	parts := strings.Split(tok.Access, ".")
	f.Add("DPoP "+tok.Access, seedProof)
	f.Add("Bearer "+tok.Access, seedProof)
	f.Add("DPoP "+tok.Access, "")
	f.Add("DPoP "+parts[0]+"."+parts[1]+".", seedProof)
	f.Add("DPoP "+parts[0]+".e30."+parts[2], seedProof)
	f.Add("DPoP "+b64u([]byte(`{"typ":"at+jwt","alg":"ES256","kid":"x","jku":"y"}`))+"."+parts[1]+"."+parts[2], seedProof)
	f.Add("DPoP "+parts[0]+"."+b64u([]byte(`{"iss":"`+h.srv.URL+`/t/tenant-a","aud":["x"]}`))+"."+parts[2], seedProof)
	f.Add("DPoP "+h.forge(tok, forged{claims: set("exp", 1e300)}), seedProof)
	f.Add("DPoP "+h.forge(tok, forged{claims: set("sid", 5)}), seedProof)
	f.Add("DPoP ..", "..")
	f.Add("DPoP", "")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, authz, proof string) {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		// header values with control characters cannot be sent; set them directly
		req.Header["Authorization"] = []string{authz}
		req.Header["Dpop"] = []string{proof}
		vt, failure, err := h.svc.VerifyAccessToken(req)
		switch {
		case err != nil:
			t.Fatalf("infrastructure error for malformed input: %v", err)
		case (vt == nil) == (failure == nil):
			t.Fatalf("token %v and failure %v: exactly one must be set", vt, failure)
		case failure != nil && failure.Challenge == "":
			t.Fatal("a refusal without a challenge")
		}
	})
}
