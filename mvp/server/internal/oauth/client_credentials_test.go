package oauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Machine clients (design §9.5, §10.1, §19 PR11): the client credentials
// grant with private_key_jwt client authentication (RFC 7523), DPoP where the
// client requires it, and what a machine principal may do (roles ∩ scope, no
// step-up).

// machine is a registered machine client and its private key.
type machine struct {
	slug     string
	clientID string
	rowID    uuid.UUID
	key      any // *ecdsa.PrivateKey | ed25519.PrivateKey
	alg      string
	kid      string
}

type machineOpts struct {
	slug     string // default slugA
	scopes   []string
	roles    []string
	noDPoP   bool // dpop_required = false
	ed25519  bool
	disabled bool
}

func (m *machine) publicJWK() jose.JSONWebKey {
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return jose.JSONWebKey{Key: &k.PublicKey, KeyID: m.kid, Algorithm: m.alg, Use: "sig"}
	default:
		return jose.JSONWebKey{Key: k.(ed25519.PrivateKey).Public(), KeyID: m.kid, Algorithm: m.alg, Use: "sig"}
	}
}

func newMachineKey(tb testing.TB, edwards bool) (key any, alg string) {
	tb.Helper()
	if edwards {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		return k, "EdDSA"
	}
	return newKey(tb), "ES256"
}

// addMachine registers a machine client owned by a fresh user of the tenant.
func (h *harness) addMachine(o machineOpts) *machine {
	h.tb.Helper()
	if o.slug == "" {
		o.slug = slugA
	}
	if o.scopes == nil {
		o.scopes = []string{"tessera:read"}
	}
	if o.roles == nil {
		o.roles = []string{"viewer"}
	}
	m := &machine{slug: o.slug, kid: "k1", clientID: "tsc_" + strings.ToLower(uuid.NewString()[:12])}
	m.key, m.alg = newMachineKey(h.tb, o.ed25519)
	owner := h.login(o.slug, "owner-"+m.clientID+"@example.test", viewer, authtest.Phr)
	set, raw, err := ParseClientJWKS(mustJSON(h.tb, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{m.publicJWK()}}))
	if err != nil || len(set.Keys) != 1 {
		h.tb.Fatalf("ParseClientJWKS: %v", err)
	}
	status := store.ClientActive
	if o.disabled {
		status = store.ClientDisabled
	}
	c := &store.APIClient{ClientID: m.clientID, Name: "ETL job", Kind: store.ClientMachine,
		GrantTypes: []string{GrantClientCredentials}, TokenEndpointAuthMethod: "private_key_jwt", JWKS: raw,
		DPoPRequired: !o.noDPoP, AllowedScopes: o.scopes, Roles: o.roles, OwnerUserID: &owner.UserID, Status: status,
		CreatedAt: h.clock.Now()}
	h.mutateTenant(o.slug, func(tx *store.TenantTx) error { return tx.InsertAPIClient(c) })
	m.rowID = c.ID
	return m
}

func mustJSON(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func (h *harness) tokenURL(slug string) string   { return h.srv.URL + "/t/" + slug + "/oauth/token" }
func (h *harness) introspectURL(s string) string { return h.srv.URL + "/t/" + s + "/oauth/introspect" }

// signInput signs a JWS signing input with m's key (raw r||s for ES256).
func signInput(m *machine, input string) string {
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			panic(err)
		}
		return b64u(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
	default:
		return b64u(ed25519.Sign(k.(ed25519.PrivateKey), []byte(input)))
	}
}

// asrt describes a client assertion with the changes under test; the zero
// value is a valid assertion for the token endpoint of the client's tenant.
type asrt struct {
	aud    string
	header func(map[string]any)
	claims func(map[string]any)
	sign   func(input string) string // overrides the signature
}

// assertion builds a client assertion for m.
func (h *harness) assertion(m *machine, a asrt) string {
	h.tb.Helper()
	if a.aud == "" {
		a.aud = h.tokenURL(m.slug)
	}
	now := h.clock.Now()
	hdr := map[string]any{"alg": m.alg, "kid": m.kid}
	claims := map[string]any{"iss": m.clientID, "sub": m.clientID, "aud": a.aud, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "jti": "j_" + uuid.NewString()}
	if a.header != nil {
		a.header(hdr)
	}
	if a.claims != nil {
		a.claims(claims)
	}
	input := b64u(mustJSON(h.tb, hdr)) + "." + b64u(mustJSON(h.tb, claims))
	if a.sign != nil {
		return input + "." + a.sign(input)
	}
	return input + "." + signInput(m, input)
}

// ccOpts shapes a token request.
type ccOpts struct {
	scope         string
	dpopKey       *ecdsa.PrivateKey // nil: no DPoP header
	omitClientID  bool
	noNonce       bool
	extra         url.Values
	assertionType string
}

func (h *harness) ccForm(m *machine, assertion string, o ccOpts) url.Values {
	f := url.Values{"grant_type": {GrantClientCredentials}, "client_assertion_type": {ClientAssertionType},
		"client_assertion": {assertion}}
	if !o.omitClientID {
		f.Set("client_id", m.clientID)
	}
	if o.scope != "" {
		f.Set("scope", o.scope)
	}
	if o.assertionType != "" {
		f.Set("client_assertion_type", o.assertionType)
	}
	for k, v := range o.extra {
		f[k] = v
	}
	return f
}

// ccReq posts a client credentials request to the token endpoint of m's tenant.
func (h *harness) ccReq(m *machine, assertion string, o ccOpts) resp {
	h.tb.Helper()
	hdr := map[string]string{}
	if o.dpopKey != nil {
		nonce := h.nonce()
		if o.noNonce {
			nonce = ""
		}
		hdr["DPoP"] = h.proof(o.dpopKey, "POST", h.tokenURL(m.slug), "", nonce)
	}
	return h.postForm("/t/"+m.slug+"/oauth/token", h.ccForm(m, assertion, o), hdr)
}

// machineToken gets an access token for m (DPoP-bound when k is set).
func (h *harness) machineToken(m *machine, scope string, k *ecdsa.PrivateKey) tokens {
	h.tb.Helper()
	return tokensOf(h.tb, h.ccReq(m, h.assertion(m, asrt{}), ccOpts{scope: scope, dpopKey: k}))
}

func (h *harness) introspectReq(m *machine, assertion, token string, extra url.Values) resp {
	h.tb.Helper()
	f := url.Values{"client_id": {m.clientID}, "client_assertion_type": {ClientAssertionType},
		"client_assertion": {assertion}, "token": {token}}
	for k, v := range extra {
		f[k] = v
	}
	return h.postForm("/t/"+m.slug+"/oauth/introspect", f, nil)
}

// introspect asks for token as m, with a good assertion for the endpoint.
func (h *harness) introspect(m *machine, token string) resp {
	h.tb.Helper()
	return h.introspectReq(m, h.assertion(m, asrt{aud: h.introspectURL(m.slug)}), token, nil)
}

func (h *harness) failedAuthEvents(slug string) []*store.AuditEvent {
	return h.auditEvents(slug, "oauth.client_auth.failed")
}

// perms reads the permissions of a machine token as the API resolves them.
func (h *harness) perms(k *ecdsa.PrivateKey, token string) []string {
	h.tb.Helper()
	r := h.whoamiReq(k, token)
	if r.Status != 200 {
		h.tb.Fatalf("whoami: %d %s", r.Status, r.Raw)
	}
	var out []string
	for _, p := range r.Body["permissions"].([]any) {
		out = append(out, p.(string))
	}
	return out
}

// TestClientCredentials_Issue: both algorithms get a DPoP-bound access token
// with the machine claims of §10.1 and no refresh token, usable at the API.
func TestClientCredentials_Issue(t *testing.T) {
	for _, ed := range []bool{false, true} {
		name := "ES256"
		if ed {
			name = "EdDSA"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			m := h.addMachine(machineOpts{ed25519: ed, scopes: []string{"tessera:read", "tessera:write"}})
			k := newKey(t)
			r := h.ccReq(m, h.assertion(m, asrt{}), ccOpts{dpopKey: k})
			tok := tokensOf(t, r)
			if r.str("token_type") != "DPoP" || tok.Refresh != "" || tok.Scope != "tessera:read tessera:write" || tok.ExpiresIn != 600 {
				t.Errorf("response: %s", r.Raw)
			}
			if r.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q", r.Header.Get("Cache-Control"))
			}
			hdr, c := decodeJWT(t, tok.Access)
			if hdr["typ"] != "at+jwt" || hdr["alg"] != "ES256" {
				t.Errorf("header %v", hdr)
			}
			if c["sub"] != MachineSubjectPrefix+m.rowID.String() || c["client_id"] != m.clientID || c["tid"] != tenantAID.String() {
				t.Errorf("claims %v", c)
			}
			for _, absent := range []string{"sid", "auth_time", "acr", "amr"} {
				if _, ok := c[absent]; ok {
					t.Errorf("a machine token must not carry %s", absent)
				}
			}
			if cnf, _ := c["cnf"].(map[string]any); cnf["jkt"] != jktOf(t, k) {
				t.Errorf("cnf = %v", c["cnf"])
			}
			// the API accepts it, as the client and with no user or session
			w := h.whoamiReq(k, tok.Access)
			if w.Status != 200 || w.str("kind") != auth.KindAPIClient || w.str("client_id") != m.clientID || w.str("user_id") != "" ||
				w.Body["has_session"] != false || w.str("via") != auth.ViaDPoP {
				t.Errorf("whoami: %d %s", w.Status, w.Raw)
			}
			// the issue is audited with the key thumbprint and never the token
			evs := h.auditEvents(slugA, "oauth.token.issued")
			if len(evs) != 1 || !strings.Contains(string(evs[0].Detail), jktOf(t, k)) || strings.Contains(string(evs[0].Detail), tok.Access) ||
				evs[0].ActorType != store.ActorAPIClient || evs[0].ActorID == nil || *evs[0].ActorID != m.clientID {
				t.Errorf("issue events: %+v", evs)
			}
		})
	}
}

// TestClientCredentials_ClientIDOptional: RFC 7523 §3, the assertion names the client.
func TestClientCredentials_ClientIDOptional(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	r := h.ccReq(m, h.assertion(m, asrt{}), ccOpts{dpopKey: newKey(t), omitClientID: true})
	tokensOf(t, r)
	// a client_id that is not the assertion's is refused
	other := h.addMachine(machineOpts{})
	r = h.ccReq(other, h.assertion(m, asrt{}), ccOpts{dpopKey: newKey(t)})
	if r.Status != 401 || r.str("error") != "invalid_client" {
		t.Errorf("client_id of another client: %d %s", r.Status, r.Raw)
	}
}

// TestClientCredentials_AssertionRefused: every way an assertion is wrong is
// invalid_client, an audited oauth.client_auth.failed with the reason (never
// shown to the client), and no token.
func TestClientCredentials_AssertionRefused(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	other := newKey(t) // a key that is not registered
	otherM := &machine{slug: slugA, clientID: m.clientID, key: other, alg: "ES256", kid: m.kid}
	otherKid := &machine{slug: slugA, clientID: m.clientID, key: other, alg: "ES256", kid: "unregistered"}
	edKey, _ := newMachineKey(t, true)
	edUnregistered := &machine{slug: slugA, clientID: m.clientID, key: edKey, alg: "EdDSA", kid: m.kid}
	hs := func(input string) string {
		mac := hmac.New(sha256.New, []byte("a shared secret of at least 32 bytes!!"))
		mac.Write([]byte(input))
		return b64u(mac.Sum(nil))
	}
	now := func() time.Time { return h.clock.Now() }
	tests := []struct {
		name   string
		m      *machine // signs (default m)
		a      asrt
		reason string // a fragment of the audited reason
	}{
		{name: "signed with an unregistered key (same kid)", m: otherM, reason: "not signed by a key registered"},
		{name: "signed with an unregistered key (unknown kid)", m: otherKid, reason: "not signed by a key registered"},
		{name: "signed with an unregistered Ed25519 key", m: edUnregistered, reason: "not signed by a key registered"},
		{name: "alg HS256", a: asrt{header: func(m map[string]any) { m["alg"] = "HS256" }, sign: hs}, reason: "ES256 or EdDSA"},
		{name: "alg none", a: asrt{header: func(m map[string]any) { m["alg"] = "none" }, sign: func(string) string { return "" }}, reason: "ES256 or EdDSA"},
		{name: "alg RS256", a: asrt{header: func(m map[string]any) { m["alg"] = "RS256" }}, reason: "ES256 or EdDSA"},
		{name: "alg ES384", a: asrt{header: func(m map[string]any) { m["alg"] = "ES384" }}, reason: "ES256 or EdDSA"},
		{name: "alg EdDSA header over an ES256 signature", a: asrt{header: func(m map[string]any) { m["alg"] = "EdDSA" }}, reason: "not signed by a key registered"},
		{name: "jwk header", a: asrt{header: func(m map[string]any) { m["jwk"] = map[string]any{"kty": "EC"} }}, reason: "must not contain jwk"},
		{name: "jku header", a: asrt{header: func(m map[string]any) { m["jku"] = "https://evil.example/jwks" }}, reason: "must not contain jku"},
		{name: "x5c header", a: asrt{header: func(m map[string]any) { m["x5c"] = []string{"AAAA"} }}, reason: "must not contain x5c"},
		{name: "crit header", a: asrt{header: func(m map[string]any) { m["crit"] = []string{"exp"} }}, reason: "must not contain crit"},
		{name: "typ dpop+jwt", a: asrt{header: func(m map[string]any) { m["typ"] = "dpop+jwt" }}, reason: "type of another kind"},
		{name: "typ at+jwt", a: asrt{header: func(m map[string]any) { m["typ"] = "AT+JWT" }}, reason: "type of another kind"},
		{name: "aud is the issuer", a: asrt{aud: h.srv.URL + "/t/" + slugA}, reason: "aud must be the URL of this endpoint"},
		{name: "aud is another tenant's token endpoint", a: asrt{aud: h.tokenURL(slugB)}, reason: "aud must be the URL"},
		{name: "aud is the introspection endpoint", a: asrt{aud: h.introspectURL(slugA)}, reason: "aud must be the URL"},
		{name: "aud with a trailing slash", a: asrt{aud: h.tokenURL(slugA) + "/"}, reason: "aud must be the URL"},
		{name: "aud as a list", a: asrt{claims: func(m map[string]any) { m["aud"] = []string{h.tokenURL(slugA)} }}, reason: "aud must be the URL"},
		{name: "aud missing", a: asrt{claims: func(m map[string]any) { delete(m, "aud") }}, reason: "aud must be the URL"},
		{name: "exp 5 minutes and 1 second after iat", a: asrt{claims: func(m map[string]any) {
			m["exp"] = now().Add(301 * time.Second).Unix()
		}}, reason: "more than 300 seconds after iat"},
		{name: "exp one hour out", a: asrt{claims: func(m map[string]any) { m["exp"] = now().Add(time.Hour).Unix() }}, reason: "more than 300 seconds"},
		{name: "exp in the past", a: asrt{claims: func(m map[string]any) {
			m["iat"], m["exp"] = now().Add(-2*time.Minute).Unix(), now().Add(-time.Minute).Unix()
		}}, reason: "expired"},
		{name: "exp missing", a: asrt{claims: func(m map[string]any) { delete(m, "exp") }}, reason: "no exp"},
		{name: "iat missing", a: asrt{claims: func(m map[string]any) { delete(m, "iat") }}, reason: "no iat"},
		{name: "exp equal to iat", a: asrt{claims: func(m map[string]any) {
			m["iat"], m["exp"] = now().Add(30*time.Second).Unix(), now().Add(30*time.Second).Unix()
		}}, reason: "exp must be after iat"},
		{name: "iat in the future", a: asrt{claims: func(m map[string]any) {
			m["iat"], m["exp"] = now().Add(5*time.Minute).Unix(), now().Add(9*time.Minute).Unix()
		}}, reason: "issued in the future"},
		{name: "nbf in the future", a: asrt{claims: func(m map[string]any) { m["nbf"] = now().Add(5 * time.Minute).Unix() }}, reason: "not yet valid"},
		{name: "iss is another client", a: asrt{claims: func(m map[string]any) { m["iss"] = "tsc_other" }}, reason: "iss and sub"},
		{name: "sub is another client", a: asrt{claims: func(m map[string]any) { m["sub"] = "tsc_other" }}, reason: "iss and sub"},
		{name: "iss missing", a: asrt{claims: func(m map[string]any) { delete(m, "iss") }}, reason: "iss and sub"},
		{name: "jti missing", a: asrt{claims: func(m map[string]any) { delete(m, "jti") }}, reason: "needs a jti"},
		{name: "jti of 129 bytes", a: asrt{claims: func(m map[string]any) { m["jti"] = strings.Repeat("j", 129) }}, reason: "needs a jti"},
		{name: "exp is not a number", a: asrt{claims: func(m map[string]any) { m["exp"] = "soon" }}, reason: ""},
		{name: "exp is enormous", a: asrt{claims: func(m map[string]any) { m["exp"] = 1e300 }}, reason: "not a valid time"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer := m
			if tc.m != nil {
				signer = tc.m
			}
			before := len(h.failedAuthEvents(slugA))
			r := h.ccReq(m, h.assertion(signer, tc.a), ccOpts{dpopKey: newKey(t)})
			if r.Status != 401 || r.str("error") != "invalid_client" || r.str("access_token") != "" {
				t.Fatalf("%d %s", r.Status, r.Raw)
			}
			if strings.Contains(r.Raw, "registered") || strings.Contains(r.Raw, "aud") {
				t.Errorf("the response says why: %s", r.Raw)
			}
			evs := h.failedAuthEvents(slugA)
			if len(evs) != before+1 {
				t.Fatalf("want one more oauth.client_auth.failed event, have %d (was %d)", len(evs), before)
			}
			e := evs[len(evs)-1]
			if e.Outcome != store.OutcomeFailure || e.ActorType != store.ActorAnonymous || !strings.Contains(string(e.Detail), tc.reason) {
				t.Errorf("event %s %s: %s", e.Outcome, e.ActorType, e.Detail)
			}
		})
	}
	if n := len(h.auditEvents(slugA, "oauth.token.issued")); n != 0 {
		t.Errorf("%d tokens were issued to refused assertions", n)
	}
	// the control: the same client with a good assertion gets a token
	h.machineToken(m, "", newKey(t))
}

// TestClientCredentials_Malformed: requests that are not client authentication
// at all are invalid_request (400), and nothing is consumed.
func TestClientCredentials_Malformed(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	good := func() string { return h.assertion(m, asrt{}) }
	tests := map[string]ccOpts{
		"a client_secret as well":          {extra: url.Values{"client_secret": {"s3cret"}}},
		"another assertion type":           {assertionType: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"},
		"two scopes parameters":            {extra: url.Values{"scope": {"tessera:read", "tessera:read"}}},
		"an oversized scope":               {scope: strings.Repeat("a ", 400)},
		"client_id repeated":               {extra: url.Values{"client_id": {m.clientID, m.clientID}}},
		"an assertion of 4 KiB and a byte": {extra: url.Values{"client_assertion": {strings.Repeat("a", MaxAssertionBytes+1)}}},
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			o.dpopKey = newKey(t)
			r := h.ccReq(m, good(), o)
			if r.Status != 400 && r.Status != 401 || r.str("access_token") != "" {
				t.Errorf("%d %s", r.Status, r.Raw)
			}
		})
	}
	// no assertion at all, and a Basic Authorization header
	r := h.postForm("/t/"+slugA+"/oauth/token", url.Values{"grant_type": {GrantClientCredentials}, "client_id": {m.clientID}},
		map[string]string{"DPoP": h.proof(newKey(t), "POST", h.tokenURL(slugA), "", h.nonce())})
	if r.Status != 400 || r.str("error") != "invalid_request" {
		t.Errorf("no assertion: %d %s", r.Status, r.Raw)
	}
	r = h.postForm("/t/"+slugA+"/oauth/token", h.ccForm(m, good(), ccOpts{}), map[string]string{"Authorization": "Basic Zm9vOmJhcg==",
		"DPoP": h.proof(newKey(t), "POST", h.tokenURL(slugA), "", h.nonce())})
	if r.Status != 400 || r.str("error") != "invalid_request" {
		t.Errorf("Authorization header: %d %s", r.Status, r.Raw)
	}
}

// TestClientCredentials_ReplayedJTI: an assertion is accepted once, until its
// exp; the same jti from another client or tenant is another assertion.
func TestClientCredentials_ReplayedJTI(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	a := h.assertion(m, asrt{})
	if r := h.ccReq(m, a, ccOpts{dpopKey: newKey(t)}); r.Status != 200 {
		t.Fatalf("first use: %d %s", r.Status, r.Raw)
	}
	r := h.ccReq(m, a, ccOpts{dpopKey: newKey(t)})
	if r.Status != 401 || r.str("error") != "invalid_client" {
		t.Fatalf("replay: %d %s", r.Status, r.Raw)
	}
	if evs := h.failedAuthEvents(slugA); len(evs) != 1 || !strings.Contains(string(evs[0].Detail), "replay") {
		t.Errorf("replay events: %+v", evs)
	}
	// still refused a moment later, and the same jti with a new assertion too
	h.clock.Advance(30 * time.Second)
	if r := h.ccReq(m, a, ccOpts{dpopKey: newKey(t)}); r.Status != 401 {
		t.Errorf("replay after 30 s: %d %s", r.Status, r.Raw)
	}
	c := h.assertion(m, asrt{claims: func(c map[string]any) { c["jti"] = "j_fixed" }})
	d := h.assertion(m, asrt{claims: func(c map[string]any) { c["jti"] = "j_fixed" }})
	if r := h.ccReq(m, c, ccOpts{dpopKey: newKey(t)}); r.Status != 200 {
		t.Fatalf("fixed jti: %d %s", r.Status, r.Raw)
	}
	if r := h.ccReq(m, d, ccOpts{dpopKey: newKey(t)}); r.Status != 401 {
		t.Errorf("same jti, new assertion: %d %s", r.Status, r.Raw)
	}
	// the same jti from another client is not a replay
	m2 := h.addMachine(machineOpts{})
	e := h.assertion(m2, asrt{claims: func(c map[string]any) { c["jti"] = "j_fixed" }})
	if r := h.ccReq(m2, e, ccOpts{dpopKey: newKey(t)}); r.Status != 200 {
		t.Errorf("same jti, another client: %d %s", r.Status, r.Raw)
	}
	// a refused assertion does not consume its jti: only a verified one does
	bad := h.assertion(m, asrt{aud: "https://elsewhere.example/token", claims: func(c map[string]any) { c["jti"] = "j_unburnt" }})
	h.ccReq(m, bad, ccOpts{dpopKey: newKey(t)})
	good := h.assertion(m, asrt{claims: func(c map[string]any) { c["jti"] = "j_unburnt" }})
	if r := h.ccReq(m, good, ccOpts{dpopKey: newKey(t)}); r.Status != 200 {
		t.Errorf("a refused assertion burnt the jti: %d %s", r.Status, r.Raw)
	}
}

// TestClientCredentials_NonceRetryKeepsAssertion: the DPoP nonce round trip
// fails before the assertion is looked at, so the client retries with the
// same assertion.
func TestClientCredentials_NonceRetryKeepsAssertion(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	a := h.assertion(m, asrt{})
	k := newKey(t)
	r := h.ccReq(m, a, ccOpts{dpopKey: k, noNonce: true})
	if r.Status != 400 || r.str("error") != "use_dpop_nonce" || r.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("without a nonce: %d %s", r.Status, r.Raw)
	}
	if r := h.ccReq(m, a, ccOpts{dpopKey: k}); r.Status != 200 {
		t.Errorf("retry with the nonce: %d %s", r.Status, r.Raw)
	}
}

// TestClientCredentials_DPoPRequired: a client that requires DPoP gets no
// token without a valid proof; one that does not gets a Bearer token, unless it
// sends a proof, which then binds the token.
func TestClientCredentials_DPoPRequired(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	r := h.ccReq(m, h.assertion(m, asrt{}), ccOpts{}) // no DPoP header
	if r.Status != 400 || r.str("error") != "invalid_dpop_proof" || r.str("access_token") != "" {
		t.Fatalf("missing DPoP: %d %s", r.Status, r.Raw)
	}
	// a proof for another URL, and a proof that is not a proof
	k := newKey(t)
	r = h.postForm("/t/"+slugA+"/oauth/token", h.ccForm(m, h.assertion(m, asrt{}), ccOpts{}),
		map[string]string{"DPoP": h.proof(k, "POST", h.tokenURL(slugB), "", h.nonce())})
	if r.Status != 400 || r.str("error") != "invalid_dpop_proof" {
		t.Errorf("proof for another endpoint: %d %s", r.Status, r.Raw)
	}
	r = h.postForm("/t/"+slugA+"/oauth/token", h.ccForm(m, h.assertion(m, asrt{}), ccOpts{}), map[string]string{"DPoP": "garbage"})
	if r.Status != 400 || r.str("error") != "invalid_dpop_proof" {
		t.Errorf("garbage proof: %d %s", r.Status, r.Raw)
	}
	if n := len(h.auditEvents(slugA, "oauth.token.issued")); n != 0 {
		t.Errorf("%d tokens issued without a valid proof", n)
	}
	// the refused requests did not consume the assertion's jti: DPoP is checked first
	a := h.assertion(m, asrt{})
	h.ccReq(m, a, ccOpts{})
	if r := h.ccReq(m, a, ccOpts{dpopKey: k}); r.Status != 200 {
		t.Errorf("the assertion was consumed by a request without a proof: %d %s", r.Status, r.Raw)
	}

	t.Run("not required", func(t *testing.T) {
		m := h.addMachine(machineOpts{noDPoP: true})
		r := h.ccReq(m, h.assertion(m, asrt{}), ccOpts{})
		tok := tokensOf(t, r)
		if r.str("token_type") != "Bearer" {
			t.Errorf("token_type = %q", r.str("token_type"))
		}
		_, c := decodeJWT(t, tok.Access)
		if _, ok := c["cnf"]; ok {
			t.Error("an unbound token must not carry cnf")
		}
		// accepted as Bearer, never as DPoP
		w := h.whoamiWith(tok.Access, "Bearer", nil)
		if w.Status != 200 || w.str("via") != auth.ViaBearer || w.str("kind") != auth.KindAPIClient {
			t.Errorf("Bearer: %d %s", w.Status, w.Raw)
		}
		if w := h.whoamiReq(k, tok.Access); w.Status != 401 {
			t.Errorf("an unbound token under DPoP: %d %s", w.Status, w.Raw)
		}
		// a proof, when sent, binds the token, which then needs the proof
		bound := tokensOf(t, h.ccReq(m, h.assertion(m, asrt{}), ccOpts{dpopKey: k}))
		if w := h.whoamiWith(bound.Access, "Bearer", nil); w.Status != 401 {
			t.Errorf("a bound token under Bearer: %d %s", w.Status, w.Raw)
		}
		if w := h.whoamiReq(k, bound.Access); w.Status != 200 || w.str("via") != auth.ViaDPoP {
			t.Errorf("a bound token with its proof: %d %s", w.Status, w.Raw)
		}
	})
}

// TestClientCredentials_Scope: the scope is a subset of what is registered,
// all of it when none is asked.
func TestClientCredentials_Scope(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{scopes: []string{"tessera:read", "tessera:write"}})
	k := newKey(t)
	for _, tc := range []struct{ ask, want string }{
		{"", "tessera:read tessera:write"},
		{"tessera:write", "tessera:write"},
		{"tessera:write tessera:read tessera:write", "tessera:write tessera:read"},
	} {
		if got := h.machineToken(m, tc.ask, k).Scope; got != tc.want {
			t.Errorf("scope %q: got %q, want %q", tc.ask, got, tc.want)
		}
	}
	for _, ask := range []string{"tessera:admin", "tessera:read tessera:audit", "tessera:introspect", "nonsense"} {
		r := h.ccReq(m, h.assertion(m, asrt{}), ccOpts{scope: ask, dpopKey: k})
		if r.Status != 400 || r.str("error") != "invalid_scope" {
			t.Errorf("scope %q: %d %s", ask, r.Status, r.Raw)
		}
	}
	if evs := h.auditEvents(slugA, "oauth.token.refused"); len(evs) != 4 || evs[0].Outcome != store.OutcomeDenied {
		t.Errorf("refusal events: %d", len(evs))
	}
}

// TestClientCredentials_GrantChecks: a machine client cannot use the CLI's
// grants, the CLI client cannot use client credentials, a disabled or unknown
// client gets nothing, and one tenant's client does not exist in another.
func TestClientCredentials_GrantChecks(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	k := newKey(t)
	cli := &machine{slug: slugA, clientID: CLIClientID, key: newKey(t), alg: "ES256", kid: "k1"}
	r := h.ccReq(cli, h.assertion(cli, asrt{}), ccOpts{dpopKey: k})
	if r.Status != 400 || r.str("error") != "unauthorized_client" {
		t.Errorf("the CLI client: %d %s", r.Status, r.Raw)
	}
	r = h.tokenReq(slugA, url.Values{"grant_type": {GrantRefresh}, "client_id": {m.clientID}, "refresh_token": {"trt_x"}}, k)
	if r.Status != 400 || r.str("error") != "unauthorized_client" {
		t.Errorf("a machine client with the refresh grant: %d %s", r.Status, r.Raw)
	}
	dis := h.addMachine(machineOpts{disabled: true})
	if r := h.ccReq(dis, h.assertion(dis, asrt{}), ccOpts{dpopKey: k}); r.Status != 401 || r.str("error") != "invalid_client" {
		t.Errorf("a disabled client: %d %s", r.Status, r.Raw)
	}
	ghost := &machine{slug: slugA, clientID: "tsc_ghost", key: newKey(t), alg: "ES256", kid: "k1"}
	if r := h.ccReq(ghost, h.assertion(ghost, asrt{}), ccOpts{dpopKey: k}); r.Status != 401 || r.str("error") != "invalid_client" {
		t.Errorf("an unknown client: %d %s", r.Status, r.Raw)
	}
	// tenant A's client with tenant B's endpoint: unknown there
	cross := &machine{slug: slugB, clientID: m.clientID, key: m.key, alg: m.alg, kid: m.kid}
	if r := h.ccReq(cross, h.assertion(cross, asrt{}), ccOpts{dpopKey: k}); r.Status != 401 || r.str("error") != "invalid_client" {
		t.Errorf("tenant A's client at tenant B: %d %s", r.Status, r.Raw)
	}
	if n := len(h.auditEvents(slugB, "oauth.token.issued")) + len(h.auditEvents(slugA, "oauth.token.issued")); n != 0 {
		t.Errorf("%d tokens issued", n)
	}
}

// TestMachineTokenVerification: the §10.4 rules that are specific to a
// machine token, with a token signed by the tenant's real key.
func TestMachineTokenVerification(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	disabled := h.addMachine(machineOpts{disabled: true})
	k := newKey(t)
	real := h.machineToken(m, "", k)
	userTok, _ := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, newKey(t))
	cases := []struct {
		name   string
		claims func(map[string]any)
		ok     bool
	}{
		{name: "valid", ok: true},
		{name: "another client's sub", claims: set("sub", MachineSubjectPrefix+uuid.NewString())},
		{name: "a user subject and no session", claims: set("sub", SubjectPrefix+uuid.NewString())},
		{name: "a session and a machine subject", claims: set("sid", uuid.NewString())},
		{name: "a disabled client", claims: set("client_id", disabled.clientID)},
		{name: "the CLI client without a session", claims: set("client_id", CLIClientID)},
		{name: "an unknown client", claims: set("client_id", "tsc_ghost")},
		{name: "an empty cnf", claims: set("cnf", map[string]string{"jkt": ""})},
		{name: "no scope", claims: set("scope", " ")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := h.forge(real, forged{claims: tc.claims})
			w := h.whoamiReq(k, tok)
			if tc.ok != (w.Status == 200) {
				t.Errorf("%d %s", w.Status, w.Raw)
			}
		})
	}
	// a user's token is never accepted without a session, whatever the client says
	noSession := h.forge(userTok, forged{claims: del("sid")})
	if w := h.whoamiReq(newKey(t), noSession); w.Status != 401 {
		t.Errorf("user token without sid: %d %s", w.Status, w.Raw)
	}
	// a machine token is never accepted as a user's: a session id with it is refused above, and
	// a user's token cannot be turned into a machine token without the tenant's key
	if w := h.whoamiReq(k, h.forge(real, forged{signer: slugB})); w.Status != 401 {
		t.Errorf("signed with tenant B's key: %d %s", w.Status, w.Raw)
	}
	// a bound token needs the proof of its key
	if w := h.whoamiReq(newKey(t), real.Access); w.Status != 401 {
		t.Errorf("another key's proof: %d %s", w.Status, w.Raw)
	}
}

// TestMachineRolesIntersectScope: effective = perms(roles) ∩ perms(scope)
// (§12.3), and a machine client never has an admin role, whatever its row says.
func TestMachineRolesIntersectScope(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	tests := []struct {
		name   string
		roles  []string
		scopes []string
		ask    string
		want   []string // permissions besides auth.self
		active []string
	}{
		{"operator with read: only what both give", []string{"operator"}, []string{"tessera:read"}, "",
			[]string{"graph.read"}, []string{"operator"}},
		{"viewer with write: the scope covers what the role lacks", []string{"viewer"}, []string{"tessera:write"}, "",
			nil, []string{"viewer"}},
		{"operator with write only: the role's read is outside the scope", []string{"operator"}, []string{"tessera:write"}, "",
			[]string{"jit.request", "jit.decide", "jit.deny_revoke", "reviews.manage", "reviews.decide", "hris.simulate_event"}, []string{"operator"}},
		{"auditor with every scope", []string{"auditor"}, []string{"tessera:read", "tessera:audit", "tessera:admin", "tessera:write"}, "",
			[]string{"graph.read", "audit.read", "audit.verify", "admin.read", "connections.read"}, []string{"auditor"}},
		{"auditor asking for less than registered", []string{"auditor"}, []string{"tessera:read", "tessera:audit", "tessera:admin"}, "tessera:audit",
			[]string{"audit.read", "audit.verify"}, []string{"auditor"}},
		{"no role", nil, []string{"tessera:read", "tessera:write", "tessera:admin"}, "", nil, nil},
		{"an admin role in the row is inactive", []string{"tenant_admin", "policy_admin", "break_glass"}, []string{"tessera:read", "tessera:write", "tessera:admin"}, "",
			nil, nil},
		{"an admin role next to a viewer", []string{"tenant_admin", "viewer"}, []string{"tessera:read", "tessera:admin"}, "",
			[]string{"graph.read"}, []string{"viewer"}},
		{"an unknown role", []string{"root", "viewer"}, []string{"tessera:read"}, "", []string{"graph.read"}, []string{"viewer"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roles := tc.roles
			if roles == nil {
				roles = []string{}
			}
			m := h.addMachine(machineOpts{roles: roles, scopes: tc.scopes})
			tok := h.machineToken(m, tc.ask, k)
			got := h.perms(k, tok.Access)
			want := append([]string{string(auth.PermAuthenticated)}, tc.want...)
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("permissions %v, want %v", got, want)
			}
			w := h.whoamiReq(k, tok.Access)
			var active []string
			for _, r := range w.Body["active_roles"].([]any) {
				active = append(active, r.(string))
			}
			if !slices.Equal(active, tc.active) {
				t.Errorf("active roles %v, want %v", active, tc.active)
			}
		})
	}
}

// TestMachineStepUpRefused: a machine principal can never satisfy step-up
// (§9.5): every route that requires it is 403
// interactive_authentication_required, even when its roles and scopes would
// allow the action, and never the 401 step_up_required challenge a user gets.
func TestMachineStepUpRefused(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	m := h.addMachine(machineOpts{roles: []string{"operator", "auditor"},
		scopes: []string{"tessera:read", "tessera:write", "tessera:audit", "tessera:admin"}})
	tok := h.machineToken(m, "", k)
	req, err := http.NewRequest(http.MethodGet, h.url("/api/whoami"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "DPoP "+tok.Access)
	req.Header.Set("DPoP", h.proof(k, "GET", h.srv.URL+"/api/whoami", tok.Access, ""))
	p, f, err := h.authn.AuthenticateRequest(req)
	if err != nil || p == nil {
		t.Fatalf("authenticate: %v %+v", err, f)
	}
	now := h.clock.Now()
	for _, tc := range []struct {
		name string
		perm auth.Permission
		req  auth.AuthnRequirement
	}{
		{"jit approve (policy step-up)", auth.PermJITDecide, auth.StepUpPolicy},
		{"review decision", auth.PermReviewsDecide, auth.StepUpPolicy},
		{"deny or revoke a request", auth.PermJITDenyRevoke, auth.StepUpPolicy},
		{"an admin step-up on a permission it has", auth.PermAdminRead, auth.StepUpAdmin},
		{"device approval (auth.self, admin step-up)", auth.PermAuthenticated, auth.StepUpAdmin},
		{"a weak requirement", auth.PermGraphRead, auth.AuthnRequirement{ACR: auth.ACRAAL1}},
	} {
		d := auth.Check(p, tc.perm, &tc.req, now)
		if d == nil || d.Status != http.StatusForbidden || d.Error != "interactive_authentication_required" || d.Requirement != nil {
			t.Errorf("%s: %+v", tc.name, d)
		}
	}
	// without a step-up requirement, the same permission is allowed
	if d := auth.Check(p, auth.PermJITDecide, nil, now); d != nil {
		t.Errorf("jit.decide without step-up: %+v", d)
	}
	// and a permission it lacks is plain forbidden, not a step-up error
	if d := auth.Check(p, auth.PermGrantsRevoke, &auth.StepUpPolicy, now); d == nil || d.Error != "forbidden" {
		t.Errorf("grants.revoke: %+v", d)
	}
}

// TestMachineTokenLifetime: access tokens live 600 s, and 300 s with the admin scope.
func TestMachineTokenLifetime(t *testing.T) {
	h := newHarness(t)
	m := h.addMachine(machineOpts{})
	k := newKey(t)
	tok := h.machineToken(m, "", k)
	if w := h.whoamiReq(k, tok.Access); w.Status != 200 {
		t.Fatalf("fresh: %d %s", w.Status, w.Raw)
	}
	h.clock.Advance(11 * time.Minute) // access tokens live 600 s, with a 30 s leeway
	if w := h.whoamiReq(k, tok.Access); w.Status != 401 {
		t.Errorf("expired: %d %s", w.Status, w.Raw)
	}
	// an admin-scoped token is short-lived (300 s)
	m2 := h.addMachine(machineOpts{roles: []string{"auditor"}, scopes: []string{"tessera:admin", "tessera:read"}})
	if got := h.machineToken(m2, "tessera:admin", k).ExpiresIn; got != 300 {
		t.Errorf("admin token expires_in = %d, want 300", got)
	}
}

// ---------------------------------------------------------------- introspection

// TestIntrospect: RFC 7662 for a machine client with the tessera:introspect scope.
func TestIntrospect(t *testing.T) {
	h := newHarness(t)
	gw := h.addMachine(machineOpts{scopes: []string{ScopeIntrospect}})
	m := h.addMachine(machineOpts{scopes: []string{"tessera:read", "tessera:write"}})
	k := newKey(t)
	machineTok := h.machineToken(m, "tessera:read", k)
	userK := newKey(t)
	userTok, login := h.signInCLI(slugA, "alice@a.example", viewer, authtest.Phr, userK)

	t.Run("a machine token", func(t *testing.T) {
		r := h.introspect(gw, machineTok.Access)
		_, c := decodeJWT(t, machineTok.Access)
		if r.Status != 200 || r.Body["active"] != true || r.str("scope") != "tessera:read" || r.str("client_id") != m.clientID ||
			r.str("sub") != MachineSubjectPrefix+m.rowID.String() || r.str("token_type") != "DPoP" || r.str("iss") != h.srv.URL+"/t/"+slugA ||
			r.str("aud") != h.srv.URL+"/api" || r.str("jti") != c["jti"] {
			t.Fatalf("%d %s", r.Status, r.Raw)
		}
		if cnf, _ := r.Body["cnf"].(map[string]any); cnf["jkt"] != jktOf(t, k) {
			t.Errorf("cnf = %v", r.Body["cnf"])
		}
		if e, _ := r.Body["exp"].(float64); int64(e) != int64(c["exp"].(float64)) {
			t.Errorf("exp = %v", r.Body["exp"])
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control = %q", r.Header.Get("Cache-Control"))
		}
	})
	t.Run("a user's token, until its session ends", func(t *testing.T) {
		r := h.introspect(gw, userTok.Access)
		if r.Status != 200 || r.Body["active"] != true || r.str("client_id") != CLIClientID || !strings.HasPrefix(r.str("sub"), SubjectPrefix) {
			t.Fatalf("%d %s", r.Status, r.Raw)
		}
		// revoking the refresh token ends the session, and with it the access token
		rev := h.postForm("/t/"+slugA+"/oauth/revoke", url.Values{"token": {userTok.Refresh}, "client_id": {CLIClientID}}, nil)
		if rev.Status != 200 {
			t.Fatalf("revoke: %d %s", rev.Status, rev.Raw)
		}
		if r := h.introspect(gw, userTok.Access); r.Status != 200 || r.Body["active"] != false || len(r.Body) != 1 {
			t.Errorf("after the session ended: %d %s", r.Status, r.Raw)
		}
		_ = login
	})
	t.Run("inactive answers say nothing else", func(t *testing.T) {
		tampered := machineTok.Access[:len(machineTok.Access)-4] + "AAAA"
		forgedOther := h.forge(machineTok, forged{signer: slugB})
		for name, token := range map[string]string{"garbage": "not a token", "tampered": tampered, "foreign key": forgedOther,
			"a refresh token": userTok.Refresh, "an oversized token": strings.Repeat("a", MaxTokenBytes)} {
			r := h.introspect(gw, token)
			if r.Status != 200 || r.Body["active"] != false || len(r.Body) != 1 {
				t.Errorf("%s: %d %s", name, r.Status, r.Raw)
			}
		}
		h.clock.Advance(11 * time.Minute)
		if r := h.introspect(gw, machineTok.Access); r.Status != 200 || r.Body["active"] != false {
			t.Errorf("expired: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("another tenant's token is inactive", func(t *testing.T) {
		mb := h.addMachine(machineOpts{slug: slugB})
		tokB := h.machineToken(mb, "", newKey(t))
		if r := h.introspect(gw, tokB.Access); r.Status != 200 || r.Body["active"] != false {
			t.Errorf("tenant B's token asked of tenant A: %d %s", r.Status, r.Raw)
		}
		gwB := h.addMachine(machineOpts{slug: slugB, scopes: []string{ScopeIntrospect}})
		if r := h.introspect(gwB, tokB.Access); r.Status != 200 || r.Body["active"] != true {
			t.Errorf("tenant B's token asked of tenant B: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("a client without the scope", func(t *testing.T) {
		r := h.introspect(m, machineTok.Access)
		if r.Status != 403 || r.str("error") != "insufficient_scope" || r.str("active") != "" {
			t.Errorf("%d %s", r.Status, r.Raw)
		}
		if evs := h.auditEvents(slugA, "oauth.token.introspected"); len(evs) == 0 ||
			evs[len(evs)-1].Outcome != store.OutcomeDenied {
			t.Errorf("events: %+v", evs)
		}
	})
	t.Run("client authentication", func(t *testing.T) {
		before := len(h.failedAuthEvents(slugA))
		a := h.assertion(gw, asrt{aud: h.introspectURL(slugA)})
		if r := h.introspectReq(gw, a, machineTok.Access, nil); r.Status != 200 {
			t.Fatalf("control: %d %s", r.Status, r.Raw)
		}
		bad := map[string]string{
			"replayed":                 a,
			"the token endpoint's aud": h.assertion(gw, asrt{}),
			"unregistered key":         h.assertion(&machine{slug: slugA, clientID: gw.clientID, key: newKey(t), alg: "ES256", kid: gw.kid}, asrt{aud: h.introspectURL(slugA)}),
			"HS256": h.assertion(gw, asrt{aud: h.introspectURL(slugA), header: set("alg", "HS256"), sign: func(in string) string {
				mac := hmac.New(sha256.New, []byte("a shared secret of at least 32 bytes!!"))
				mac.Write([]byte(in))
				return b64u(mac.Sum(nil))
			}}),
			"exp too far": h.assertion(gw, asrt{aud: h.introspectURL(slugA), claims: func(c map[string]any) { c["exp"] = h.clock.Now().Add(time.Hour).Unix() }}),
		}
		for name, assertion := range bad {
			if r := h.introspectReq(gw, assertion, machineTok.Access, nil); r.Status != 401 || r.str("error") != "invalid_client" || r.str("active") != "" {
				t.Errorf("%s: %d %s", name, r.Status, r.Raw)
			}
		}
		if got := len(h.failedAuthEvents(slugA)) - before; got != len(bad) {
			t.Errorf("%d failed-authentication events, want %d", got, len(bad))
		}
		// a client without a registered key set, and an unknown one
		ghost := &machine{slug: slugA, clientID: "tsc_ghost", key: newKey(t), alg: "ES256", kid: "k1"}
		if r := h.introspectReq(ghost, h.assertion(ghost, asrt{aud: h.introspectURL(slugA)}), machineTok.Access, nil); r.Status != 401 {
			t.Errorf("unknown client: %d %s", r.Status, r.Raw)
		}
		// the CLI client has no key and cannot introspect
		cli := &machine{slug: slugA, clientID: CLIClientID, key: newKey(t), alg: "ES256", kid: "k1"}
		if r := h.introspectReq(cli, h.assertion(cli, asrt{aud: h.introspectURL(slugA)}), machineTok.Access, nil); r.Status != 401 {
			t.Errorf("CLI client: %d %s", r.Status, r.Raw)
		}
		// tenant B's endpoint does not know tenant A's client
		cross := &machine{slug: slugB, clientID: gw.clientID, key: gw.key, alg: gw.alg, kid: gw.kid}
		if r := h.introspectReq(cross, h.assertion(cross, asrt{aud: h.introspectURL(slugB)}), machineTok.Access, nil); r.Status != 401 {
			t.Errorf("cross tenant: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		a := h.assertion(gw, asrt{aud: h.introspectURL(slugA)})
		if r := h.introspectReq(gw, a, "", nil); r.Status != 400 || r.str("error") != "invalid_request" {
			t.Errorf("no token: %d %s", r.Status, r.Raw)
		}
		a = h.assertion(gw, asrt{aud: h.introspectURL(slugA)})
		if r := h.introspectReq(gw, a, "x", url.Values{"token": {"x", "y"}}); r.Status != 400 {
			t.Errorf("two tokens: %d %s", r.Status, r.Raw)
		}
		req, _ := http.NewRequest(http.MethodGet, h.url("/t/"+slugA+"/oauth/introspect"), nil)
		if r := do(t, req); r.Status == 200 {
			t.Errorf("GET: %d %s", r.Status, r.Raw)
		}
		if r := h.postForm("/t/nobody/oauth/introspect", url.Values{"token": {"x"}}, nil); r.Status != 404 {
			t.Errorf("unknown tenant: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("audit", func(t *testing.T) {
		evs := h.auditEvents(slugA, "oauth.token.introspected")
		if len(evs) == 0 {
			t.Fatal("no oauth.token.introspected events")
		}
		for _, e := range evs {
			d := string(e.Detail)
			if strings.Contains(d, machineTok.Access) || strings.Contains(d, userTok.Access) {
				t.Errorf("a token is in the audit log: %s", d)
			}
		}
		if e := evs[0]; e.ActorType != store.ActorAPIClient || e.ActorID == nil || *e.ActorID != gw.clientID {
			t.Errorf("actor %s %v", e.ActorType, e.ActorID)
		}
	})
}

// ---------------------------------------------------------------- parsing

// TestParseClientJWKS: only public EC P-256 and Ed25519 keys with unique kids
// can be registered.
func TestParseClientJWKS(t *testing.T) {
	ec, ed := &machine{key: newKey(t), alg: "ES256", kid: "ec"}, &machine{alg: "EdDSA", kid: "ed"}
	ed.key, _ = newMachineKey(t, true)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := func(ks ...jose.JSONWebKey) []byte { return mustJSON(t, jose.JSONWebKeySet{Keys: ks}) }
	pub := func(m *machine) jose.JSONWebKey { return m.publicJWK() }
	priv := jose.JSONWebKey{Key: ec.key, KeyID: "p", Algorithm: "ES256"}
	noKid := pub(ec)
	noKid.KeyID = ""
	dup := pub(ed)
	dup.KeyID = "ec"
	wrongAlg := pub(ec)
	wrongAlg.Algorithm = "EdDSA"
	enc := pub(ec)
	enc.Use = "enc"
	var many []jose.JSONWebKey
	for i := 0; i < MaxClientKeys+1; i++ {
		k := pub(ec)
		k.KeyID = strings.Repeat("k", i+1)
		many = append(many, k)
	}
	tests := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"one ES256 key", jwks(pub(ec)), true},
		{"ES256 and EdDSA keys", jwks(pub(ec), pub(ed)), true},
		{"a private key", jwks(priv), false},
		{"an RSA key", jwks(jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "r"}), false},
		{"no kid", jwks(noKid), false},
		{"a repeated kid", jwks(pub(ec), dup), false},
		{"an alg that does not fit the key", jwks(wrongAlg), false},
		{"an encryption key", jwks(enc), false},
		{"too many keys", jwks(many...), false},
		{"no keys", []byte(`{"keys":[]}`), false},
		{"not JSON", []byte(`nope`), false},
		{"empty", nil, false},
		{"a symmetric key", []byte(`{"keys":[{"kty":"oct","k":"AAAA","kid":"s"}]}`), false},
		{"oversized", []byte(`{"keys":[],"x":"` + strings.Repeat("a", maxJWKSBytes) + `"}`), false},
	}
	for _, tc := range tests {
		_, out, err := ParseClientJWKS(tc.raw)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if tc.ok && strings.Contains(string(out), `"d"`) {
			t.Errorf("%s: a private member survived: %s", tc.name, out)
		}
	}
}

// FuzzParseClientAssertion: untrusted input never panics the parser, the
// verifier or the claim checks, and nothing but a signature made by a
// registered key and claims that satisfy every rule is accepted.
func FuzzParseClientAssertion(f *testing.F) {
	ecKey, edKey := newKey(f), func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }()
	ec := &machine{key: ecKey, alg: "ES256", kid: "ec", clientID: "tsc_fuzz"}
	ed := &machine{key: edKey, alg: "EdDSA", kid: "ed", clientID: "tsc_fuzz"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{ec.publicJWK(), ed.publicJWK()}}
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	const aud = "https://tessera.test/t/tenant-a/oauth/token"
	build := func(m *machine, hdr, claims map[string]any) string {
		in := b64u(mustJSON(f, hdr)) + "." + b64u(mustJSON(f, claims))
		return in + "." + signInput(m, in)
	}
	claims := map[string]any{"iss": "tsc_fuzz", "sub": "tsc_fuzz", "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "j"}
	f.Add(build(ec, map[string]any{"alg": "ES256", "kid": "ec"}, claims))
	f.Add(build(ed, map[string]any{"alg": "EdDSA", "kid": "ed"}, claims))
	f.Add(build(ec, map[string]any{"alg": "ES256"}, claims))
	f.Add(build(ec, map[string]any{"alg": "HS256", "kid": "ec"}, claims))
	f.Add(build(ec, map[string]any{"alg": "ES256", "kid": "ec", "jwk": map[string]any{"kty": "EC"}}, claims))
	f.Add(build(ec, map[string]any{"alg": "ES256", "kid": "ec"}, map[string]any{"exp": 1e300, "iat": -1}))
	f.Add("e30.e30.")
	f.Add("..")
	f.Add("a.b.c")
	f.Add(strings.Repeat("a", MaxAssertionBytes+10))
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseClientAssertion(s)
		if err != nil {
			var ae *AssertionError
			if !errors.As(err, &ae) {
				t.Fatalf("a parse error that is not an AssertionError: %v", err)
			}
			return
		}
		if a.Alg != "ES256" && a.Alg != "EdDSA" {
			t.Fatalf("accepted algorithm %q", a.Alg)
		}
		_ = a.UnverifiedIssuer()
		c, err := a.Verify(set)
		if err != nil {
			return
		}
		if err := c.Check("tsc_fuzz", aud, now); err != nil {
			return
		}
		// accepted: every rule held
		if c.Issuer != "tsc_fuzz" || c.Subject != "tsc_fuzz" || c.Audience != aud || c.JTI == "" || len(c.JTI) > MaxJTIBytes ||
			!now.Before(c.Expiry) || c.Expiry.Sub(c.IssuedAt) > MaxAssertionLifetime || c.IssuedAt.After(now.Add(assertionSkew)) {
			t.Fatalf("accepted claims that break a rule: %+v", c)
		}
	})
}
