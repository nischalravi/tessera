package devidp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
)

const redirectURI = "http://127.0.0.1:5999/callback"

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// browser is a cookie-keeping client that does not follow redirects.
type browser struct {
	t   *testing.T
	idp *devidptest.IdP
	c   *http.Client
}

func newBrowser(t *testing.T, idp *devidptest.IdP) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, idp: idp, c: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func start(t *testing.T, cfg devidp.Config) (*devidptest.IdP, *browser) {
	t.Helper()
	idp := devidptest.Start(t, cfg)
	return idp, newBrowser(t, idp)
}

// request is one authorization request and the PKCE verifier behind it.
type request struct {
	params   url.Values
	verifier string
}

func newRequest(extra map[string]string) request {
	verifier := strings.Repeat("v", 20) + rand.Text() // 46 unreserved characters
	sum := sha256.Sum256([]byte(verifier))
	p := url.Values{
		"client_id":             {devidptest.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {"st-" + rand.Text()},
		"nonce":                 {"n-" + rand.Text()},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		if v == "<omit>" {
			p.Del(k)
		} else {
			p.Set(k, v)
		}
	}
	return request{params: p, verifier: verifier}
}

func (b *browser) get(u string) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.c.Get(u)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

var reqRE = regexp.MustCompile(`name="req" value="([^"]+)"`)

// authorize starts an authorization request. It returns the callback
// parameters when the IdP redirected straight back (SSO or an error), or the
// sign-in page's request id.
func (b *browser) authorize(r request) (callback url.Values, pageReq string) {
	b.t.Helper()
	resp, body := b.get(b.idp.URL + "/authorize?" + r.params.Encode())
	switch resp.StatusCode {
	case http.StatusFound:
		return b.callback(resp), ""
	case http.StatusOK:
		m := reqRE.FindStringSubmatch(body)
		if m == nil {
			b.t.Fatalf("sign-in page without a request id:\n%s", body)
		}
		return nil, m[1]
	}
	b.t.Fatalf("authorize: status %d: %s", resp.StatusCode, body)
	return nil, ""
}

func (b *browser) callback(resp *http.Response) url.Values {
	b.t.Helper()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != redirectURI {
		b.t.Fatalf("redirected to %s, want %s", got, redirectURI)
	}
	v, err := url.ParseQuery(loc.RawQuery)
	if err != nil {
		b.t.Fatal(err)
	}
	return v
}

// signIn submits the sign-in page.
func (b *browser) signIn(pageReq, sub string, m devidp.Method, p devidp.Profile) url.Values {
	b.t.Helper()
	resp, err := b.c.PostForm(b.idp.URL+"/authorize", url.Values{
		"req": {pageReq}, "choice": {sub + " " + string(m)}, "profile": {string(p)}})
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		b.t.Fatalf("sign-in: status %d: %s", resp.StatusCode, body)
	}
	return b.callback(resp)
}

// login runs authorize + the sign-in page and returns the callback.
func (b *browser) login(r request, sub string, m devidp.Method, p devidp.Profile) url.Values {
	b.t.Helper()
	cb, pageReq := b.authorize(r)
	if cb != nil {
		b.t.Fatalf("expected the sign-in page, got a redirect: %v", cb)
	}
	return b.signIn(pageReq, sub, m, p)
}

type tokens struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

func (b *browser) exchange(form url.Values, basic bool) (int, tokens) {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.idp.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(devidptest.ClientID, devidptest.ClientSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var tk tokens
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil {
		b.t.Fatal(err)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		b.t.Errorf("token response Cache-Control = %q, want no-store", cc)
	}
	return resp.StatusCode, tk
}

func codeForm(code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
}

// redeem exchanges the callback's code and returns the ID token.
func (b *browser) redeem(cb url.Values, r request) string {
	b.t.Helper()
	if e := cb.Get("error"); e != "" {
		b.t.Fatalf("authorization error %s: %s", e, cb.Get("error_description"))
	}
	status, tk := b.exchange(codeForm(cb.Get("code"), r.verifier), true)
	if status != http.StatusOK || tk.IDToken == "" {
		b.t.Fatalf("token: status %d, error %q", status, tk.Error)
	}
	return tk.IDToken
}

func fetchJWKS(t *testing.T, idp *devidptest.IdP) jose.JSONWebKeySet {
	t.Helper()
	resp, err := http.Get(idp.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set
}

// unverifiedClaims decodes the payload without checking anything.
func unverifiedClaims(t *testing.T, tok string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", tok)
	}
	dec := func(s string, into *map[string]any) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatal(err)
		}
	}
	dec(parts[0], &header)
	dec(parts[1], &claims)
	return header, claims
}

// validate checks an ID token the way a relying party must (§10.4) with
// go-jose against the JWKS, and returns its claims.
func validate(t *testing.T, idp *devidptest.IdP, tok, nonce string) map[string]any {
	t.Helper()
	set := fetchJWKS(t, idp)
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	keys := set.Key(parsed.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q not in the JWKS", parsed.Headers[0].KeyID)
	}
	var std jwt.Claims
	var all map[string]any
	if err := parsed.Claims(keys[0], &std, &all); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{Issuer: idp.URL, AnyAudience: jwt.Audience{devidptest.ClientID}, Time: time.Now()}, 0); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if all["nonce"] != nonce {
		t.Fatalf("nonce %v, want %s", all["nonce"], nonce)
	}
	if _, ok := all["auth_time"].(float64); !ok {
		t.Fatal("auth_time missing")
	}
	return all
}

func TestDiscoveryDocumentShape(t *testing.T) {
	idp, _ := start(t, devidp.Config{})
	resp, err := http.Get(idp.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	str := func(k string) any { return d[k] }
	list := func(k string) []string {
		raw, _ := d[k].([]any)
		out := make([]string, len(raw))
		for i, v := range raw {
			out[i], _ = v.(string)
		}
		return out
	}
	for k, want := range map[string]string{
		"issuer":                 idp.URL,
		"authorization_endpoint": idp.URL + "/authorize",
		"token_endpoint":         idp.URL + "/token",
		"jwks_uri":               idp.URL + "/jwks",
		"userinfo_endpoint":      idp.URL + "/userinfo",
		"end_session_endpoint":   idp.URL + "/logout",
	} {
		if str(k) != want {
			t.Errorf("%s = %v, want %s", k, str(k), want)
		}
	}
	for k, want := range map[string][]string{
		"response_types_supported":              {"code"},
		"response_modes_supported":              {"query"},
		"grant_types_supported":                 {"authorization_code"},
		"code_challenge_methods_supported":      {"S256"},
		"id_token_signing_alg_values_supported": {"RS256"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "private_key_jwt"},
		"prompt_values_supported":               {"none", "login"},
	} {
		if got := list(k); !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	for _, k := range []string{"authorization_response_iss_parameter_supported", "claims_parameter_supported"} {
		if d[k] != true {
			t.Errorf("%s = %v, want true", k, d[k])
		}
	}
	for _, k := range []string{"request_parameter_supported", "request_uri_parameter_supported"} {
		if d[k] != false {
			t.Errorf("%s = %v, want false", k, d[k])
		}
	}
	for _, v := range []string{"phr", "phrh", devidp.OktaACR2FA} {
		if !slices.Contains(list("acr_values_supported"), v) {
			t.Errorf("acr_values_supported lacks %q", v)
		}
	}
	for _, v := range []string{"auth_time", "acr", "amr", "nonce", "sid"} {
		if !slices.Contains(list("claims_supported"), v) {
			t.Errorf("claims_supported lacks %q", v)
		}
	}

	set := fetchJWKS(t, idp)
	if len(set.Keys) != 1 {
		t.Fatalf("%d keys in the JWKS, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	if k.KeyID != idp.KeyID() || k.Algorithm != "RS256" || k.Use != "sig" || !k.IsPublic() {
		t.Errorf("JWKS key kid=%q alg=%q use=%q public=%v", k.KeyID, k.Algorithm, k.Use, k.IsPublic())
	}
}

func TestIDTokenValidatesAgainstJWKS(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	r := newRequest(nil)
	cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	if cb.Get("state") != r.params.Get("state") || cb.Get("iss") != idp.URL {
		t.Fatalf("callback state/iss = %q/%q", cb.Get("state"), cb.Get("iss"))
	}
	tok := b.redeem(cb, r)
	c := validate(t, idp, tok, r.params.Get("nonce"))
	if c["sub"] != "00u-alice-admin" || c["email"] != "alice.admin@larkspur.example" || c["sid"] == "" {
		t.Errorf("claims %v", c)
	}
	if got := fmt.Sprint(c["roles"]); got != "[tenant_admin]" {
		t.Errorf("roles = %s", got)
	}
	// HS256 and none are never accepted by the allow-list.
	if _, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.HS256}); err == nil {
		t.Error("an RS256 token parsed under an HS256-only allow-list")
	}
}

func TestPKCEEnforced(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	_ = idp
	for _, tc := range []struct {
		name  string
		extra map[string]string
	}{
		{"no challenge", map[string]string{"code_challenge": "<omit>"}},
		{"no method", map[string]string{"code_challenge_method": "<omit>"}},
		{"plain method", map[string]string{"code_challenge_method": "plain"}},
		{"short challenge", map[string]string{"code_challenge": "abc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cb, _ := b.authorize(newRequest(tc.extra))
			if cb.Get("error") != "invalid_request" || !strings.Contains(cb.Get("error_description"), "PKCE") || cb.Get("code") != "" {
				t.Fatalf("callback %v, want a PKCE invalid_request", cb)
			}
		})
	}

	r := newRequest(nil)
	cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	code := cb.Get("code")
	challenge := r.params.Get("code_challenge")
	for _, tc := range []struct {
		name     string
		verifier string
	}{
		{"missing verifier", ""},
		{"wrong verifier", strings.Repeat("x", 50)},
		{"challenge as verifier (plain downgrade)", challenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A failed redemption burns the code: use a fresh one per case,
			// and check the right verifier cannot redeem it afterwards.
			r2 := newRequest(nil)
			cb2, _ := b.authorize(r2) // SSO now: redirected with a code
			status, tk := b.exchange(codeForm(cb2.Get("code"), tc.verifier), true)
			if status != http.StatusBadRequest || tk.Error != "invalid_grant" || tk.IDToken != "" {
				t.Fatalf("status %d error %q", status, tk.Error)
			}
			if status, _ := b.exchange(codeForm(cb2.Get("code"), r2.verifier), true); status != http.StatusBadRequest {
				t.Fatalf("code redeemed after a failed attempt: status %d", status)
			}
		})
	}
	if status, tk := b.exchange(codeForm(code, r.verifier), true); status != http.StatusOK || tk.IDToken == "" {
		t.Fatalf("correct verifier: status %d error %q", status, tk.Error)
	}
	if status, tk := b.exchange(codeForm(code, r.verifier), true); status != http.StatusBadRequest || tk.Error != "invalid_grant" {
		t.Fatalf("code replay: status %d error %q", status, tk.Error)
	}
}

func TestTokenEndpointRejects(t *testing.T) {
	_, b := start(t, devidp.Config{})
	b.login(newRequest(nil), "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
		basic  bool
		status int
		err    string
	}{
		{"no client auth", func(url.Values) {}, false, 401, "invalid_client"},
		{"client_secret_post", func(f url.Values) {
			f.Set("client_id", devidptest.ClientID)
			f.Set("client_secret", devidptest.ClientSecret)
		}, false, 400, "invalid_request"},
		{"other client_id", func(f url.Values) { f.Set("client_id", "someone-else") }, true, 401, "invalid_client"},
		{"wrong redirect_uri", func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:5999/other") }, true, 400, "invalid_grant"},
		{"wrong grant_type", func(f url.Values) { f.Set("grant_type", "refresh_token") }, true, 400, "unsupported_grant_type"},
		{"unknown code", func(f url.Values) { f.Set("code", "nope") }, true, 400, "invalid_grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest(nil)
			cb, _ := b.authorize(r)
			f := codeForm(cb.Get("code"), r.verifier)
			tc.mutate(f)
			status, tk := b.exchange(f, tc.basic)
			if status != tc.status || tk.Error != tc.err {
				t.Fatalf("status %d error %q, want %d %q", status, tk.Error, tc.status, tc.err)
			}
		})
	}

	// Wrong secret.
	r := newRequest(nil)
	cb, _ := b.authorize(r)
	req, _ := http.NewRequest(http.MethodPost, b.idp.URL+"/token", strings.NewReader(codeForm(cb.Get("code"), r.verifier).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(devidptest.ClientID, "wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("wrong secret: status %d", resp.StatusCode)
	}
}

func TestAuthorizeRequestValidation(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	// Unknown client or unregistered redirect_uri: an error page, never a redirect.
	for _, extra := range []map[string]string{
		{"client_id": "unknown"},
		{"redirect_uri": "http://evil.example/callback"},
		{"redirect_uri": "http://127.0.0.1:5999/callback/extra"},
		{"redirect_uri": "<omit>"},
	} {
		resp, _ := b.get(idp.URL + "/authorize?" + newRequest(extra).params.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%v: status %d location %q, want a 400 page", extra, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	for _, tc := range []struct {
		extra map[string]string
		err   string
	}{
		{map[string]string{"response_type": "token"}, "unsupported_response_type"},
		{map[string]string{"scope": "email"}, "invalid_scope"},
		{map[string]string{"nonce": "<omit>"}, "invalid_request"},
		{map[string]string{"state": "<omit>"}, "invalid_request"},
		{map[string]string{"max_age": "-1"}, "invalid_request"},
		{map[string]string{"prompt": "none login"}, "invalid_request"},
		{map[string]string{"request": "eyJ"}, "request_not_supported"},
		{map[string]string{"response_mode": "fragment"}, "invalid_request"},
		{map[string]string{"claims": "{"}, "invalid_request"},
		{map[string]string{"fault": "xsw1"}, "invalid_request"},
		{map[string]string{"fault": "bogus"}, "invalid_request"},
	} {
		cb, _ := b.authorize(newRequest(tc.extra))
		if cb.Get("error") != tc.err || cb.Get("iss") != idp.URL {
			t.Errorf("%v: callback %v, want error %s with iss", tc.extra, cb, tc.err)
		}
	}
	// A repeated parameter is refused.
	r := newRequest(nil)
	r.params.Add("acr_values", "phr")
	r.params.Add("acr_values", "phrh")
	if cb, _ := b.authorize(r); cb.Get("error") != "invalid_request" {
		t.Errorf("repeated acr_values: %v", cb)
	}
}

// TestOktaIgnoresUnrequestedACRValues: the Okta emulation returns phr/phrh
// only when requested and satisfied, and silently ignores acr_values it does
// not support, as Okta does (§8.2 rule 2).
func TestOktaIgnoresUnrequestedACRValues(t *testing.T) {
	for _, tc := range []struct {
		acrValues string
		sub       string
		method    devidp.Method
		want      string
	}{
		{"", "00u-alice-admin", devidp.MethodPasskey, devidp.OktaACR2FA},
		{"urn:tessera:acr:phr", "00u-alice-admin", devidp.MethodPasskey, devidp.OktaACR2FA},
		{"urn:example:unsupported", "00u-alice-admin", devidp.MethodPasskey, devidp.OktaACR2FA},
		{"urn:example:unsupported phr", "00u-alice-admin", devidp.MethodPasskey, "phr"},
		{"phr", "00u-alice-admin", devidp.MethodPasskey, "phr"},
		{"phr", "00u-alice-admin", devidp.MethodPasswordOTP, devidp.OktaACR2FA},
		{"phr", "00u-alice-admin", devidp.MethodPassword, devidp.OktaACR1FA},
		{"phrh", "00u-alice-admin", devidp.MethodPasskey, devidp.OktaACR2FA},
		{"phrh", "00u-ivan-admin2", devidp.MethodHardwareKey, "phrh"},
		{"phrh phr", "00u-alice-admin", devidp.MethodPasskey, "phr"},
	} {
		t.Run(tc.acrValues+"/"+string(tc.method), func(t *testing.T) {
			idp, b := start(t, devidp.Config{})
			r := newRequest(map[string]string{"acr_values": tc.acrValues})
			c := validate(t, idp, b.redeem(b.login(r, tc.sub, tc.method, devidp.ProfileOkta), r), r.params.Get("nonce"))
			if c["acr"] != tc.want {
				t.Fatalf("acr = %v, want %s", c["acr"], tc.want)
			}
			if _, ok := c["acrs"]; ok {
				t.Error("Okta emulation emitted acrs")
			}
		})
	}
}

func TestEntraAndGenericProfiles(t *testing.T) {
	claimsParam := `{"id_token":{"acrs":{"essential":true,"values":["c1"]}}}`
	for _, tc := range []struct {
		name     string
		profile  devidp.Profile
		method   devidp.Method
		extra    map[string]string
		wantACR  any
		wantACRS string
		wantAMR  string
	}{
		{"entra passkey with auth context", devidp.ProfileEntra, devidp.MethodPasskey,
			map[string]string{"claims": claimsParam, "acr_values": "phr"}, nil, "[c1]", "[fido mfa]"},
		{"entra password+otp with auth context", devidp.ProfileEntra, devidp.MethodPasswordOTP,
			map[string]string{"claims": claimsParam}, nil, "", "[pwd mfa]"},
		{"entra passkey without auth context", devidp.ProfileEntra, devidp.MethodPasskey, nil, nil, "", "[fido mfa]"},
		{"generic phr requested", devidp.ProfileGeneric, devidp.MethodPasskey,
			map[string]string{"acr_values": "phr"}, "phr", "", "[swk user mfa]"},
		{"generic nothing requested", devidp.ProfileGeneric, devidp.MethodPasskey, nil, "mfa", "", "[swk user mfa]"},
		{"generic phr requested, password", devidp.ProfileGeneric, devidp.MethodPassword,
			map[string]string{"acr_values": "phr"}, "pwd", "", "[pwd]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, b := start(t, devidp.Config{})
			r := newRequest(tc.extra)
			c := validate(t, idp, b.redeem(b.login(r, "00u-alice-admin", tc.method, tc.profile), r), r.params.Get("nonce"))
			if c["acr"] != tc.wantACR {
				t.Errorf("acr = %v, want %v", c["acr"], tc.wantACR)
			}
			gotACRS := ""
			if v, ok := c["acrs"]; ok {
				gotACRS = fmt.Sprint(v)
			}
			if gotACRS != tc.wantACRS {
				t.Errorf("acrs = %q, want %q", gotACRS, tc.wantACRS)
			}
			if got := fmt.Sprint(c["amr"]); got != tc.wantAMR {
				t.Errorf("amr = %s, want %s", got, tc.wantAMR)
			}
			if tc.profile == devidp.ProfileEntra {
				if c["oid"] != devidp.EntraObjectID("00u-alice-admin") || c["tid"] != devidp.EntraTenantID("larkspur") ||
					c["sub"] == "00u-alice-admin" || c["sub"] != devidp.EntraPairwiseSub("00u-alice-admin", devidptest.ClientID) {
					t.Errorf("entra identifiers: sub=%v oid=%v tid=%v", c["sub"], c["oid"], c["tid"])
				}
			}
		})
	}
}

// TestStepUpPromptAndMaxAge: the IdP session gives SSO with the original
// auth_time; prompt=login, max_age=0 or an exceeded max_age show the page
// again and update auth_time; prompt=none never shows the page.
func TestStepUpPromptAndMaxAge(t *testing.T) {
	clk := &clock{t: time.Now().Truncate(time.Second)}
	idp, b := start(t, devidp.Config{Now: clk.now})
	t0 := clk.now().Unix()
	authTime := func(r request, cb url.Values) int64 {
		t.Helper()
		_, c := unverifiedClaims(t, b.redeem(cb, r))
		return int64(c["auth_time"].(float64))
	}

	if cb, _ := b.authorize(newRequest(map[string]string{"prompt": "none"})); cb.Get("error") != "login_required" {
		t.Fatalf("prompt=none without a session: %v", cb)
	}
	r := newRequest(nil)
	if got := authTime(r, b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)); got != t0 {
		t.Fatalf("auth_time %d, want %d", got, t0)
	}
	clk.add(100 * time.Second)

	for _, tc := range []struct {
		name  string
		extra map[string]string
		sso   bool
	}{
		{"plain SSO", nil, true},
		{"prompt=none", map[string]string{"prompt": "none"}, true},
		{"max_age not exceeded", map[string]string{"max_age": "300"}, true},
		{"max_age exceeded", map[string]string{"max_age": "50"}, false},
		{"max_age=0", map[string]string{"max_age": "0"}, false},
		{"prompt=login", map[string]string{"prompt": "login"}, false},
		{"login_hint of another user", map[string]string{"login_hint": "pat.policy@larkspur.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := clk.now().Unix()
			r := newRequest(tc.extra)
			cb, pageReq := b.authorize(r)
			if tc.sso {
				if cb == nil {
					t.Fatal("expected SSO, got the sign-in page")
				}
				if got := authTime(r, cb); got != t0 {
					t.Fatalf("SSO auth_time %d, want the original %d", got, t0)
				}
				return
			}
			if cb != nil {
				t.Fatalf("expected the sign-in page, got %v", cb)
			}
			sub := "00u-alice-admin"
			if tc.extra["login_hint"] != "" {
				sub = "00u-pat-policy"
			}
			if got := authTime(r, b.signIn(pageReq, sub, devidp.MethodPasskey, devidp.ProfileOkta)); got != before {
				t.Fatalf("re-authentication auth_time %d, want now (%d)", got, before)
			}
			t0 = before
			clk.add(10 * time.Second)
		})
	}

	// prompt=none with a session that is too old for max_age.
	clk.add(time.Hour)
	if cb, _ := b.authorize(newRequest(map[string]string{"prompt": "none", "max_age": "60"})); cb.Get("error") != "login_required" {
		t.Fatalf("prompt=none + stale session: %v", cb)
	}

	// login_hint only preselects: the hinted user is listed first (by sub,
	// email or Entra oid), and another user may still sign in.
	for _, hint := range []string{"00u-vic-viewer", "vic@larkspur.example", devidp.EntraObjectID("00u-vic-viewer")} {
		resp, body := b.get(idp.URL + "/authorize?" + newRequest(map[string]string{"prompt": "login", "login_hint": hint}).params.Encode())
		if resp.StatusCode != http.StatusOK || strings.Index(body, "00u-vic-viewer") > strings.Index(body, "00u-alice-admin") {
			t.Errorf("login_hint %s: status %d, hinted user not listed first", hint, resp.StatusCode)
		}
	}
	_, pageReq := b.authorize(newRequest(map[string]string{"prompt": "login", "login_hint": "00u-vic-viewer"}))
	b.signIn(pageReq, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)

	// Logout ends the session: the next request shows the page.
	if resp, _ := b.get(idp.URL + "/logout"); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if cb, _ := b.authorize(newRequest(nil)); cb != nil {
		t.Fatalf("after logout: %v", cb)
	}
}

func TestSignInPageRejectsBadChoices(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	for _, choice := range []url.Values{
		{"choice": {"00u-vic-viewer passkey"}, "profile": {"okta"}}, // Vic has no passkey
		{"choice": {"00u-nobody passkey"}, "profile": {"okta"}},
		{"choice": {"00u-alice-admin passkey"}, "profile": {"keycloak"}},
	} {
		_, pageReq := b.authorize(newRequest(nil))
		choice.Set("req", pageReq)
		resp, err := b.c.PostForm(idp.URL+"/authorize", choice)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%v: status %d", choice, resp.StatusCode)
		}
	}
	// The page's request id is single use.
	_, pageReq := b.authorize(newRequest(nil))
	b.signIn(pageReq, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	resp, err := b.c.PostForm(idp.URL+"/authorize", url.Values{"req": {pageReq}, "choice": {"00u-alice-admin passkey"}, "profile": {"okta"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reused page request: status %d", resp.StatusCode)
	}
	// Cancel returns access_denied.
	_, pageReq = b.authorize(newRequest(map[string]string{"prompt": "login"}))
	resp, err = b.c.PostForm(idp.URL+"/authorize", url.Values{"req": {pageReq}, "action": {"cancel"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cb := b.callback(resp); cb.Get("error") != "access_denied" {
		t.Errorf("cancel: %v", cb)
	}
}

// defects lists every way an ID token (and its authorization response)
// differs from a valid one for the given request. A fault must produce
// exactly its own defect.
func defects(t *testing.T, idp *devidptest.IdP, cb url.Values, tok string, r request, user string, profile devidp.Profile) []string {
	t.Helper()
	var out []string
	if cb.Get("iss") != idp.URL {
		out = append(out, string(devidp.FaultNoIssParam))
	}
	h, c := unverifiedClaims(t, tok)
	set := fetchJWKS(t, idp)
	pub := set.Keys[0]
	switch h["alg"] {
	case "none":
		out = append(out, string(devidp.FaultAlgNone))
	case "HS256":
		der, err := x509.MarshalPKIXPublicKey(pub.Key)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		i := strings.LastIndexByte(tok, '.')
		mac.Write([]byte(tok[:i]))
		if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) == tok[i+1:] {
			out = append(out, string(devidp.FaultHS256WithPubkey))
		} else {
			out = append(out, string(devidp.FaultBadSignature))
		}
	case "RS256":
		if len(set.Key(fmt.Sprint(h["kid"]))) == 0 {
			out = append(out, string(devidp.FaultKidUnknown))
		}
		parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
		realSig := err == nil && parsed.Claims(pub.Key, &map[string]any{}) == nil
		if jku, ok := h["jku"].(string); ok {
			// jku_header: signed by the key the jku JWKS serves, not the real one.
			resp, err := http.Get(jku)
			if err != nil {
				t.Fatal(err)
			}
			var js jose.JSONWebKeySet
			_ = json.NewDecoder(resp.Body).Decode(&js)
			resp.Body.Close()
			if !realSig && len(js.Keys) == 1 && parsed.Claims(js.Keys[0].Key, &map[string]any{}) == nil {
				out = append(out, string(devidp.FaultJKUHeader))
			} else {
				out = append(out, "jku present but not attacker-signed")
			}
		} else if !realSig {
			out = append(out, string(devidp.FaultBadSignature))
		}
	default:
		out = append(out, "unexpected alg")
	}
	now := time.Now().Unix()
	num := func(k string) (int64, bool) {
		v, ok := c[k].(float64)
		return int64(v), ok
	}
	if c["iss"] != idp.URL {
		out = append(out, string(devidp.FaultWrongIss))
	}
	if c["aud"] != devidptest.ClientID {
		out = append(out, string(devidp.FaultWrongAud))
	}
	if exp, _ := num("exp"); exp < now-60 {
		out = append(out, string(devidp.FaultExpired))
	}
	if iat, _ := num("iat"); iat > now+60 || iat < now-600 {
		out = append(out, string(devidp.FaultFutureIat))
	}
	if c["nonce"] != r.params.Get("nonce") {
		out = append(out, string(devidp.FaultNonceMismatch))
	}
	maxAge := int64(300)
	if at, ok := num("auth_time"); !ok {
		out = append(out, string(devidp.FaultMissingAuthTime))
	} else if now-at > maxAge+60 {
		out = append(out, string(devidp.FaultStaleAuthTime))
	}
	wantSub := user
	if profile == devidp.ProfileEntra {
		wantSub = devidp.EntraPairwiseSub(user, devidptest.ClientID)
		if (c["oid"] != devidp.EntraObjectID(user)) != (c["sub"] != wantSub) {
			out = append(out, "entra sub and oid disagree")
		}
	}
	if c["sub"] != wantSub {
		out = append(out, string(devidp.FaultSubChangeStepUp))
	}
	_, hasACRS := c["acrs"]
	if (c["acr"] == devidp.OktaACRPhr && !slices.Contains(strings.Fields(r.params.Get("acr_values")), "phr")) ||
		(hasACRS && !r.params.Has("claims")) {
		out = append(out, string(devidp.FaultACRUnrequested))
	}
	// Everything the faults do not target must still be there.
	for _, k := range []string{"sid", "amr", "email", "name", "at_hash"} {
		if _, ok := c[k]; !ok {
			out = append(out, "missing "+k)
		}
	}
	sort.Strings(out)
	return out
}

// TestEachFaultProducesExactlyItsDefect runs every OIDC fault, selected with
// fault= on /authorize, and checks the response has that defect and no other.
func TestEachFaultProducesExactlyItsDefect(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	for _, profile := range []devidp.Profile{devidp.ProfileOkta, devidp.ProfileEntra} {
		for _, f := range append([]devidp.Fault{devidp.FaultNone}, devidp.OIDCFaults()...) {
			t.Run(string(profile)+"/fault="+string(f), func(t *testing.T) {
				extra := map[string]string{"max_age": "300", "prompt": "login"}
				if f != devidp.FaultNone {
					extra["fault"] = string(f)
				}
				r := newRequest(extra)
				cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, profile)
				got := defects(t, idp, cb, b.redeem(cb, r), r, "00u-alice-admin", profile)
				var want []string
				if f != devidp.FaultNone {
					want = []string{string(f)}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("defects %v, want %v", got, want)
				}
			})
		}
	}
}

// TestFaultsRefusedWhereTheyAreNoDefect: acr_unrequested makes no sense when
// phr (or an Entra context) was requested, nor sub_change_on_stepup outside a
// re-authentication, so those combinations are refused.
func TestFaultsRefusedWhereTheyAreNoDefect(t *testing.T) {
	_, b := start(t, devidp.Config{})
	for _, extra := range []map[string]string{
		{"fault": "acr_unrequested", "acr_values": "phr"},
		{"fault": "acr_unrequested", "acr_values": "phrh"},
		{"fault": "acr_unrequested", "claims": `{"id_token":{"acrs":{"essential":true,"values":["c1"]}}}`},
		{"fault": "sub_change_on_stepup"},
	} {
		if cb, _ := b.authorize(newRequest(extra)); cb.Get("error") != "invalid_request" {
			t.Errorf("%v: %v, want invalid_request", extra, cb)
		}
	}
	for _, extra := range []map[string]string{
		{"fault": "sub_change_on_stepup", "prompt": "login"},
		{"fault": "sub_change_on_stepup", "max_age": "0"},
		{"fault": "acr_unrequested", "acr_values": "urn:okta:loa:2fa:any"},
	} {
		if cb, pageReq := b.authorize(newRequest(extra)); cb != nil || pageReq == "" {
			t.Errorf("%v: refused: %v", extra, cb)
		}
	}
}

func TestFaultEndpointAndDisabledFaults(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	post := func(body string) int {
		resp, err := http.Post(idp.URL+"/_faults", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := post(`{"fault":"wrong_aud"}`); s != http.StatusOK {
		t.Fatalf("set fault: %d", s)
	}
	r := newRequest(map[string]string{"prompt": "login"})
	cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	if got := defects(t, idp, cb, b.redeem(cb, r), r, "00u-alice-admin", devidp.ProfileOkta); !slices.Equal(got, []string{"wrong_aud"}) {
		t.Fatalf("defects %v after POST /_faults", got)
	}
	for _, bad := range []string{`{"fault":"bogus"}`, `{"fault":"xsw2"}`, `{"fault":"x","more":1}`, `nope`} {
		if s := post(bad); s != http.StatusBadRequest {
			t.Errorf("POST %s: %d", bad, s)
		}
	}
	if s := post(`{"fault":""}`); s != http.StatusOK {
		t.Fatalf("clear fault: %d", s)
	}
	r = newRequest(nil)
	cb, _ = b.authorize(r)
	if got := defects(t, idp, cb, b.redeem(cb, r), r, "00u-alice-admin", devidp.ProfileOkta); len(got) != 0 {
		t.Fatalf("defects %v after clearing", got)
	}

	// With faults disabled, fault= is refused and /_faults does not exist.
	srv, err := devidp.New(devidp.Config{Issuer: "http://127.0.0.1:1", Clients: []devidp.Client{{
		ID: devidptest.ClientID, Secret: "s", RedirectURIs: []string{redirectURI}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetFault(devidp.FaultWrongIss); err == nil {
		t.Error("SetFault succeeded with faults disabled")
	}
	rec := httptestRecorder(srv.Handler(), http.MethodGet, "/authorize?"+newRequest(map[string]string{"fault": "wrong_iss"}).params.Encode())
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if v, _ := url.ParseQuery(loc.RawQuery); v.Get("error") != "invalid_request" {
		t.Errorf("fault= with faults disabled: %d %v", rec.Code, loc)
	}
	if rec := httptestRecorder(srv.Handler(), http.MethodPost, "/_faults"); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("/_faults with faults disabled: %d", rec.Code)
	}
}

func TestUserinfoAndSAMLStub(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	r := newRequest(nil)
	cb := b.login(r, "00u-olu-operator", devidp.MethodPasswordOTP, devidp.ProfileOkta)
	status, tk := b.exchange(codeForm(cb.Get("code"), r.verifier), true)
	if status != http.StatusOK || tk.TokenType != "Bearer" || tk.ExpiresIn <= 0 {
		t.Fatalf("token: %d %+v", status, tk)
	}
	get := func(auth string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, idp.URL+"/userinfo", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	if s, m := get("Bearer " + tk.AccessToken); s != http.StatusOK || m["sub"] != "00u-olu-operator" || m["email"] != "olu@larkspur.example" {
		t.Fatalf("userinfo: %d %v", s, m)
	}
	for _, auth := range []string{"", "Bearer nope", "Basic " + tk.AccessToken} {
		if s, _ := get(auth); s != http.StatusUnauthorized {
			t.Errorf("userinfo with %q: %d", auth, s)
		}
	}
	for _, p := range []string{"/saml/metadata", "/saml/sso"} {
		if resp, _ := b.get(idp.URL + p); resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s: %d, want 501 until PR9", p, resp.StatusCode)
		}
	}
}

func TestPrivateKeyJWTClient(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: ek.Public(), KeyID: "rp-1", Algorithm: "ES256", Use: "sig"}
	idp, b := start(t, devidp.Config{Clients: []devidp.Client{{ID: "tessera-pkjwt", JWKS: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}},
		RedirectURIs: []string{redirectURI}}}})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: ek, KeyID: "rp-1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertion := func(jti string, aud string) string {
		now := time.Now()
		s, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: "tessera-pkjwt", Subject: "tessera-pkjwt",
			Audience: jwt.Audience{aud}, ID: jti, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute))}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	try := func(a string) (int, tokens) {
		r := newRequest(map[string]string{"client_id": "tessera-pkjwt", "prompt": "login"})
		cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
		f := codeForm(cb.Get("code"), r.verifier)
		f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		f.Set("client_assertion", a)
		return b.exchange(f, false)
	}
	if s, tk := try(assertion("j1", idp.URL+"/token")); s != http.StatusOK || tk.IDToken == "" {
		t.Fatalf("private_key_jwt: %d %q", s, tk.Error)
	}
	if s, tk := try(assertion("j1", idp.URL+"/token")); s != http.StatusUnauthorized || tk.Error != "invalid_client" {
		t.Errorf("replayed jti: %d %q", s, tk.Error)
	}
	for i, aud := range []string{"https://elsewhere.example/token", idp.URL} {
		if s, _ := try(assertion(fmt.Sprint("j-aud-", i), aud)); s != http.StatusUnauthorized {
			t.Errorf("aud %s: %d, want 401 (aud must be the token endpoint)", aud, s)
		}
	}
}

func httptestRecorder(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// TestExpiryBoundaries: a code lives 60 s, an access token 5 min and the SSO
// session 12 h; at exactly the expiry instant each is gone.
func TestExpiryBoundaries(t *testing.T) {
	clk := &clock{t: time.Now().Truncate(time.Second)}
	idp, b := start(t, devidp.Config{Now: clk.now})
	r := newRequest(nil)
	cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	clk.add(60 * time.Second)
	if status, tk := b.exchange(codeForm(cb.Get("code"), r.verifier), true); status != http.StatusBadRequest || tk.Error != "invalid_grant" {
		t.Fatalf("code at 60 s: %d %q", status, tk.Error)
	}
	r = newRequest(nil)
	cb, _ = b.authorize(r)
	clk.add(59 * time.Second)
	status, tk := b.exchange(codeForm(cb.Get("code"), r.verifier), true)
	if status != http.StatusOK {
		t.Fatalf("code at 59 s: %d %q", status, tk.Error)
	}
	userinfo := func() int {
		req, _ := http.NewRequest(http.MethodGet, idp.URL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tk.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	clk.add(5*time.Minute - time.Second)
	if s := userinfo(); s != http.StatusOK {
		t.Fatalf("access token before expiry: %d", s)
	}
	clk.add(time.Second)
	if s := userinfo(); s != http.StatusUnauthorized {
		t.Fatalf("access token at expiry: %d", s)
	}
	clk.add(12*time.Hour - 7*time.Minute)
	if cb, _ := b.authorize(newRequest(nil)); cb == nil {
		t.Fatal("SSO session expired too early")
	}
	clk.add(7 * time.Minute)
	if cb, _ := b.authorize(newRequest(nil)); cb != nil {
		t.Fatalf("SSO after 12 h: %v", cb)
	}
}

// TestConcurrentCodeRedemption: of many simultaneous redemptions of one code,
// exactly one succeeds.
func TestConcurrentCodeRedemption(t *testing.T) {
	_, b := start(t, devidp.Config{})
	r := newRequest(nil)
	cb := b.login(r, "00u-alice-admin", devidp.MethodPasskey, devidp.ProfileOkta)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := codeForm(cb.Get("code"), r.verifier)
			req, _ := http.NewRequest(http.MethodPost, b.idp.URL+"/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(devidptest.ClientID, devidptest.ClientSecret)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d successful redemptions, want exactly 1", ok)
	}
}
