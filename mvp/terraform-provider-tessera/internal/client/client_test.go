package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func pemOf(t *testing.T, k any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestValidateEndpoint(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"https://tessera.example.com", true},
		{"https://tessera.example.com/", true},
		{"http://localhost:8000", true},
		{"http://127.0.0.1:8400", true},
		{"http://tessera.example.com", false},
		{"ftp://tessera.example.com", false},
		{"https://user:pw@tessera.example.com", false},
		{"https://tessera.example.com?x=1", false},
		{"https://tessera.example.com#f", false},
		{"tessera.example.com", false},
		{"", false},
	} {
		u, err := ValidateEndpoint(c.in)
		if (err == nil) != c.ok {
			t.Errorf("%q: err = %v, want ok=%v", c.in, err, c.ok)
		}
		if err == nil && strings.HasSuffix(u.String(), "/") {
			t.Errorf("%q: trailing slash kept: %s", c.in, u)
		}
	}
}

func TestParsePrivateKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	for name, c := range map[string]struct {
		pem string
		ok  bool
	}{
		"p256 pkcs8": {pemOf(t, ec), true},
		"ed25519":    {pemOf(t, ed), true},
		"p256 sec1":  {string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})), true},
		"p384":       {pemOf(t, p384), false},
		"not pem":    {"hello", false},
		"empty":      {"", false},
	} {
		if _, err := ParsePrivateKey(c.pem); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestParseError(t *testing.T) {
	for _, c := range []struct {
		body string
		want string
	}{
		{`{"error":{"code":"invalid_name","message":"a name is required","field":"name"}}`, "invalid_name: a name is required (field name) (HTTP 422)"},
		{`{"error":"privilege_required","detail":"the create privilege is required"}`, "privilege_required: the create privilege is required (HTTP 422)"},
		{`not json`, "HTTP 422"},
		{"{\"error\":\"x\\u001b[31m\"}", "x [31m (HTTP 422)"},
	} {
		if got := parseError(422, []byte(c.body)).Error(); got != c.want {
			t.Errorf("%s: got %q want %q", c.body, got, c.want)
		}
	}
}

// fakeServer is a tenant's OAuth endpoints and one API route, checking what a real server checks of a client.
type fakeServer struct {
	*httptest.Server
	t          *testing.T
	clientKey  *ecdsa.PublicKey
	tokens     atomic.Int32
	dpop       bool
	needNonce  bool
	rejectOnce atomic.Bool
	apiCalls   atomic.Int32
}

func newFake(t *testing.T, pub *ecdsa.PublicKey, dpop, needNonce bool) *fakeServer {
	f := &fakeServer{t: t, clientKey: pub, dpop: dpop, needNonce: needNonce}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	mux.HandleFunc("/t/larkspur/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": f.URL + "/t/larkspur/oauth/token"})
	})
	mux.HandleFunc("/t/larkspur/oauth/token", f.token)
	mux.HandleFunc("/api/v1/things", f.things)
	return f
}

func (f *fakeServer) token(w http.ResponseWriter, r *http.Request) {
	t := f.t
	if f.needNonce && !strings.Contains(r.Header.Get("DPoP"), ".") {
		t.Error("a DPoP proof is required")
	}
	if err := r.ParseForm(); err != nil {
		t.Error(err)
	}
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "tsc_x" ||
		r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("bad token request: %v", r.PostForm)
	}
	if r.PostForm.Get("client_secret") != "" {
		t.Error("a client secret was sent")
	}
	tok, err := jwt.ParseSigned(r.PostForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Headers[0].KeyID != "k1" {
		t.Errorf("kid = %q", tok.Headers[0].KeyID)
	}
	var c jwt.Claims
	if err := tok.Claims(f.clientKey, &c); err != nil {
		t.Fatalf("the assertion is not signed by the client key: %v", err)
	}
	if c.Issuer != "tsc_x" || c.Subject != "tsc_x" || len(c.Audience) != 1 || c.Audience[0] != f.URL+"/t/larkspur/oauth/token" || c.ID == "" ||
		c.Expiry == nil || c.IssuedAt == nil || c.Expiry.Time().Sub(c.IssuedAt.Time()) > 5*60*1e9 {
		t.Errorf("bad assertion claims: %+v", c)
	}
	if f.dpop && f.needNonce && !hasNonce(r.Header.Get("DPoP")) {
		// the nonce travels inside the proof: ask for it once
		w.Header().Set("DPoP-Nonce", "n-1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		return
	}
	f.tokens.Add(1)
	typ := "Bearer"
	if f.dpop {
		typ = "DPoP"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + string(rune('0'+f.tokens.Load())), "token_type": typ, "expires_in": 600})
}

func hasNonce(proof string) bool {
	tok, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return false
	}
	var c map[string]any
	if tok.UnsafeClaimsWithoutVerification(&c) != nil {
		return false
	}
	return c["nonce"] == "n-1"
}

func (f *fakeServer) things(w http.ResponseWriter, r *http.Request) {
	f.apiCalls.Add(1)
	auth := r.Header.Get("Authorization")
	if f.dpop {
		if !strings.HasPrefix(auth, "DPoP ") || r.Header.Get("DPoP") == "" {
			f.t.Errorf("want a DPoP request, got %q", auth)
		}
		tok, err := jwt.ParseSigned(r.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || tok.Headers[0].JSONWebKey == nil || tok.Headers[0].ExtraHeaders[jose.HeaderType] != "dpop+jwt" {
			f.t.Errorf("bad DPoP proof: %v", err)
		} else {
			var c map[string]any
			_ = tok.Claims(tok.Headers[0].JSONWebKey, &c)
			if c["htm"] != r.Method || c["htu"] != f.URL+"/api/v1/things" || c["ath"] == nil {
				f.t.Errorf("bad proof claims: %v", c)
			}
		}
	} else if !strings.HasPrefix(auth, "Bearer ") {
		f.t.Errorf("want a Bearer request, got %q", auth)
	}
	if f.rejectOnce.CompareAndSwap(true, false) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Query().Get("cursor") {
	case "":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]int{{"n": 1}, {"n": 2}}, "next_cursor": "c2"})
	case "c2":
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]int{{"n": 3}}, "next_cursor": nil})
	}
}

func testClient(t *testing.T, f *fakeServer, key *ecdsa.PrivateKey, dpop bool) *Client {
	c, err := New(Config{Endpoint: f.URL, Tenant: "larkspur", ClientID: "tsc_x", PrivateKeyPEM: pemOf(t, key), KeyID: "k1", DPoP: dpop})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClient_BearerFlow(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &key.PublicKey, false, false)
	c := testClient(t, f, key, false)
	items, err := c.List(context.Background(), "/things", url.Values{"q": {"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("followed the cursor to %d items, want 3", len(items))
	}
	if f.tokens.Load() != 1 {
		t.Fatalf("minted %d tokens for 2 calls, want 1 (the token is reused)", f.tokens.Load())
	}
	// a revoked or expired token is renewed once, and the call is retried
	f.rejectOnce.Store(true)
	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 2 {
		t.Fatalf("tokens = %d, want 2 after a 401", f.tokens.Load())
	}
}

func TestClient_DPoPFlowWithNonce(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &key.PublicKey, true, true)
	c := testClient(t, f, key, true)
	if _, err := c.List(context.Background(), "/things", nil); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 1 {
		t.Fatalf("tokens = %d", f.tokens.Load())
	}
}

func TestClient_DPoPRefusesABearerToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &key.PublicKey, false, false)
	c := testClient(t, f, key, true)
	err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("got %v", err)
	}
}

func TestClient_RefusesAnotherOriginsTokenEndpointAndRedirects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the assertion was sent to another origin") }))
	defer evil.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/t/larkspur/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": evil.URL + "/t/larkspur/oauth/token"})
		default:
			http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
		}
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Tenant: "larkspur", ClientID: "tsc_x", PrivateKeyPEM: pemOf(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("a token endpoint on another origin was accepted: %v", err)
	}
	// redirects are refused at the transport
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	if _, err := c.http.Do(req); err == nil || !strings.Contains(err.Error(), "another origin") {
		t.Fatalf("a cross-origin redirect was followed: %v", err)
	}
}

func TestClient_RejectsBadPaths(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, err := New(Config{Endpoint: "https://tessera.example.com", Tenant: "larkspur", ClientID: "tsc_x", PrivateKeyPEM: pemOf(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"things", "//evil.example/x", "/a\\b", "/a\r\nHost: x"} {
		if err := c.Do(context.Background(), http.MethodGet, p, nil, nil); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}
