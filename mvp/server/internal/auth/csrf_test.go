package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
)

var allowed = []string{"http://localhost:5173", "https://tessera.example.com"}

// TestCSRF: an unsafe request of a cookie principal needs the session's
// token in X-Tessera-CSRF and an allowed Origin (or Referer); safe methods
// need neither (§11, threat T2).
func TestCSRF(t *testing.T) {
	e := newEnv(t)
	l := authtest.LoginAs(t, e.db, tenantA, admin, authtest.Phr, t0)
	other := authtest.LoginAs(t, e.db, tenantA, viewer, authtest.Phr, t0)
	p, _ := e.authenticate(t, l.Cookie)
	if p == nil {
		t.Fatal("not signed in")
	}
	if p.CSRFToken() != l.CSRFToken || p.CSRFToken() != auth.CSRFToken(*p.Session().CSRFSecret) {
		t.Fatal("the CSRF token is not derived from the session's secret")
	}
	type hdr map[string]string
	cases := []struct {
		name   string
		method string
		h      hdr
		ok     bool
	}{
		{"GET needs nothing", http.MethodGet, hdr{}, true},
		{"HEAD needs nothing", http.MethodHead, hdr{}, true},
		{"token and origin", http.MethodPost, hdr{"Origin": "http://localhost:5173", auth.CSRFHeader: l.CSRFToken}, true},
		{"token and production origin", http.MethodDelete, hdr{"Origin": "https://tessera.example.com", auth.CSRFHeader: l.CSRFToken}, true},
		{"token and referer, no origin", http.MethodPut, hdr{"Referer": "http://localhost:5173/jit?x=1", auth.CSRFHeader: l.CSRFToken}, true},
		{"no token", http.MethodPost, hdr{"Origin": "http://localhost:5173"}, false},
		{"wrong token", http.MethodPost, hdr{"Origin": "http://localhost:5173", auth.CSRFHeader: "x" + l.CSRFToken[1:]}, false},
		{"another session's token", http.MethodPost, hdr{"Origin": "http://localhost:5173", auth.CSRFHeader: other.CSRFToken}, false},
		{"the session secret as token", http.MethodPost, hdr{"Origin": "http://localhost:5173", auth.CSRFHeader: l.Cookie.Value}, false},
		{"no origin or referer", http.MethodPost, hdr{auth.CSRFHeader: l.CSRFToken}, false},
		{"foreign origin", http.MethodPatch, hdr{"Origin": "https://evil.example", auth.CSRFHeader: l.CSRFToken}, false},
		{"origin with another port", http.MethodPost, hdr{"Origin": "http://localhost:5174", auth.CSRFHeader: l.CSRFToken}, false},
		{"null origin", http.MethodPost, hdr{"Origin": "null", auth.CSRFHeader: l.CSRFToken}, false},
		{"foreign referer", http.MethodPost, hdr{"Referer": "https://evil.example/x", auth.CSRFHeader: l.CSRFToken}, false},
		{"lookalike origin", http.MethodPost, hdr{"Origin": "http://localhost:5173.evil.example", auth.CSRFHeader: l.CSRFToken}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/jit/sweep", strings.NewReader(`{}`))
			for k, v := range tc.h {
				r.Header.Set(k, v)
			}
			err := auth.CheckCSRF(r, p, allowed)
			if (err == nil) != tc.ok {
				t.Errorf("CheckCSRF = %v, want ok=%t", err, tc.ok)
			}
			if err != nil && !errors.Is(err, auth.ErrCSRF) {
				t.Errorf("error %v is not ErrCSRF", err)
			}
		})
	}
	// token principals (DPoP, PR10) are not cookie-bound and are not checked
	tok := *p
	tok.Via = auth.ViaDPoP
	r := httptest.NewRequest(http.MethodPost, "/api/jit/sweep", nil)
	if err := auth.CheckCSRF(r, &tok, allowed); err != nil {
		t.Errorf("token principal: %v", err)
	}
}

// TestCSRFTokenRotates: rotating the session changes its CSRF token.
func TestCSRFTokenStable(t *testing.T) {
	if auth.CSRFToken("a") != auth.CSRFToken("a") || auth.CSRFToken("a") == auth.CSRFToken("b") {
		t.Error("the token must be a function of the secret")
	}
}
