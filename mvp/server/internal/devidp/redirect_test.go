package devidp_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
)

// TestUnregisteredRedirectTargetsAreRefused: a malicious CAS service or OIDC
// redirect_uri gets a 400 page, never a redirect, and the page never echoes
// the raw input (reflected XSS, open redirect).
func TestUnregisteredRedirectTargetsAreRefused(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	const evil = "http://evil.example/<script>alert(1)</script>"
	for _, tc := range []struct{ name, target string }{
		{"cas service", idp.URL + "/cas/login?" + url.Values{"service": {evil}}.Encode()},
		{"cas service other host", idp.URL + "/cas/login?service=" + url.QueryEscape("http://evil.example/callback")},
		{"cas service userinfo", idp.URL + "/cas/login?service=" + url.QueryEscape("http://127.0.0.1:5999@evil.example/callback")},
		{"cas repeated parameter", idp.URL + "/cas/login?service=" + url.QueryEscape(redirectURI) + "&%3Cb%3E=1&%3Cb%3E=2"},
		{"oidc redirect_uri", idp.URL + "/authorize?" + newRequest(map[string]string{"redirect_uri": evil}).params.Encode()},
		{"oidc redirect_uri other host", idp.URL + "/authorize?" + newRequest(map[string]string{"redirect_uri": "http://evil.example/callback"}).params.Encode()},
	} {
		resp, body := b.get(tc.target)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q, want a 400 page", tc.name, resp.StatusCode, resp.Header.Get("Location"))
		}
		for _, raw := range []string{"<script>", "evil.example", "<b>"} {
			if strings.Contains(body, raw) {
				t.Errorf("%s: the error page echoes %q", tc.name, raw)
			}
		}
	}
}

// TestCASValidateNeverEchoesInput: failure bodies carry fixed messages only.
func TestCASValidateNeverEchoesInput(t *testing.T) {
	idp, b := start(t, devidp.Config{})
	const raw = "ST-<script>alert(1)</script>"
	resp, body := b.get(idp.URL + "/cas/p3/serviceValidate?" + url.Values{"ticket": {raw}, "service": {redirectURI}}.Encode())
	if !strings.Contains(body, "authenticationFailure") {
		t.Fatalf("status %d: want an authenticationFailure, got %q", resp.StatusCode, body)
	}
	if strings.Contains(body, "script") || strings.Contains(body, "ST-") {
		t.Errorf("the failure body echoes the ticket: %q", body)
	}
}
