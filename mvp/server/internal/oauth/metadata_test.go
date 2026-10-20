package oauth

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
)

func get(t testing.TB, h *harness, path string) resp {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	return do(t, req)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestAuthorizationServerMetadata is the RFC 8414 document of a tenant's issuer.
func TestAuthorizationServerMetadata(t *testing.T) {
	h := newHarness(t)
	r := get(t, h, "/t/"+slugA+"/.well-known/oauth-authorization-server")
	if r.Status != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
	iss := h.srv.URL + "/t/" + slugA
	for k, want := range map[string]string{
		"issuer":                        iss,
		"token_endpoint":                iss + "/oauth/token",
		"device_authorization_endpoint": iss + "/oauth/device_authorization",
		"revocation_endpoint":           iss + "/oauth/revoke",
		"introspection_endpoint":        iss + "/oauth/introspect",
		"jwks_uri":                      iss + "/.well-known/jwks.json",
	} {
		if r.str(k) != want {
			t.Errorf("%s = %q, want %q", k, r.str(k), want)
		}
	}
	if got := strs(r.Body["grant_types_supported"]); !slices.Equal(got, []string{GrantDeviceCode, GrantRefresh, GrantClientCredentials}) {
		t.Errorf("grant_types_supported = %v", got)
	}
	if got := strs(r.Body["dpop_signing_alg_values_supported"]); !slices.Equal(got, []string{"ES256", "EdDSA"}) {
		t.Errorf("dpop_signing_alg_values_supported = %v", got)
	}
	if got := strs(r.Body["token_endpoint_auth_methods_supported"]); !slices.Equal(got, []string{"none", "private_key_jwt"}) {
		t.Errorf("token_endpoint_auth_methods_supported = %v", got)
	}
	for _, k := range []string{"token_endpoint_auth_signing_alg_values_supported", "introspection_endpoint_auth_signing_alg_values_supported"} {
		if got := strs(r.Body[k]); !slices.Equal(got, []string{"ES256", "EdDSA"}) {
			t.Errorf("%s = %v (no HS*, RS* or none)", k, got)
		}
	}
	if got := strs(r.Body["introspection_endpoint_auth_methods_supported"]); !slices.Equal(got, []string{"private_key_jwt"}) {
		t.Errorf("introspection_endpoint_auth_methods_supported = %v", got)
	}
	if got := strs(r.Body["scopes_supported"]); !slices.Equal(got, MachineScopes) {
		t.Errorf("scopes_supported = %v", got)
	}
	if r.Body["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("authorization_response_iss_parameter_supported = %v", r.Body["authorization_response_iss_parameter_supported"])
	}
	if _, ok := r.Body["authorization_endpoint"]; ok {
		t.Error("there is no authorization endpoint")
	}
	if cc := r.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=300") || strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
	// the issuer is per tenant
	rb := get(t, h, "/t/"+slugB+"/.well-known/oauth-authorization-server")
	if rb.str("issuer") != h.srv.URL+"/t/"+slugB || rb.str("token_endpoint") == r.str("token_endpoint") {
		t.Errorf("tenant B: %s", rb.Raw)
	}
	for _, slug := range []string{"nobody", "_platform", "UPPER", "a"} {
		if r := get(t, h, "/t/"+slug+"/.well-known/oauth-authorization-server"); r.Status != 404 {
			t.Errorf("slug %q: %d %s", slug, r.Status, r.Raw)
		}
	}
	// the document names no secret and no other tenant
	if strings.Contains(r.Raw, slugB) {
		t.Errorf("tenant A's metadata names tenant B: %s", r.Raw)
	}
}

// TestProtectedResourceMetadata is the RFC 9728 document of the API.
func TestProtectedResourceMetadata(t *testing.T) {
	h := newHarness(t)
	r := get(t, h, "/.well-known/oauth-protected-resource")
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
	if r.str("resource") != h.srv.URL+"/api" {
		t.Errorf("resource = %q (must equal the aud of access tokens)", r.str("resource"))
	}
	if got := strs(r.Body["authorization_servers"]); !slices.Equal(got, []string{h.srv.URL + "/t/{slug}"}) {
		t.Errorf("authorization_servers = %v", got)
	}
	if got := strs(r.Body["bearer_methods_supported"]); !slices.Equal(got, []string{"header"}) {
		t.Errorf("bearer_methods_supported = %v", got)
	}
	if r.Body["dpop_bound_access_tokens_required"] != true {
		t.Errorf("dpop_bound_access_tokens_required = %v", r.Body["dpop_bound_access_tokens_required"])
	}
	if got := strs(r.Body["dpop_signing_alg_values_supported"]); !slices.Equal(got, []string{"ES256", "EdDSA"}) {
		t.Errorf("dpop_signing_alg_values_supported = %v", got)
	}
	// the resource really is the audience of the tokens it issues
	k := newKey(t)
	tok, _ := h.signInCLI(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr, k)
	if _, c := decodeJWT(t, tok.Access); c["aud"] != r.str("resource") {
		t.Errorf("token aud %v, resource %q", c["aud"], r.str("resource"))
	}
}

// TestJWKS: the tenant's public keys verify its tokens, carry nothing
// private, and never include another tenant's key.
func TestJWKS(t *testing.T) {
	h := newHarness(t)
	k := newKey(t)
	tok, _ := h.signInCLI(slugA, "alice@a.example", []auth.Role{auth.RoleViewer}, authtest.Phr, k)
	r := get(t, h, "/t/"+slugA+"/.well-known/jwks.json")
	if r.Status != 200 || !strings.Contains(r.Header.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("%d %s %q", r.Status, r.Raw, r.Header.Get("Cache-Control"))
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(r.Raw), &set); err != nil || len(set.Keys) < 2 { // active and next
		t.Fatalf("keys: %v %s", err, r.Raw)
	}
	hdr, _ := decodeJWT(t, tok.Access)
	found := false
	for _, key := range set.Keys {
		for _, private := range []string{"d", "p", "q", "k"} {
			if _, ok := key[private]; ok {
				t.Errorf("the JWKS has a private member %q: %v", private, key)
			}
		}
		if key["kty"] != "EC" || key["crv"] != "P-256" || key["alg"] != "ES256" || key["use"] != "sig" {
			t.Errorf("key %v", key)
		}
		if key["kid"] == hdr["kid"] {
			found = true
		}
	}
	if !found {
		t.Errorf("the token's kid %v is not in the JWKS", hdr["kid"])
	}
	rb := get(t, h, "/t/"+slugB+"/.well-known/jwks.json")
	var setB struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal([]byte(rb.Raw), &setB)
	for _, a := range set.Keys {
		for _, b := range setB.Keys {
			if a["kid"] == b["kid"] || (a["x"] == b["x"] && a["y"] == b["y"]) {
				t.Errorf("tenants A and B share a key: %v", a["kid"])
			}
		}
	}
	if r := get(t, h, "/t/nobody/.well-known/jwks.json"); r.Status != 404 {
		t.Errorf("unknown tenant: %d", r.Status)
	}
}
