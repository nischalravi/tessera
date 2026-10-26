package awsorg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/mcpauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TestFederationToken_RefusedByTesseraVerifiers: the federation token is signed
// with the same access-token key as API (internal/oauth) and MCP
// (internal/mcpauth) tokens, so neither verifier may accept it. The typ header
// ("JWT", not "at+jwt") refuses it first; the issuer and the audience refuse it
// as well. Token confusion regression for #638.
func TestFederationToken_RefusedByTesseraVerifiers(t *testing.T) {
	e := newFedEnv(t, newReplay(t))
	k := e.create(t, e.f.A, "prod")
	tok, err := e.svc.Federation.Token(context.Background(), e.f.A.ID, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(strings.SplitN(tok, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Typ, Alg, Kid string }
	if err := json.Unmarshal(hdr, &h); err != nil || h.Typ != "JWT" || h.Typ == mcpauth.TokenType || h.Alg != "ES256" || h.Kid == "" {
		t.Fatalf("header = %s", hdr)
	}

	// the MCP verifier, for the MCP issuer and even for the AWS issuer itself
	for _, iss := range []string{fedPublicURL + "/t/" + e.f.A.Slug + "/mcp", IssuerURL(fedPublicURL, e.f.A.Slug)} {
		if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
			if _, err := mcpauth.Verify(c, tok, iss, testNow); !errors.Is(err, mcpauth.ErrTokenInvalid) {
				t.Errorf("mcpauth.Verify(%s) = %v, want ErrTokenInvalid", iss, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// the API's resource server, as Bearer and as DPoP; its audience is set to
	// the federation audience, the worst case, so only typ and iss refuse it
	as, err := oauth.New(oauth.Config{DB: e.f.DB, Sealer: e.seal, Clock: e.svc.Federation.Clock, PublicURL: fedPublicURL,
		APIAudience: FederationAudience})
	if err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{"Bearer ", "DPoP "} {
		r := httptest.NewRequest("GET", fedPublicURL+"/api/me", nil)
		r.Header.Set("Authorization", scheme+tok)
		vt, fail, err := as.VerifyAccessToken(r)
		if err != nil || vt != nil || fail == nil {
			t.Errorf("%sAPI verifier accepted the federation token: %v %v %v", scheme, vt, fail, err)
		}
	}
}

// TestRedact_TokenOutsideMessage: a token anywhere in an AWS error, not only in
// its message, is withheld.
func TestRedact_TokenOutsideMessage(t *testing.T) {
	const tok = "eyJhbGciOi.secretpayload.sig"
	got := redact(&Error{Service: "sts", Op: "AssumeRoleWithWebIdentity", Status: 400, Code: "Bad" + tok}, tok)
	if strings.Contains(got.Error(), tok) {
		t.Errorf("redact = %v", got)
	}
}
