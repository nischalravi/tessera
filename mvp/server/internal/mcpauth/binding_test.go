package mcpauth

import (
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Issuer and audience binding of MCP resource servers, and the policy against
// unregistered servers (issue #479).

const evilIssuer = "https://evil.example/t/tiny/mcp"

func (e *env) bind(res *store.MCPResource, issuer, audience string) {
	e.t.Helper()
	e.write(func(tx *store.TenantTx) error {
		return tx.PutMCPResourceBinding(&store.MCPResourceBinding{ResourceID: res.ID, Issuer: issuer, Audience: audience,
			UpdatedBy: "admin", UpdatedAt: e.now})
	})
}

// mint signs a token with the tenant's key and the given claims: what a token
// of another issuer or audience looks like to a resource server.
func (e *env) mint(iss, aud string, res *store.MCPResource) string {
	e.t.Helper()
	var raw string
	e.write(func(tx *store.TenantTx) error {
		var err error
		raw, err = Mint(tx, e.svc.Sealer, Claims{Issuer: iss, Subject: SubjectOf(e.alice), Audience: jwt.Audience{aud},
			Expiry: jwt.NewNumericDate(e.now.Add(time.Minute)), NotBefore: jwt.NewNumericDate(e.now), IssuedAt: jwt.NewNumericDate(e.now),
			ID: "forged-" + strings.ReplaceAll(iss+aud, "/", ""), Scope: e.shared, ClientID: e.client.ClientID})
		return err
	})
	return raw
}

func TestBindingDefaultsAndExplicitAudience(t *testing.T) {
	e := newEnv(t)
	e.read(func(tx *store.TenantTx) error {
		b, err := BindingOf(tx, e.resA, testIssuer)
		if err != nil || b.Explicit || b.Issuer != testIssuer || b.Audience != e.resA.Resource {
			t.Errorf("default binding = %+v, %v", b, err)
		}
		return nil
	})
	const aud = "https://api.mcp-a.example/"
	e.bind(e.resA, testIssuer, aud)
	tok := e.userToken(e.resA)
	if c := e.claims(tok.AccessToken); len(c.Audience) != 1 || c.Audience[0] != aud || c.Issuer != testIssuer {
		t.Fatalf("claims iss=%s aud=%v, want the bound audience %s", c.Issuer, c.Audience, aud)
	}
	if in, why := e.introspect(tok.AccessToken, e.resA); !in.Active || in.Aud != aud {
		t.Errorf("bound resource: %+v %s", in, why)
	}
	// the token of A is not accepted by B, whose audience is its own URI
	if in, why := e.introspect(tok.AccessToken, e.resB); in.Active || why == "" {
		t.Errorf("A's token accepted by B: %+v %q", in, why)
	}
}

func TestBindingRefusesMismatchedAudience(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA)
	// the token is for A: B refuses it, with a reason
	if in, why := e.introspect(tok.AccessToken, e.resB); in.Active || why != msgAudWrong {
		t.Errorf("A's token at B: %+v %q", in, why)
	}
	// a token signed by the tenant but carrying another audience
	wrong := e.mint(testIssuer, "https://mcp-b.example/mcp", e.resA)
	if in, why := e.introspect(wrong, e.resA); in.Active || why != msgAudWrong {
		t.Errorf("foreign audience at A: %+v %q", in, why)
	}
	// the same through a tool-call decision, which records the reason
	var allow bool
	var reason string
	e.write(func(tx *store.TenantTx) error {
		var err error
		allow, reason, _, err = e.svc.DecideToolCall(tx, testIssuer, e.resB, ToolCall{Token: tok.AccessToken, Tool: "query", RequiredScope: []string{e.shared}})
		return err
	})
	if allow || reason != msgAudWrong {
		t.Errorf("tool call with another server's token: %v %q", allow, reason)
	}
	found := false
	for _, d := range e.decisions() {
		found = found || (d.Kind == store.MCPDecisionToolCall && !d.Allow && d.Reason == msgAudWrong)
	}
	if !found {
		t.Error("the refusal is not in the decision log")
	}
	// the right server still accepts it
	if in, why := e.introspect(tok.AccessToken, e.resA); !in.Active {
		t.Errorf("A refused its own token: %q", why)
	}
}

func TestBindingRefusesMismatchedIssuer(t *testing.T) {
	e := newEnv(t)
	good := e.userToken(e.resA)
	// a token signed by the tenant's key that names another issuer
	forged := e.mint(evilIssuer, e.resA.Resource, e.resA)
	if in, why := e.introspect(forged, e.resA); in.Active || why != msgIssuerWrong {
		t.Errorf("foreign issuer: %+v %q", in, why)
	}
	// the resource is now bound to another authorization server: its existing
	// token (issued by this one) is refused, and no new token is issued for it
	e.bind(e.resA, "https://other-as.example/", e.resA.Resource)
	if in, why := e.introspect(good.AccessToken, e.resA); in.Active || why != msgIssuerWrong {
		t.Errorf("token of another issuer than the binding: %+v %q", in, why)
	}
	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		var err error
		_, _, oe, err = e.svc.BeginAuthorization(tx, e.graph(), NewAuthRequest{Issuer: testIssuer, Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		return err
	})
	if oe == nil || oe.Code != "invalid_target" || oe.Desc != msgIssuerBound {
		t.Errorf("authorization for a resource bound elsewhere: %+v", oe)
	}
	if n := len(e.audit(ActionIssuerMismatch)); n != 1 {
		t.Errorf("%d issuer-mismatch denials audited, want 1", n)
	}
	// the other resource is unaffected
	if tok := e.userToken(e.resB); tok.AccessToken == "" {
		t.Error("B lost its token")
	}
}

func TestBindingBlocksRedeemAndExchangeForOtherIssuer(t *testing.T) {
	e := newEnv(t)
	code, _ := e.authorize(e.resA.Resource, e.shared)
	e.bind(e.resA, "https://other-as.example/", e.resA.Resource) // bound after the user approved
	if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil || oe.Desc != msgIssuerBound {
		t.Errorf("redeem: %+v", oe)
	}
	// token exchange towards a resource bound to another authorization server
	user := e.userToken(e.resB)
	actor := e.actorToken(actorOpts{})
	if _, oe := e.exchange(user.AccessToken, actor, e.resA, e.shared); oe == nil || oe.Desc != msgIssuerBound {
		t.Errorf("exchange: %+v", oe)
	}
}

func TestUnregisteredServerIsBlockedByPolicy(t *testing.T) {
	e := newEnv(t)
	unknown := &store.MCPResource{ID: "x", Resource: "https://rogue.example/mcp"}
	user := e.userToken(e.resB)
	actor := e.actorToken(actorOpts{})

	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		var err error
		_, _, oe, err = e.svc.BeginAuthorization(tx, e.graph(), NewAuthRequest{Issuer: testIssuer, Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: unknown.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		return err
	})
	if oe == nil || oe.Code != "invalid_target" || !strings.Contains(oe.Desc, "blocked by policy") {
		t.Errorf("authorize: %+v", oe)
	}
	if _, oe := e.exchange(user.AccessToken, actor, unknown, e.shared); oe == nil || !strings.Contains(oe.Desc, "blocked by policy") {
		t.Errorf("exchange: %+v", oe)
	}
	// a disabled server is just as unusable
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPResourceStatus(e.resA.ID, "disabled") })
	if _, oe := e.exchange(user.AccessToken, actor, e.resA, e.shared); oe == nil || !strings.Contains(oe.Desc, "blocked by policy") {
		t.Errorf("disabled: %+v", oe)
	}
	evs := e.audit(ActionUnregistered)
	if len(evs) != 3 {
		t.Fatalf("%d policy denials audited, want 3", len(evs))
	}
	denied := 0
	for _, d := range e.decisions() {
		if !d.Allow && strings.Contains(d.Reason, "blocked by policy") {
			denied++
		}
	}
	if denied != 3 {
		t.Errorf("%d policy denials in the decision log, want 3", denied)
	}
	// no token was issued for any of them
	e.read(func(tx *store.TenantTx) error {
		ts, err := tx.MCPTokens()
		for _, x := range ts {
			if x.Audience == unknown.Resource || (x.Audience == e.resA.Resource && x.GrantType == "token_exchange") {
				t.Errorf("a token was issued for %s", x.Audience)
			}
		}
		return err
	})
}

func TestValidateBinding(t *testing.T) {
	for _, tc := range []struct {
		name, iss, aud string
		ok             bool
	}{
		{"https pair", "https://as.example/t/x/mcp", "https://mcp.example/api", true},
		{"loopback http", "http://127.0.0.1:8000/t/x/mcp", "http://127.0.0.1:9000/mcp", true},
		{"issuer not a URL", "as.example", "https://mcp.example/api", false},
		{"issuer http", "http://as.example/", "https://mcp.example/api", false},
		{"issuer with a query", "https://as.example/?x=1", "https://mcp.example/api", false},
		{"issuer with a fragment", "https://as.example/#x", "https://mcp.example/api", false},
		{"audience with a space", "https://as.example/", "https://mcp.example/a b", false},
		{"audience not a URI", "https://as.example/", "mcp-a", false},
		{"empty", "", "", false},
	} {
		if err := ValidateBinding(tc.iss, tc.aud); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
