package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t)
	// the task asks for more than the agent may hold: the grant is narrowed
	code, granted := e.authorize(e.resA.Resource, e.shared, e.alone)
	if !slices.Equal(granted, []string{e.shared}) {
		t.Fatalf("granted = %v, want only %s", granted, e.shared)
	}
	resp, oe := e.redeem(e.codeReq(code, e.resA))
	if oe != nil {
		t.Fatalf("redeem: %+v", oe)
	}
	if resp.TokenType != "Bearer" || resp.Scope != e.shared || resp.ExpiresIn <= 0 || resp.ExpiresIn > 300 {
		t.Errorf("response = %+v", resp)
	}
	c := e.claims(resp.AccessToken)
	if c.Audience[0] != e.resA.Resource || len(c.Audience) != 1 {
		t.Errorf("aud = %v, want pinned to the resource indicator", c.Audience)
	}
	if c.Subject != SubjectOf(e.alice) || c.Act == nil || c.Act.Sub != SubjectOf(e.bot) || c.Act.ClientID != e.client.ClientID || c.Act.Act != nil {
		t.Errorf("sub/act = %s / %+v", c.Subject, c.Act)
	}
	if _, err := uuid.Parse(c.ID); err != nil {
		t.Errorf("jti %q is not a uuid", c.ID)
	}
	if d := c.Expiry.Time().Sub(c.IssuedAt.Time()); d > MaxTTL || d <= 0 {
		t.Errorf("lifetime %v", d)
	}
	if c.PolicyVersion != testPolicy || c.ClientID != e.client.ClientID {
		t.Errorf("claims = %+v", c)
	}
	row := e.tokenRow(c.ID)
	if row.RevokedAt != nil || row.Audience != e.resA.Resource || row.GrantType != "authorization_code" || row.PolicyVersion != testPolicy {
		t.Errorf("row = %+v", row)
	}
	// the issue is in the decision log and the audit ledger, with the policy version
	ds := e.decisions()
	if len(ds) == 0 || ds[0].Kind != store.MCPDecisionIssue || !ds[0].Allow || ds[0].PolicyVersion != testPolicy || ds[0].JTI != c.ID ||
		ds[0].GrantedScope != e.shared {
		t.Errorf("decision = %+v", ds)
	}
	evs := e.audit("mcp.token.issue")
	if len(evs) != 1 || evs[0].PolicyVersion == nil || *evs[0].PolicyVersion != testPolicy {
		t.Errorf("audit = %+v", evs)
	}
	// replaying the code fails
	if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil || oe.Code != "invalid_grant" {
		t.Errorf("replayed code = %+v", oe)
	}
}

func TestAuthorizationCodeRefusals(t *testing.T) {
	cases := []struct {
		name string
		do   func(e *env, code string) CodeRequest
		want string
	}{
		{"wrong verifier", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.Verifier = strings.Repeat("a", 43)
			return r
		}, "invalid_grant"},
		{"malformed verifier", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.Verifier = "short"
			return r
		}, "invalid_request"},
		{"no verifier", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.Verifier = ""
			return r
		}, "invalid_request"},
		{"other redirect uri", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.RedirectURI = "https://evil.example/cb"
			return r
		}, "invalid_grant"},
		{"other resource", func(e *env, c string) CodeRequest { return e.codeReq(c, e.resB) }, "invalid_target"},
		{"no resource", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.Resource = ""
			return r
		}, "invalid_request"},
		{"other client", func(e *env, c string) CodeRequest {
			r := e.codeReq(c, e.resA)
			r.ClientID = "https://other.example/meta.json"
			return r
		}, "invalid_client"},
		{"unknown code", func(e *env, c string) CodeRequest { return e.codeReq("nope", e.resA) }, "invalid_grant"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			code, _ := e.authorize(e.resA.Resource, e.shared)
			if resp, oe := e.redeem(c.do(e, code)); resp != nil || oe == nil || oe.Code != c.want {
				t.Fatalf("redeem = %+v, %+v; want %s", resp, oe, c.want)
			}
			if len(e.audit("mcp.token.issue")) != 0 {
				t.Error("a token was issued")
			}
			if evs := e.audit("mcp.token.deny"); len(evs) != 1 || evs[0].Outcome != store.OutcomeFailure {
				t.Errorf("the denial was not audited: %+v", evs)
			}
			// a failed attempt on a real code burns it
			if c.name != "unknown code" && c.name != "other client" && c.name != "malformed verifier" && c.name != "no verifier" &&
				c.name != "no resource" {
				if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil {
					t.Error("the code survived a failed attempt")
				}
			}
		})
	}
	t.Run("expired code", func(t *testing.T) {
		e := newEnv(t)
		code, _ := e.authorize(e.resA.Resource, e.shared)
		e.now = e.now.Add(CodeTTL + time.Second)
		if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("redeem = %+v", oe)
		}
	})
	t.Run("client disabled after the approval", func(t *testing.T) {
		e := newEnv(t)
		code, _ := e.authorize(e.resA.Resource, e.shared)
		e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(e.client.ClientID, &e.bot, "disabled", e.now) })
		if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil || oe.Code != "invalid_client" {
			t.Errorf("redeem = %+v", oe)
		}
	})
	t.Run("delegation ended after the approval", func(t *testing.T) {
		e := newEnv(t)
		code, _ := e.authorize(e.resA.Resource, e.shared)
		e.write(func(tx *store.TenantTx) error { _, err := tx.DeleteAgentDelegations(); return err })
		if _, oe := e.redeem(e.codeReq(code, e.resA)); oe == nil || oe.Code != "access_denied" {
			t.Errorf("redeem = %+v", oe)
		}
	})
}

func TestAuthorizationRequestRefusals(t *testing.T) {
	e := newEnv(t)
	try := func(mod func(in *NewAuthRequest)) *OAuthError {
		var oe *OAuthError
		e.write(func(tx *store.TenantTx) error {
			g, err := graphOf(tx, e)
			if err != nil {
				return err
			}
			in := NewAuthRequest{Issuer: testIssuer, Client: e.client, RedirectURI: testRedirect, CodeChallenge: ChallengeS256(testVerif),
				Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice}
			mod(&in)
			_, _, oe, err = e.svc.BeginAuthorization(tx, g, in)
			return err
		})
		return oe
	}
	if oe := try(func(*NewAuthRequest) {}); oe != nil {
		t.Fatalf("valid request refused: %+v", oe)
	}
	for name, c := range map[string]struct {
		mod  func(in *NewAuthRequest)
		want string
	}{
		"unregistered resource":   {func(in *NewAuthRequest) { in.Resource = "https://unknown.example/mcp" }, "invalid_target"},
		"nothing the agent holds": {func(in *NewAuthRequest) { in.Scope = []string{e.alone} }, "invalid_scope"},
		"unknown user":            {func(in *NewAuthRequest) { in.UserIdentity = 424242 }, "access_denied"},
		"the agent as the user":   {func(in *NewAuthRequest) { in.UserIdentity = e.bot }, "access_denied"},
		"pending client": {func(in *NewAuthRequest) {
			c := *e.client
			c.Status = "pending"
			in.Client = &c
		}, "unauthorized_client"},
		"unbound client": {func(in *NewAuthRequest) {
			c := *e.client
			c.AgentIdentityID = nil
			in.Client = &c
		}, "unauthorized_client"},
	} {
		if oe := try(c.mod); oe == nil || oe.Code != c.want {
			t.Errorf("%s: %+v, want %s", name, oe, c.want)
		}
	}
	if n := len(e.audit("mcp.authorize.deny")); n != 5 {
		t.Errorf("%d authorize denials audited, want 5", n)
	}
	if n := len(e.audit(ActionUnregistered)); n != 1 { // the unregistered resource is a policy denial (#479)
		t.Errorf("%d unregistered-server denials audited, want 1", n)
	}
	// a disabled resource is unusable
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPResourceStatus(e.resA.ID, "disabled") })
	if oe := try(func(*NewAuthRequest) {}); oe == nil || oe.Code != "invalid_target" {
		t.Errorf("disabled resource: %+v", oe)
	}
}

func TestTokenLifetimeIsCapped(t *testing.T) {
	e := newEnv(t)
	e.svc.TTL = time.Hour
	if r := e.userToken(e.resA); r.ExpiresIn != int(MaxTTL/time.Second) {
		t.Errorf("expires_in = %d with a 1h setting, want 300", r.ExpiresIn)
	}
	e.svc.TTL = time.Minute
	if r := e.userToken(e.resA); r.ExpiresIn != 60 {
		t.Errorf("expires_in = %d, want 60", r.ExpiresIn)
	}
	// an expired token no longer verifies
	r := e.userToken(e.resA)
	e.now = e.now.Add(time.Minute + time.Second)
	e.read(func(tx *store.TenantTx) error {
		if _, err := Verify(tx, r.AccessToken, testIssuer, e.now); err != ErrTokenExpired {
			t.Errorf("Verify after expiry = %v", err)
		}
		return nil
	})
}

func TestVerifyRejects(t *testing.T) {
	e := newEnv(t)
	good := e.userToken(e.resA).AccessToken
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(good, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	e.read(func(tx *store.TenantTx) error {
		c, err := Verify(tx, good, testIssuer, e.now)
		if err != nil {
			t.Fatal(err)
		}
		// the tenant's own kid, but signed by someone else's key
		forged := forge(t, foreign, "at+jwt", kid, *c)
		wrongTyp := forge(t, foreign, "JWT", kid, *c)
		for name, tok := range map[string]string{"empty": "", "garbage": "a.b.c", "foreign key": forged, "wrong typ": wrongTyp,
			"truncated": good[:len(good)-4], "huge": strings.Repeat("a", MaxTokenBytes+1)} {
			if _, err := Verify(tx, tok, testIssuer, e.now); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		if _, err := Verify(tx, good, "https://tessera.example/t/other", e.now); err == nil {
			t.Error("a token for another issuer was accepted")
		}
		return nil
	})
}

// ---------------------------------------------------------------- token exchange

func TestExchange(t *testing.T) {
	e := newEnv(t)
	user := e.userToken(e.resA)
	resp, oe := e.exchange(user.AccessToken, e.actorToken(actorOpts{}), e.resA, e.shared+" "+e.alone)
	if oe != nil {
		t.Fatalf("exchange: %+v", oe)
	}
	if resp.Scope != e.shared || resp.IssuedTokenType != TypeAccessToken || resp.ExpiresIn > 300 {
		t.Errorf("response = %+v", resp)
	}
	c := e.claims(resp.AccessToken)
	if c.Audience[0] != e.resA.Resource || c.Subject != SubjectOf(e.alice) || c.Act == nil || c.Act.Sub != SubjectOf(e.bot) {
		t.Errorf("claims = %+v act %+v", c, c.Act)
	}
	if c.Act.Act != nil {
		t.Errorf("the same agent re-exchanging must not nest itself: %+v", c.Act)
	}
	if row := e.tokenRow(c.ID); row.GrantType != "token_exchange" || row.Audience != e.resA.Resource {
		t.Errorf("row = %+v", row)
	}
	if ds := e.decisions(); ds[0].Kind != store.MCPDecisionExchange || !ds[0].Allow || ds[0].PolicyVersion != testPolicy ||
		ds[0].RequestedScope != e.shared+" "+e.alone || ds[0].GrantedScope != e.shared {
		t.Errorf("decision = %+v", ds[0])
	}
	if evs := e.audit("mcp.token.exchange"); len(evs) != 1 || *evs[0].PolicyVersion != testPolicy {
		t.Errorf("audit = %+v", evs)
	}
	// no refresh token exists in the response type at all
	if strings.Contains(strings.ToLower(resp.AccessToken), "refresh") {
		t.Error("refresh in the token")
	}
}

func TestExchangeNeverWidensOrAcceptsEmpty(t *testing.T) {
	e := newEnv(t)
	user := e.userToken(e.resA)
	for name, scope := range map[string]string{
		"only what the user alone holds": e.alone,
		"nothing real":                   "x:y:z",
		"two things neither holds":       e.alone + " x:y:z",
	} {
		resp, oe := e.exchange(user.AccessToken, e.actorToken(actorOpts{}), e.resA, scope)
		if resp != nil || oe == nil || oe.Code != "access_denied" {
			t.Errorf("%s: %+v, %+v", name, resp, oe)
		}
	}
	if _, oe := e.exchange(user.AccessToken, e.actorToken(actorOpts{}), e.resA, ""); oe == nil || oe.Code != "invalid_scope" {
		t.Errorf("no scope: %+v", oe)
	}
	// the subject token's own scope is a ceiling: a token that only carried the
	// user's private scope cannot be exchanged for the shared one
	row := e.craftSubject(e.alice, []string{e.alone}, nil, e.resA)
	if _, oe := e.exchange(row, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "access_denied" {
		t.Errorf("exchange widened an upstream scope: %+v", oe)
	}
	if n := len(e.audit("mcp.token.deny")); n != 5 {
		t.Errorf("%d denials audited, want 5", n)
	}
	for _, d := range e.decisions() {
		if d.Allow && d.Kind == store.MCPDecisionExchange {
			t.Errorf("an exchange was allowed: %+v", d)
		}
	}
}

// craftSubject mints a subject token (signed with the tenant key) and records
// it as issued, for chain and scope cases the flow cannot produce.
func (e *env) craftSubject(user int64, scope []string, act *Actor, res *store.MCPResource) string {
	e.t.Helper()
	var raw string
	e.write(func(tx *store.TenantTx) error {
		jti := uuid.NewString()
		cid := e.client.ClientID
		if e.craftClient != "" {
			cid = e.craftClient
		}
		c := Claims{Issuer: testIssuer, Subject: SubjectOf(user), Audience: jwt.Audience{res.Resource},
			Expiry: jwt.NewNumericDate(e.now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(e.now), ID: jti,
			Scope: JoinScope(scope), ClientID: cid, Act: act, PolicyVersion: testPolicy}
		var err error
		if raw, err = Mint(tx, e.svc.Sealer, c); err != nil {
			return err
		}
		return tx.InsertMCPToken(&store.MCPToken{JTI: jti, ClientID: c.ClientID, SubjectID: user, AgentID: e.bot, Audience: res.Resource,
			Scope: c.Scope, Act: actJSON(act), GrantType: "authorization_code", PolicyVersion: testPolicy, IssuedAt: e.now,
			ExpiresAt: e.now.Add(time.Minute)})
	})
	return raw
}

func TestExchangeActChain(t *testing.T) {
	e := newEnv(t)
	other := SubjectOf(e.alice + 1000)
	other2, other3 := SubjectOf(e.alice+1001), SubjectOf(e.alice+1002)
	t.Run("a sub-agent nests the chain", func(t *testing.T) {
		subj := e.craftSubject(e.alice, []string{e.shared}, &Actor{Sub: other}, e.resA)
		resp, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared)
		if oe != nil {
			t.Fatalf("exchange: %+v", oe)
		}
		c := e.claims(resp.AccessToken)
		if c.Act.Sub != SubjectOf(e.bot) || c.Act.Act == nil || c.Act.Act.Sub != other || c.Act.Depth() != 2 {
			t.Errorf("act = %+v", c.Act)
		}
	})
	t.Run("the chain is bounded", func(t *testing.T) {
		chain := &Actor{Sub: other, Act: &Actor{Sub: other2, Act: &Actor{Sub: other3}}} // depth 3: the bot would be the 4th
		subj := e.craftSubject(e.alice, []string{e.shared}, chain, e.resA)
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "access_denied" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("a subject token that is already too deep is not valid", func(t *testing.T) {
		chain := &Actor{Sub: other, Act: &Actor{Sub: other2, Act: &Actor{Sub: other3, Act: &Actor{Sub: "identity:9"}}}}
		subj := e.craftSubject(e.alice, []string{e.shared}, chain, e.resA)
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("an agent already deeper in the chain is a cycle", func(t *testing.T) {
		chain := &Actor{Sub: other, Act: &Actor{Sub: SubjectOf(e.bot)}}
		subj := e.craftSubject(e.alice, []string{e.shared}, chain, e.resA)
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "access_denied" {
			t.Errorf("exchange = %+v", oe)
		}
	})
}

func TestExchangeValidatesBothTokens(t *testing.T) {
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		name string
		mod  func(e *env, in *ExchangeRequest)
		want string
	}
	cases := []tc{
		{"no subject token", func(e *env, in *ExchangeRequest) { in.SubjectToken = "" }, "invalid_request"},
		{"no actor token", func(e *env, in *ExchangeRequest) { in.ActorToken = "" }, "invalid_request"},
		{"wrong subject token type", func(e *env, in *ExchangeRequest) { in.SubjectTokenType = TypeJWT }, "invalid_request"},
		{"wrong actor token type", func(e *env, in *ExchangeRequest) { in.ActorTokenType = TypeAccessToken }, "invalid_request"},
		{"garbage subject token", func(e *env, in *ExchangeRequest) { in.SubjectToken = "a.b.c" }, "invalid_grant"},
		{"garbage actor token", func(e *env, in *ExchangeRequest) { in.ActorToken = "a.b.c" }, "invalid_client"},
		{"actor signed by another key", func(e *env, in *ExchangeRequest) { in.ActorToken = e.actorToken(actorOpts{key: foreign}) }, "invalid_client"},
		{"actor with an unknown kid", func(e *env, in *ExchangeRequest) { in.ActorToken = e.actorToken(actorOpts{kid: "zz"}) }, "invalid_client"},
		{"actor of an unknown client", func(e *env, in *ExchangeRequest) {
			in.ActorToken = e.actorToken(actorOpts{iss: "https://nobody.example/meta.json"})
		}, "invalid_client"},
		{"actor sub differs from iss", func(e *env, in *ExchangeRequest) {
			in.ActorToken = e.actorToken(actorOpts{sub: "https://other.example/meta.json"})
		}, "invalid_client"},
		{"actor for another audience", func(e *env, in *ExchangeRequest) {
			in.ActorToken = e.actorToken(actorOpts{aud: "https://elsewhere.example"})
		}, "invalid_client"},
		{"actor that already expired", func(e *env, in *ExchangeRequest) { in.ActorToken = e.actorToken(actorOpts{ttl: -time.Second}) }, "invalid_client"},
		{"actor that lives too long", func(e *env, in *ExchangeRequest) { in.ActorToken = e.actorToken(actorOpts{ttl: 10 * time.Minute}) }, "invalid_client"},
		{"actor without a jti", func(e *env, in *ExchangeRequest) { in.ActorToken = e.actorToken(actorOpts{noJTI: true}) }, "invalid_client"},
		{"another subject token as the actor", func(e *env, in *ExchangeRequest) { in.ActorToken = in.SubjectToken }, "invalid_client"},
		{"no resource", func(e *env, in *ExchangeRequest) { in.Resource = "" }, "invalid_target"},
		{"unregistered resource", func(e *env, in *ExchangeRequest) { in.Resource = "https://unknown.example/mcp" }, "invalid_target"},
		{"relative resource", func(e *env, in *ExchangeRequest) { in.Resource = "/mcp" }, "invalid_target"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			in := ExchangeRequest{SubjectToken: e.userToken(e.resA).AccessToken, SubjectTokenType: TypeAccessToken,
				ActorToken: e.actorToken(actorOpts{}), ActorTokenType: TypeJWT, Resource: e.resA.Resource, Scope: e.shared}
			c.mod(e, &in)
			if resp, oe := e.exchangeReq(in); resp != nil || oe == nil || oe.Code != c.want {
				t.Fatalf("exchange = %+v, %+v; want %s", resp, oe, c.want)
			}
		})
	}
	t.Run("a replayed actor assertion", func(t *testing.T) {
		e := newEnv(t)
		subj, act := e.userToken(e.resA).AccessToken, e.actorToken(actorOpts{})
		if _, oe := e.exchange(subj, act, e.resA, e.shared); oe != nil {
			t.Fatalf("first use: %+v", oe)
		}
		if _, oe := e.exchange(subj, act, e.resA, e.shared); oe == nil || oe.Code != "invalid_client" {
			t.Errorf("replay = %+v", oe)
		}
	})
	t.Run("expired subject token", func(t *testing.T) {
		e := newEnv(t)
		subj := e.userToken(e.resA).AccessToken
		e.now = e.now.Add(6 * time.Minute)
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("revoked subject token", func(t *testing.T) {
		e := newEnv(t)
		r := e.userToken(e.resA)
		jti := e.claims(r.AccessToken).ID
		e.write(func(tx *store.TenantTx) error { return e.svc.RevokeToken(tx, jti, "test") })
		if _, oe := e.exchange(r.AccessToken, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("subject token of another tenant's issuer", func(t *testing.T) {
		e := newEnv(t)
		subj := e.userToken(e.resA).AccessToken
		var resp *TokenResponse
		var oe *OAuthError
		e.write(func(tx *store.TenantTx) error {
			g, err := graphOf(tx, e)
			if err != nil {
				return err
			}
			resp, oe, err = e.svc.Exchange(tx, g, "https://tessera.example/t/other", ExchangeRequest{SubjectToken: subj,
				SubjectTokenType: TypeAccessToken, ActorToken: e.actorToken(actorOpts{aud: "https://tessera.example/t/other"}),
				ActorTokenType: TypeJWT, Resource: e.resA.Resource, Scope: e.shared})
			return err
		})
		if resp != nil || oe == nil {
			t.Errorf("exchange = %+v, %+v", resp, oe)
		}
	})
	t.Run("the delegation ended", func(t *testing.T) {
		e := newEnv(t)
		subj := e.userToken(e.resA).AccessToken
		e.write(func(tx *store.TenantTx) error { _, err := tx.DeleteAgentDelegations(); return err })
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "access_denied" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("the client is disabled", func(t *testing.T) {
		e := newEnv(t)
		subj := e.userToken(e.resA).AccessToken
		e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(e.client.ClientID, &e.bot, "disabled", e.now) })
		// the subject token's own client is the disabled one, so that check answers first
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("exchange = %+v", oe)
		}
	})
	t.Run("the user left", func(t *testing.T) {
		e := newEnv(t)
		subj := e.userToken(e.resA).AccessToken
		e.write(func(tx *store.TenantTx) error { return tx.TerminateIdentity(e.alice, e.now) })
		if _, oe := e.exchange(subj, e.actorToken(actorOpts{}), e.resA, e.shared); oe == nil || oe.Code != "invalid_grant" {
			t.Errorf("exchange = %+v", oe)
		}
	})
}

// ---------------------------------------------------------------- introspection, decisions, kill switch

func TestIntrospectAndToolCalls(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA).AccessToken
	if in, why := e.introspect(tok, e.resA); !in.Active || in.Aud != e.resA.Resource || in.Act == nil || in.Scope != e.shared {
		t.Fatalf("introspect = %+v %s", in, why)
	}
	if in, _ := e.introspect(tok, e.resB); in.Active {
		t.Error("a token for resource A was active for resource B")
	}
	if in, _ := e.introspect("garbage", e.resA); in.Active {
		t.Error("garbage was active")
	}
	call := func(tool string, need ...string) (bool, string) {
		var ok bool
		var reason string
		e.write(func(tx *store.TenantTx) error {
			var err error
			ok, reason, _, err = e.svc.DecideToolCall(tx, testIssuer, e.resA, ToolCall{Token: tok, Tool: tool, RequiredScope: need})
			return err
		})
		return ok, reason
	}
	if ok, why := call("query", e.shared); !ok {
		t.Errorf("covered call denied: %s", why)
	}
	for name, c := range map[string]struct {
		tool string
		need []string
	}{
		"a scope the token lacks":     {"export", []string{e.alone}},
		"one covered, one not":        {"mixed", []string{e.shared, e.alone}},
		"a tool naming no scope":      {"bare", nil},
		"no tool name":                {"", []string{e.shared}},
		"a scope that does not exist": {"ghost", []string{"x:y:z"}},
	} {
		if ok, _ := call(c.tool, c.need...); ok {
			t.Errorf("%s was allowed", name)
		}
	}
	ds := e.decisions()
	n := 0
	for _, d := range ds {
		if d.Kind == store.MCPDecisionToolCall {
			n++
			if d.PolicyVersion != testPolicy || d.Resource != e.resA.Resource {
				t.Errorf("tool decision = %+v", d)
			}
		}
	}
	if n != 6 || len(e.audit("mcp.tool_call.decision")) != 6 {
		t.Errorf("%d tool-call decisions logged, %d audited; want 6 each", n, len(e.audit("mcp.tool_call.decision")))
	}
	// a token for another audience is refused as a tool-call token, too
	var ok bool
	e.write(func(tx *store.TenantTx) error {
		var err error
		ok, _, _, err = e.svc.DecideToolCall(tx, testIssuer, e.resB, ToolCall{Token: tok, Tool: "query", RequiredScope: []string{e.shared}})
		return err
	})
	if ok {
		t.Error("a token was accepted at the wrong resource server")
	}
}

func TestKillSwitchRevokesAllAgentTokens(t *testing.T) {
	e := newEnv(t)
	a := e.userToken(e.resA).AccessToken
	b := e.userToken(e.resB).AccessToken
	x, oe := e.exchange(b, e.actorToken(actorOpts{}), e.resB, e.shared)
	if oe != nil {
		t.Fatal(oe)
	}
	for _, tok := range []string{a, b, x.AccessToken} {
		res := e.resA
		if tok != a {
			res = e.resB
		}
		if in, why := e.introspect(tok, res); !in.Active {
			t.Fatalf("token inactive before the kill switch: %s", why)
		}
	}
	var n int64
	e.write(func(tx *store.TenantTx) error {
		var err error
		n, err = e.svc.RevokeIdentity(tx, e.bot, "kill switch (agent)")
		return err
	})
	if n != 3 {
		t.Fatalf("revoked %d tokens, want 3", n)
	}
	for _, tok := range []string{a, b, x.AccessToken} {
		res := e.resA
		if tok != a {
			res = e.resB
		}
		if in, why := e.introspect(tok, res); in.Active || why != "token is revoked" {
			t.Errorf("token still active after the kill switch: %+v %s", in, why)
		}
	}
	// the revoked tokens cannot be exchanged or used for a tool call
	if _, oe := e.exchange(a, e.actorToken(actorOpts{}), e.resB, e.shared); oe == nil || oe.Code != "invalid_grant" {
		t.Errorf("exchange of a revoked token = %+v", oe)
	}
	if evs := e.audit("mcp.tokens.revoke_identity"); len(evs) != 1 {
		t.Errorf("revoke audited %d times", len(evs))
	}
	// nothing left to revoke: no second event
	e.write(func(tx *store.TenantTx) error {
		var err error
		n, err = e.svc.RevokeIdentity(tx, e.bot, "again")
		return err
	})
	if n != 0 || len(e.audit("mcp.tokens.revoke_identity")) != 1 {
		t.Errorf("second kill switch revoked %d", n)
	}
	// the agent's own account being contained also blocks new tokens
	e.write(func(tx *store.TenantTx) error { return tx.TerminateIdentity(e.bot, e.now) })
	var oe2 *OAuthError
	e.write(func(tx *store.TenantTx) error {
		g, err := graphOf(tx, e)
		if err != nil {
			return err
		}
		_, _, oe2, err = e.svc.BeginAuthorization(tx, g, NewAuthRequest{Client: e.client, RedirectURI: testRedirect,
			CodeChallenge: ChallengeS256(testVerif), Resource: e.resA.Resource, Scope: []string{e.shared}, UserIdentity: e.alice})
		return err
	})
	if oe2 == nil {
		t.Error("a terminated agent got an authorization")
	}
}

func TestKillSwitchOfTheUserAlsoRevokes(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA).AccessToken
	e.write(func(tx *store.TenantTx) error {
		n, err := e.svc.RevokeIdentity(tx, e.alice, "leaver")
		if n != 1 {
			t.Errorf("revoked %d", n)
		}
		return err
	})
	if in, _ := e.introspect(tok, e.resA); in.Active {
		t.Error("a leaver's token is still active")
	}
}

func TestRevokeClientAndResource(t *testing.T) {
	e := newEnv(t)
	a := e.userToken(e.resA).AccessToken
	b := e.userToken(e.resB).AccessToken
	e.write(func(tx *store.TenantTx) error {
		n, err := e.svc.RevokeResource(tx, e.resA.Resource, "disabled")
		if n != 1 {
			t.Errorf("revoked %d for the resource", n)
		}
		return err
	})
	if in, _ := e.introspect(a, e.resA); in.Active {
		t.Error("resource A token still active")
	}
	if in, _ := e.introspect(b, e.resB); !in.Active {
		t.Error("resource B token was revoked")
	}
	e.write(func(tx *store.TenantTx) error {
		n, err := e.svc.RevokeClient(tx, e.client.ClientID, "disabled")
		if n != 1 {
			t.Errorf("revoked %d for the client", n)
		}
		return err
	})
	if in, _ := e.introspect(b, e.resB); in.Active {
		t.Error("client token still active")
	}
}

func TestIntrospectNeedsActiveClientAndAgent(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA).AccessToken
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(e.client.ClientID, &e.bot, "disabled", e.now) })
	if in, why := e.introspect(tok, e.resA); in.Active || why != "client is not active" {
		t.Errorf("disabled client: %+v %s", in, why)
	}
	e.write(func(tx *store.TenantTx) error { return tx.SetMCPClient(e.client.ClientID, &e.bot, "active", e.now) })
	if in, _ := e.introspect(tok, e.resA); !in.Active {
		t.Fatal("not active again")
	}
	// a status change that revokes nothing: the status check holds on its own
	e.write(func(tx *store.TenantTx) error { return tx.SetIdentityStatusFrom(e.bot, "active", "terminated") })
	if in, why := e.introspect(tok, e.resA); in.Active || why != "agent is not active" {
		t.Errorf("terminated agent: %+v %s", in, why)
	}
}

// ---------------------------------------------------------------- helpers

func graphOf(tx *store.TenantTx, e *env) (*graph.Snapshot, error) { return graph.Build(tx, e.now) }

// forge signs c with key under a JOSE typ and kid.
func forge(t *testing.T, key *ecdsa.PrivateKey, typ, kid string, c Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestIdentityEndedRevokesMCPTokens: every path that ends an identity (leaver
// or lifecycle end, a sync that writes a non-active status, a containment
// disable) revokes the MCP tokens it holds as user or as agent, in the
// transaction that ends it.
func TestIdentityEndedRevokesMCPTokens(t *testing.T) {
	ends := []struct {
		name   string
		reason string
		end    func(e *env, tx *store.TenantTx, id int64) error
	}{
		{"terminate", store.RevokedIdentityTerminated, func(e *env, tx *store.TenantTx, id int64) error {
			return tx.TerminateIdentity(id, e.now)
		}},
		{"sync terminated", store.RevokedIdentityTerminated, func(e *env, tx *store.TenantTx, id int64) error {
			i, err := tx.Identity(id)
			if err != nil {
				return err
			}
			i.Status = "terminated"
			return tx.UpsertIdentity(i)
		}},
		{"sync disabled", auth.RevokedIdentityDisabled, func(e *env, tx *store.TenantTx, id int64) error {
			i, err := tx.Identity(id)
			if err != nil {
				return err
			}
			i.Status = "disabled"
			return tx.UpsertIdentity(i)
		}},
		{"containment disable", auth.RevokedIdentityDisabled, func(e *env, tx *store.TenantTx, id int64) error {
			_, err := containment.Disable(tx, id, "admin", "test", "none", e.now)
			return err
		}},
	}
	for _, who := range []struct {
		name string
		id   func(e *env) int64
	}{{"user", func(e *env) int64 { return e.alice }}, {"agent", func(e *env) int64 { return e.bot }}} {
		for _, tc := range ends {
			t.Run(who.name+"/"+tc.name, func(t *testing.T) {
				e := newEnv(t)
				tok := e.userToken(e.resA)
				if in, why := e.introspect(tok.AccessToken, e.resA); !in.Active {
					t.Fatalf("inactive before: %s", why)
				}
				e.write(func(tx *store.TenantTx) error { return tc.end(e, tx, who.id(e)) })
				row := e.tokenRow(e.claims(tok.AccessToken).ID)
				if row.RevokedAt == nil || row.RevokedReason != tc.reason {
					t.Errorf("token row %+v, want revoked with %q", row, tc.reason)
				}
				if in, why := e.introspect(tok.AccessToken, e.resA); in.Active || why != "token is revoked" {
					t.Errorf("after: %+v %s", in, why)
				}
				if _, oe := e.exchange(tok.AccessToken, e.actorToken(actorOpts{}), e.resB, e.shared); oe == nil || oe.Code != "invalid_grant" {
					t.Errorf("exchange after = %+v", oe)
				}
			})
		}
	}
}

// TestEndedIdentityTokensRefusedWithoutRevocation: the status check holds on
// its own, for a status changed by a path that revokes nothing (#345's rule
// for CLI tokens, applied to MCP): introspection and exchange refuse.
func TestEndedIdentityTokensRefusedWithoutRevocation(t *testing.T) {
	e := newEnv(t)
	tok := e.userToken(e.resA).AccessToken
	if err := e.db.InTenant(context.Background(), e.db.Tenant, func(tx *store.TenantTx) error {
		return tx.SetIdentityStatusFrom(e.alice, "active", "disabled")
	}); err != nil {
		t.Fatal(err)
	}
	if in, why := e.introspect(tok, e.resA); in.Active || why != "user is not active" {
		t.Errorf("introspect: %+v %s", in, why)
	}
	if _, oe := e.exchange(tok, e.actorToken(actorOpts{}), e.resB, e.shared); oe == nil || oe.Code != "invalid_grant" {
		t.Errorf("exchange = %+v", oe)
	}
}
