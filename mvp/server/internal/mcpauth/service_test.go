package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const (
	testIssuer   = "https://tessera.example/t/tiny"
	testVerif    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testRedirect = "https://client.example/cb"
	testPolicy   = "pol-test"
)

// env is the tiny world plus an MCP setup: alice (a person) and helper-bot
// (an ai_agent that alice delegated to) share one permission, snowflake
// SELECT on CUSTOMERS; alice alone also holds s3 GetObject on customer-pii.
type env struct {
	t      *testing.T
	db     *testkit.DB
	svc    *Service
	now    time.Time
	alice  int64
	bot    int64
	resA   *store.MCPResource
	resB   *store.MCPResource
	client *store.MCPClient
	key    *ecdsa.PrivateKey
	shared string // the scope alice and the bot share
	alone  string // alice's own scope
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, ids := testkit.Tiny(t)
	e := &env{t: t, db: db, now: testkit.Now, alice: ids["alice"], bot: ids["helper-bot"]}
	kek := make([]byte, seal.KeySize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = &Service{Sealer: sealer, Clock: func() time.Time { return e.now }, PolicyVersion: func() string { return testPolicy }}
	if e.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &e.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	e.write(func(tx *store.TenantTx) error {
		if err := keys.EnsureKeys(tx, "tiny", sealer, e.now); err != nil {
			return err
		}
		// alice joins snowflake's PII_READER: she and the bot now share SELECT on CUSTOMERS
		if _, err := tx.InsertEdge(&store.GrantEdge{Src: graph.Key("account", ids["acct:okta:alice"]),
			Dst: graph.Key("group", ids["group:snowflake:PII_READER"]), Relation: "member_of", Source: "manual", CreatedAt: e.now}); err != nil {
			return err
		}
		for _, r := range []**store.MCPResource{&e.resA, &e.resB} {
			n := "a"
			if r == &e.resB {
				n = "b"
			}
			x := &store.MCPResource{Resource: "https://mcp-" + n + ".example/mcp", Name: "mcp " + n,
				SecretHash: seal.SHA256Hex([]byte("secret-" + n)), CreatedBy: "admin", CreatedAt: e.now}
			if err := tx.InsertMCPResource(x); err != nil {
				return err
			}
			*r = x
		}
		c := &store.MCPClient{ClientID: "https://client.example/agent.json", Name: "Agent Host",
			RedirectURIs: `["` + testRedirect + `"]`, JWKS: string(jwks), DocSHA256: strings.Repeat("0", 64), ExpiresAt: e.now.Add(100 * time.Hour)}
		if err := tx.UpsertMCPClient(c, e.now); err != nil {
			return err
		}
		if err := tx.SetMCPClient(c.ClientID, &e.bot, "active", e.now); err != nil {
			return err
		}
		var err error
		e.client, err = tx.MCPClient(c.ClientID)
		return err
	})
	g := e.graph()
	shared := Intersect(ScopesOf(g.EffectivePermissions(e.alice)), ScopesOf(g.EffectivePermissions(e.bot)))
	if len(shared) != 1 || shared[0] != "snowflake:SELECT:snowflake/CUSTOMERS" {
		t.Fatalf("shared scopes = %v", shared)
	}
	e.shared = shared[0]
	e.alone = "aws:s3:GetObject:s3://customer-pii"
	if !slices.Contains(ScopesOf(g.EffectivePermissions(e.alice)), e.alone) || slices.Contains(ScopesOf(g.EffectivePermissions(e.bot)), e.alone) {
		t.Fatalf("alice's scopes %v", ScopesOf(g.EffectivePermissions(e.alice)))
	}
	return e
}

func (e *env) write(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.db.InTenant(context.Background(), e.db.Tenant, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.db.ReadTenant(context.Background(), e.db.Tenant, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) graph() *graph.Snapshot {
	e.t.Helper()
	var g *graph.Snapshot
	e.read(func(tx *store.TenantTx) error {
		var err error
		g, err = graph.Build(tx, e.now)
		return err
	})
	return g
}

// authorize runs authorize + approve for scope and returns the code.
func (e *env) authorize(resource string, scope ...string) (string, []string) {
	e.t.Helper()
	var code string
	var granted []string
	e.write(func(tx *store.TenantTx) error {
		g, err := graph.Build(tx, e.now)
		if err != nil {
			return err
		}
		req, _, oe, err := e.svc.BeginAuthorization(tx, g, NewAuthRequest{Client: e.client, RedirectURI: testRedirect, State: "st",
			CodeChallenge: ChallengeS256(testVerif), Resource: resource, Scope: scope, UserIdentity: e.alice})
		if err != nil || oe != nil {
			e.t.Fatalf("BeginAuthorization = %v, %v", oe, err)
		}
		code, granted, oe, err = e.svc.Decide(tx, g, req, true)
		if err != nil || oe != nil {
			e.t.Fatalf("Decide = %v, %v", oe, err)
		}
		return nil
	})
	return code, granted
}

func (e *env) redeem(in CodeRequest) (*TokenResponse, *OAuthError) {
	e.t.Helper()
	var resp *TokenResponse
	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		g, err := graph.Build(tx, e.now)
		if err != nil {
			return err
		}
		resp, oe, err = e.svc.RedeemCode(tx, g, testIssuer, in)
		return err
	})
	return resp, oe
}

func (e *env) codeReq(code string, resource *store.MCPResource) CodeRequest {
	return CodeRequest{Code: code, Verifier: testVerif, ClientID: e.client.ClientID, RedirectURI: testRedirect, Resource: resource.Resource}
}

// userToken runs the whole authorization-code flow for the shared scope.
func (e *env) userToken(res *store.MCPResource) *TokenResponse {
	e.t.Helper()
	code, _ := e.authorize(res.Resource, e.shared)
	resp, oe := e.redeem(e.codeReq(code, res))
	if oe != nil {
		e.t.Fatalf("redeem: %+v", oe)
	}
	return resp
}

type actorOpts struct {
	key      *ecdsa.PrivateKey
	kid      string
	iss, sub string
	aud      string
	ttl      time.Duration
	jti      string
	noJTI    bool
}

func (e *env) actorToken(o actorOpts) string {
	e.t.Helper()
	if o.key == nil {
		o.key = e.key
	}
	if o.kid == "" {
		o.kid = "k1"
	}
	if o.iss == "" {
		o.iss = e.client.ClientID
	}
	if o.sub == "" {
		o.sub = o.iss
	}
	if o.aud == "" {
		o.aud = testIssuer
	}
	if o.ttl == 0 {
		o.ttl = time.Minute
	}
	if o.jti == "" && !o.noJTI {
		o.jti = uuid.NewString()
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: o.key, KeyID: o.kid}}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: o.iss, Subject: o.sub, Audience: jwt.Audience{o.aud},
		Expiry: jwt.NewNumericDate(e.now.Add(o.ttl)), IssuedAt: jwt.NewNumericDate(e.now), ID: o.jti}).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *env) exchange(subject, actor string, res *store.MCPResource, scope string) (*TokenResponse, *OAuthError) {
	e.t.Helper()
	return e.exchangeReq(ExchangeRequest{SubjectToken: subject, SubjectTokenType: TypeAccessToken, ActorToken: actor,
		ActorTokenType: TypeJWT, Resource: res.Resource, Scope: scope})
}

func (e *env) exchangeReq(in ExchangeRequest) (*TokenResponse, *OAuthError) {
	e.t.Helper()
	var resp *TokenResponse
	var oe *OAuthError
	e.write(func(tx *store.TenantTx) error {
		g, err := graph.Build(tx, e.now)
		if err != nil {
			return err
		}
		resp, oe, err = e.svc.Exchange(tx, g, testIssuer, in)
		return err
	})
	return resp, oe
}

func (e *env) claims(raw string) *Claims {
	e.t.Helper()
	var c *Claims
	e.read(func(tx *store.TenantTx) error {
		var err error
		c, err = Verify(tx, raw, testIssuer, e.now)
		if err != nil {
			e.t.Fatalf("Verify: %v", err)
		}
		return nil
	})
	return c
}

func (e *env) introspect(raw string, res *store.MCPResource) (*Introspection, string) {
	e.t.Helper()
	var in *Introspection
	var why string
	e.read(func(tx *store.TenantTx) error {
		var err error
		in, why, err = e.svc.Introspect(tx, testIssuer, raw, res)
		return err
	})
	return in, why
}

// auditActions lists the audit actions of the tenant, newest first, with the
// policy version of each.
func (e *env) audit(action string) []*store.AuditEvent {
	e.t.Helper()
	var out []*store.AuditEvent
	e.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.AuditEvents(store.AuditFilter{Action: action})
		return err
	})
	return out
}

func (e *env) decisions() []*store.MCPDecision {
	e.t.Helper()
	var out []*store.MCPDecision
	e.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.MCPDecisions(500)
		return err
	})
	return out
}

func (e *env) tokenRow(jti string) *store.MCPToken {
	e.t.Helper()
	var row *store.MCPToken
	e.read(func(tx *store.TenantTx) error {
		var err error
		row, err = tx.MCPToken(jti)
		return err
	})
	return row
}

// ---------------------------------------------------------------- the intersection

func TestEffective(t *testing.T) {
	e := newEnv(t)
	g := e.graph()
	var carol, bob int64
	e.read(func(tx *store.TenantTx) error {
		ids, _, err := tx.IdentityMap()
		for id, i := range ids {
			switch i.ExternalID {
			case "carol":
				carol = id
			case "bob":
				bob = id
			}
		}
		return err
	})
	cases := []struct {
		name        string
		user, agent int64
		task        []string
		narrow      [][]string
		want        []string
	}{
		{"shared permission, exact task", e.alice, e.bot, []string{e.shared}, nil, []string{e.shared}},
		{"task wider than the agent: the agent is the ceiling", e.alice, e.bot, []string{e.shared, e.alone}, nil, []string{e.shared}},
		{"task only what the agent lacks", e.alice, e.bot, []string{e.alone}, nil, nil},
		{"task names nothing real", e.alice, e.bot, []string{"x:y:z"}, nil, nil},
		{"empty task", e.alice, e.bot, nil, nil, nil},
		{"user lacks what the agent holds", carol, e.bot, []string{e.shared}, nil, nil},
		{"agent lacks what the user holds", e.alice, bob, []string{e.alone}, nil, nil},
		{"unknown agent", e.alice, 987654, []string{e.shared}, nil, nil},
		{"unknown user", 987654, e.bot, []string{e.shared}, nil, nil},
		{"an upstream scope narrows it", e.alice, e.bot, []string{e.shared}, [][]string{{e.alone}}, nil},
		{"an upstream scope that covers it keeps it", e.alice, e.bot, []string{e.shared}, [][]string{{e.shared, e.alone}}, []string{e.shared}},
		{"an empty upstream scope removes everything", e.alice, e.bot, []string{e.shared}, [][]string{{}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Effective(g, c.user, c.agent, c.task, c.narrow...)
			if !slices.Equal(got, c.want) {
				t.Errorf("Effective = %v, want %v", got, c.want)
			}
			// whatever the inputs, nothing outside the user's and the agent's own scopes appears
			ours, theirs := ScopesOf(g.EffectivePermissions(c.user)), ScopesOf(g.EffectivePermissions(c.agent))
			if !Subset(got, ours) || !Subset(got, theirs) || !Subset(got, c.task) {
				t.Errorf("Effective %v is not within user %v, agent %v and task %v", got, ours, theirs, c.task)
			}
		})
	}
}
