package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

const fedPublicURL = "https://tessera.example.com"

type fedEnv struct {
	f    *storetest.Fixture
	svc  *Service
	seal *seal.Sealer
}

// newFedEnv has signing keys for both tenants and a federated service.
func newFedEnv(t *testing.T, r *awsreplay.Replay) *fedEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	sl := testSealer(t)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return keys.EnsureKeys(c, tn.Slug, sl, testNow)
		}); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Service{Sealer: sl, Client: testClient(r, nil), CatalogVersion: "2026-10-08-0123456789abcdef",
		Clock:      func() time.Time { return testNow },
		Federation: &Federation{DB: f.DB, Sealer: sl, PublicURL: fedPublicURL, Clock: func() time.Time { return testNow }}}
	return &fedEnv{f: f, svc: svc, seal: sl}
}

func (e *fedEnv) create(t *testing.T, tn storetest.Tenant, name string) *store.AWSConnector {
	t.Helper()
	var k *store.AWSConnector
	if err := e.f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
		k, err = e.svc.CreateConnector(c, CreateInput{Name: name, Config: *orgConfig()}, "admin", testNow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return k
}

func (e *fedEnv) jwks(t *testing.T, tn storetest.Tenant) *jose.JSONWebKeySet {
	t.Helper()
	var set *jose.JSONWebKeySet
	if err := e.f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
		set, err = keys.JWKSFor(c, store.KeyPurposeAWSFederation, testNow, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return set
}

type fedClaims struct {
	Issuer, Subject string
	Audience        jwt.Audience
	IssuedAt        *jwt.NumericDate `json:"iat"`
	NotBefore       *jwt.NumericDate `json:"nbf"`
	Expiry          *jwt.NumericDate `json:"exp"`
	JTI             string           `json:"jti"`
}

// verify checks tok against set and returns its claims.
func verify(t *testing.T, tok string, set *jose.JSONWebKeySet) (fedClaims, error) {
	t.Helper()
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	ks := set.Key(kid)
	if len(ks) == 0 {
		return fedClaims{}, errors.New("kid not in the JWKS")
	}
	var raw struct {
		Iss string           `json:"iss"`
		Sub string           `json:"sub"`
		Aud jwt.Audience     `json:"aud"`
		Iat *jwt.NumericDate `json:"iat"`
		Nbf *jwt.NumericDate `json:"nbf"`
		Exp *jwt.NumericDate `json:"exp"`
		JTI string           `json:"jti"`
	}
	if err := parsed.Claims(ks[0].Key, &raw); err != nil {
		return fedClaims{}, err
	}
	return fedClaims{Issuer: raw.Iss, Subject: raw.Sub, Audience: raw.Aud, IssuedAt: raw.Iat, NotBefore: raw.Nbf, Expiry: raw.Exp, JTI: raw.JTI}, nil
}

func TestFederationToken_ClaimsAndExpiry(t *testing.T) {
	e := newFedEnv(t, newReplay(t))
	k := e.create(t, e.f.A, "prod")
	tok, err := e.svc.Federation.Token(context.Background(), e.f.A.ID, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if h := parsed.Headers[0]; h.Algorithm != "ES256" || h.KeyID == "" || h.ExtraHeaders[jose.HeaderType] != "JWT" {
		t.Errorf("header = %+v", h)
	}
	c, err := verify(t, tok, e.jwks(t, e.f.A))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != fedPublicURL+"/t/"+e.f.A.Slug+"/aws" || c.Issuer != IssuerURL(fedPublicURL, e.f.A.Slug) {
		t.Errorf("iss = %q", c.Issuer)
	}
	if c.Subject != "tessera:tenant:"+e.f.A.ID.String()+":aws-connector:"+k.ID || c.Subject != Subject(e.f.A.ID, k.ID) {
		t.Errorf("sub = %q", c.Subject)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "sts.amazonaws.com" {
		t.Errorf("aud = %v", c.Audience)
	}
	if c.Expiry == nil || c.IssuedAt == nil || c.NotBefore == nil || c.JTI == "" {
		t.Fatalf("claims = %+v", c)
	}
	if got := c.Expiry.Time().Sub(testNow); got != TokenTTL || TokenTTL > 10*time.Minute {
		t.Errorf("exp is %v after now (TokenTTL %v): want a few minutes", got, TokenTTL)
	}
	if c.IssuedAt.Time().After(testNow) || c.NotBefore.Time().After(testNow) {
		t.Errorf("iat %v / nbf %v are in the future", c.IssuedAt.Time(), c.NotBefore.Time())
	}
	tok2, err := e.svc.Federation.Token(context.Background(), e.f.A.ID, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c2, _ := verify(t, tok2, e.jwks(t, e.f.A)); c2.JTI == c.JTI {
		t.Error("two tokens share a jti")
	}
}

// TestFederationToken_TenantIsolation: a token names its tenant in both the
// issuer and the subject, verifies only against that tenant's keys, and a
// tenant cannot get one for another tenant's connector (or for none).
func TestFederationToken_TenantIsolation(t *testing.T) {
	e := newFedEnv(t, newReplay(t))
	ka, kb := e.create(t, e.f.A, "prod"), e.create(t, e.f.B, "prod")
	ctx := context.Background()
	ta, err := e.svc.Federation.Token(ctx, e.f.A.ID, ka.ID)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := e.svc.Federation.Token(ctx, e.f.B.ID, kb.ID)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := verify(t, ta, e.jwks(t, e.f.A))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := verify(t, tb, e.jwks(t, e.f.B))
	if err != nil {
		t.Fatal(err)
	}
	if ca.Issuer == cb.Issuer || ca.Subject == cb.Subject || !strings.Contains(ca.Subject, e.f.A.ID.String()) || !strings.Contains(cb.Subject, e.f.B.ID.String()) {
		t.Errorf("tenants share an identity: %+v / %+v", ca, cb)
	}
	if _, err := verify(t, ta, e.jwks(t, e.f.B)); err == nil {
		t.Error("A's token verifies against B's JWKS")
	}
	if _, err := e.svc.Federation.Token(ctx, e.f.B.ID, ka.ID); err == nil {
		t.Error("tenant B minted a token for A's connector")
	}
	if _, err := e.svc.Federation.Token(ctx, e.f.A.ID, "no-such-connector"); err == nil {
		t.Error("a token was minted for a connector that does not exist")
	}
	if _, err := e.svc.Federation.Token(ctx, tenancy.ID{}, ka.ID); err == nil {
		t.Error("a token was minted with no tenant")
	}
	// the same connector name in two tenants gives two different subjects
	if ka.Name != kb.Name || ka.ID == kb.ID {
		t.Errorf("fixture: %s/%s", ka.ID, kb.ID)
	}
}

func TestFederation_NotConfigured(t *testing.T) {
	var f *Federation
	if _, err := f.Token(context.Background(), tenancy.Platform, "x"); err == nil {
		t.Error("nil federation minted a token")
	}
	if _, err := (&Federation{}).Token(context.Background(), tenancy.Platform, "x"); err == nil {
		t.Error("empty federation minted a token")
	}
}

// TestFederated_NoSecretStored: a federated connector keeps no secret: no
// sealed blob, no external id, and neither the token nor the temporary
// credentials reach the connector row, an audit event or the findings.
func TestFederated_NoSecretStored(t *testing.T) {
	r := newReplay(t)
	e := newFedEnv(t, r)
	k := e.create(t, e.f.A, "prod")
	if len(k.CredentialsEnc) != 0 || k.ExternalID != "" || !strings.Contains(string(k.Config), `"auth":"federated"`) {
		t.Fatalf("connector = %+v config=%s", k, k.Config)
	}
	hdr, err := e.svc.Collect(context.Background(), e.f.DB, e.f.A.ID, k.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if u := r.Unrecorded(); len(u) > 0 {
		t.Fatalf("unrecorded: %v", u)
	}
	if b := r.BadSignatures(); len(b) > 0 {
		t.Fatalf("bad signatures: %v", b)
	}
	// how it was fetched: every STS call is AssumeRoleWithWebIdentity, unsigned,
	// with a token of this connector, and no ExternalId
	set := e.jwks(t, e.f.A)
	var tokens []string
	for _, q := range r.Requests() {
		if q.Service != "sts" {
			if q.AccessKeyID != sessionKeyID || q.SessionToken == "" {
				t.Errorf("%s/%s not signed with the assumed role's session", q.Service, q.Operation)
			}
			continue
		}
		if q.Operation != "AssumeRoleWithWebIdentity" || q.AccessKeyID != "" || q.SessionToken != "" || q.Form.Get("ExternalId") != "" ||
			q.Form.Get("RoleSessionName") == "" || q.Form.Get("DurationSeconds") != "3600" || !strings.HasSuffix(q.Form.Get("RoleArn"), ":role/TesseraReader") {
			t.Errorf("STS request = %+v", q)
		}
		tok := q.Form.Get("WebIdentityToken")
		c, err := verify(t, tok, set)
		if err != nil || c.Subject != Subject(e.f.A.ID, k.ID) || c.Audience[0] != FederationAudience {
			t.Errorf("token sent to STS: %+v, %v", c, err)
		}
		tokens = append(tokens, tok)
	}
	if len(tokens) != 2 {
		t.Fatalf("STS calls = %d, want one per account (the management session is reused)", len(tokens))
	}
	if tokens[0] == tokens[1] {
		t.Error("the same token was sent twice")
	}
	secrets := append([]string{sessionSecret, "FwoGZXIvYXdzEXAMPLETOKEN"}, tokens...)
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		got, err := c.AWSConnector(k.ID)
		if err != nil {
			return err
		}
		if len(got.CredentialsEnc) != 0 || got.ExternalID != "" || got.Status != store.AWSConnectorOK || got.LastSnapshotID != hdr.ID {
			t.Errorf("connector after run = %+v", got)
		}
		blob := string(got.Config) + got.LastError + string(got.CredentialsEnc) + got.ExternalID
		evs, err := c.AuditLog(0)
		for _, ev := range evs {
			blob += ev.Action + string(ev.Detail)
		}
		for _, s := range secrets {
			if strings.Contains(blob, s) {
				t.Errorf("a secret (%.10s...) is stored in the connector or audit rows", s)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// the snapshot (what is persisted from AWS) holds no secret either
	snapJSON, _ := json.Marshal(hdr)
	snap := string(snapJSON)
	for _, s := range secrets {
		if strings.Contains(snap, s) {
			t.Errorf("a secret is in the snapshot header")
		}
	}
}

// leakyDoer answers every STS web identity call with an error that echoes the
// token, the way a careless service might.
type leakyDoer struct{ inner Doer }

func (d leakyDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") == "" && req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		return &http.Response{StatusCode: 400, Header: http.Header{}, Request: req,
			Body: io.NopCloser(strings.NewReader("<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>bad token " + string(b) + "</Message></Error></ErrorResponse>"))}, nil
	}
	return d.inner.Do(req)
}

// TestFederated_ErrorsNeverEchoTheToken: an STS refusal that quotes the request
// reaches no error text, connector row or audit event with the token in it.
func TestFederated_ErrorsNeverEchoTheToken(t *testing.T) {
	r := newReplay(t)
	e := newFedEnv(t, r)
	e.svc.Client = testClient(leakyDoer{r}, nil)
	k := e.create(t, e.f.A, "prod")
	_, err := e.svc.Collect(context.Background(), e.f.DB, e.f.A.ID, k.ID, "admin")
	if err == nil {
		t.Fatal("collected through a refused STS call")
	}
	if !IsCode(err, "InvalidIdentityToken") {
		t.Errorf("error = %v, want the STS code kept", err)
	}
	looksLikeJWT := func(s string) bool { return strings.Contains(s, "eyJ") }
	if looksLikeJWT(err.Error()) {
		t.Errorf("error holds a token: %v", err)
	}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		got, err := c.AWSConnector(k.ID)
		if err != nil {
			return err
		}
		if got.Status != store.AWSConnectorFailed || looksLikeJWT(got.LastError) {
			t.Errorf("connector = status %s, last_error %q", got.Status, got.LastError)
		}
		evs, err := c.AuditLog(0)
		for _, ev := range evs {
			if looksLikeJWT(string(ev.Detail)) {
				t.Errorf("audit event %s holds a token", ev.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRedact(t *testing.T) {
	const tok = "eyJhbGciOi.secretpayload.sig"
	ae := &Error{Service: "sts", Op: "AssumeRoleWithWebIdentity", Status: 400, Code: "InvalidIdentityToken", Message: "got " + tok + "!"}
	for name, tc := range map[string]struct{ in, want error }{
		"aws error": {ae, ae}, "wrapped": {errors.Join(errors.New("ctx"), ae), ae},
	} {
		got := redact(tc.in, tok)
		var ge *Error
		if !errors.As(got, &ge) || strings.Contains(got.Error(), tok) || ge.Code != "InvalidIdentityToken" || ge.Status != 400 {
			t.Errorf("%s: %v", name, got)
		}
	}
	if got := redact(errors.New("Post https://x: "+tok), tok); strings.Contains(got.Error(), tok) {
		t.Errorf("transport error: %v", got)
	}
	plain := errors.New("timeout")
	if redact(plain, tok) != plain || redact(nil, tok) != nil {
		t.Error("an error without the secret changed")
	}
	if ae.Message == "" || !strings.Contains(ae.Message, tok) {
		t.Error("redact modified its input")
	}
}

// TestFederated_CredentialCachingAndRefresh: a session is reused until five
// minutes before its credentials expire, then assumed again with a new token.
func TestFederated_CredentialCachingAndRefresh(t *testing.T) {
	sts := func(exp time.Time) awsreplay.Response {
		return awsreplay.Response{Body: `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
<AccessKeyId>` + sessionKeyID + `</AccessKeyId><SecretAccessKey>` + sessionSecret + `</SecretAccessKey><SessionToken>tok</SessionToken>
<Expiration>` + exp.UTC().Format(time.RFC3339) + `</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`}
	}
	now := testNow
	r := awsreplay.NewReplay(nil)
	r.Enqueue("sts/AssumeRoleWithWebIdentity", sts(testNow.Add(time.Hour)), sts(testNow.Add(2*time.Hour)))
	minted := 0
	cfg := orgConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c := &Collector{Client: testClient(r, nil), Config: cfg, Now: func() time.Time { return now },
		WebIdentity: func(context.Context) (string, error) { minted++; return "token-" + string(rune('a'+minted)), nil }}
	cache := map[string]*accountSession{}
	ctx := context.Background()
	acct := "222222222222"
	s1, err := c.assume(ctx, cache, acct)
	if err != nil {
		t.Fatal(err)
	}
	now = testNow.Add(54 * time.Minute) // more than five minutes left
	s2, err := c.assume(ctx, cache, acct)
	if err != nil || s2 != s1 || r.Calls("sts/AssumeRoleWithWebIdentity") != 1 || minted != 1 {
		t.Fatalf("cached: same=%t calls=%d minted=%d err=%v", s2 == s1, r.Calls("sts/AssumeRoleWithWebIdentity"), minted, err)
	}
	now = testNow.Add(56 * time.Minute) // under five minutes left: refresh
	s3, err := c.assume(ctx, cache, acct)
	if err != nil || s3 == s1 || r.Calls("sts/AssumeRoleWithWebIdentity") != 2 || minted != 2 {
		t.Fatalf("refresh: new=%t calls=%d minted=%d err=%v", s3 != s1, r.Calls("sts/AssumeRoleWithWebIdentity"), minted, err)
	}
	reqs := r.Requests()
	if reqs[0].Form.Get("WebIdentityToken") != "token-b" || reqs[1].Form.Get("WebIdentityToken") != "token-c" {
		t.Errorf("tokens sent = %q, %q: each assume mints its own", reqs[0].Form.Get("WebIdentityToken"), reqs[1].Form.Get("WebIdentityToken"))
	}
	// a token source that fails is an error, and nothing is sent
	c.WebIdentity = func(context.Context) (string, error) { return "", errors.New("no key") }
	if _, err := c.assume(ctx, map[string]*accountSession{}, acct); err == nil || r.Calls("sts/AssumeRoleWithWebIdentity") != 2 {
		t.Errorf("failing token source: err=%v calls=%d", err, r.Calls("sts/AssumeRoleWithWebIdentity"))
	}
}

func TestService_StaticKeysFlag(t *testing.T) {
	r := newReplay(t)
	e := newFedEnv(t, r)
	keysIn := Credentials{AccessKeyID: baseKeyID, SecretAccessKey: baseSecret}
	create := func(in CreateInput) (*store.AWSConnector, error) {
		var k *store.AWSConnector
		err := e.f.DB.InTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) (err error) {
			k, err = e.svc.CreateConnector(c, in, "admin", testNow)
			return err
		})
		return k, err
	}
	code := func(err error) string {
		var ie *InputError
		if errors.As(err, &ie) {
			return ie.Code
		}
		return ""
	}
	// flag off: keys are refused, in either spelling, and nothing is stored
	if _, err := create(CreateInput{Name: "a", Config: *orgConfig(), Credentials: keysIn}); code(err) != "static_keys_disabled" {
		t.Errorf("keys with the flag off: %v", err)
	}
	staticCfg := *orgConfig()
	staticCfg.Auth = AuthStaticKey
	if _, err := create(CreateInput{Name: "a", Config: staticCfg}); code(err) != "static_keys_disabled" {
		t.Errorf("auth=static_key with the flag off: %v", err)
	}
	// federated is the default, and takes no keys or external id
	k, err := create(CreateInput{Name: "fed", Config: *orgConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := ParseConfig(k.Config); cfg.Mode() != AuthFederated {
		t.Errorf("default mode = %s", cfg.Mode())
	}
	fedCfg := *orgConfig()
	fedCfg.Auth = AuthFederated
	if _, err := create(CreateInput{Name: "b", Config: fedCfg, Credentials: keysIn}); code(err) != "invalid_credentials" {
		t.Errorf("federated with keys: %v", err)
	}
	if _, err := create(CreateInput{Name: "b", Config: fedCfg, ExternalID: "abc-123"}); code(err) != "invalid_external_id" {
		t.Errorf("federated with an external id: %v", err)
	}
	badCfg := *orgConfig()
	badCfg.Auth = "password"
	if _, err := create(CreateInput{Name: "c", Config: badCfg}); code(err) != "invalid_config" {
		t.Errorf("unknown auth: %v", err)
	}

	// flag on: keys work and the connector is a static-key one
	e.svc.AllowStaticKeys = true
	ks, err := create(CreateInput{Name: "static", Config: *orgConfig(), Credentials: keysIn})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := ParseConfig(ks.Config); cfg.Mode() != AuthStaticKey || len(ks.CredentialsEnc) == 0 || ks.ExternalID == "" {
		t.Errorf("static connector = %s %+v", ks.Config, ks)
	}
	// a stored config from before federation has no auth: it is a static-key one
	if cfg, _ := ParseConfig([]byte(`{"regions":["us-east-1"],"account_ids":["111111111111"]}`)); cfg.Mode() != AuthStaticKey {
		t.Error("legacy config is not static_key")
	}
	// the flag turned off later (prod): a stored static connector is not collected from
	e.svc.AllowStaticKeys = false
	before := len(r.Requests())
	_, err = e.svc.Collect(context.Background(), e.f.DB, e.f.A.ID, ks.ID, "admin")
	if err == nil || !strings.Contains(err.Error(), "disabled") || len(r.Requests()) != before {
		t.Errorf("collect a static connector with the flag off: %v (requests %d -> %d)", err, before, len(r.Requests()))
	}
	// a federated service with no token issuer fails closed
	e.svc.Federation = nil
	if _, err := e.svc.Collect(context.Background(), e.f.DB, e.f.A.ID, k.ID, "admin"); err == nil || len(r.Requests()) != before {
		t.Errorf("collect with no federation: %v", err)
	}
}

// TestTrustPolicy: the policy the customer attaches to the role parses, trusts
// only the account's provider for the issuer, and pins aud and sub.
// TestFederationToken_LegacyTenantCutover (#676): a tenant that has only access_token and
// idp_client_auth keys (created before the aws_federation purpose) gets an aws_federation
// key from EnsureAll at the next start, and federation tokens are then signed with it,
// never with the access_token key.
func TestFederationToken_LegacyTenantCutover(t *testing.T) {
	f := storetest.TwoTenants(t)
	sl := testSealer(t)
	ctx := context.Background()
	full := keys.TenantPurposes
	keys.TenantPurposes = []string{store.KeyPurposeAccessToken, store.KeyPurposeIdPClientAuth}
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return keys.EnsureKeys(c, f.A.Slug, sl, testNow) })
	keys.TenantPurposes = full
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Sealer: sl, Clock: func() time.Time { return testNow }}
	fed := &Federation{DB: f.DB, Sealer: sl, PublicURL: fedPublicURL, Clock: func() time.Time { return testNow }}
	var k *store.AWSConnector
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) {
		k, err = svc.CreateConnector(c, CreateInput{Name: "legacy", Config: *orgConfig()}, "admin", testNow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fed.Token(ctx, f.A.ID, k.ID); err == nil {
		t.Fatal("a token was signed before the tenant had an aws_federation key")
	}
	if err := keys.EnsureAll(ctx, f.DB, sl, testNow); err != nil {
		t.Fatal(err)
	}
	tok, err := fed.Token(ctx, f.A.ID, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		for purpose, want := range map[string]bool{store.KeyPurposeAWSFederation: true, store.KeyPurposeAccessToken: false} {
			ks, err := c.SigningKeys(purpose)
			if err != nil {
				return err
			}
			found := false
			for _, key := range ks {
				found = found || key.KID == kid
			}
			if found != want {
				t.Errorf("kid %s in %s keys = %v, want %v", kid, purpose, found, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTrustPolicy(t *testing.T) {
	iss := IssuerURL(fedPublicURL, "larkspur")
	sub := Subject(tenancy.Platform, "conn-1")
	raw := TrustPolicy(iss, sub)
	res, err := policy.Parse(raw, policy.Options{Kind: model.PolicyTrust, SourceARN: "tessera:trust-policy"})
	if err != nil || len(res.Anomalies) > 0 {
		t.Fatalf("trust policy does not parse: %v %v\n%s", err, res.Anomalies, raw)
	}
	s := string(raw)
	for _, want := range []string{
		`"Federated": "arn:aws:iam::{ACCOUNT_ID}:oidc-provider/tessera.example.com/t/larkspur/aws"`,
		`"Action": "sts:AssumeRoleWithWebIdentity"`,
		`"tessera.example.com/t/larkspur/aws:aud": "sts.amazonaws.com"`,
		`"tessera.example.com/t/larkspur/aws:sub": "` + sub + `"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("trust policy lacks %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, "https://") || strings.Contains(s, `"*"`) {
		t.Errorf("trust policy is too loose:\n%s", s)
	}
}
