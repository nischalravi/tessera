package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

const awsFedPublic = "https://tessera.example.com"

// TestAWSFederation_PublicDocuments: the discovery document and JWKS that an IAM
// OIDC provider reads are public and per tenant, and a token the connector
// mints verifies against them (and only against its own tenant's).
func TestAWSFederation_PublicDocuments(t *testing.T) {
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return keys.EnsureKeys(c, tn.Slug, sealer, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", RateLimits: noRateLimits,
		AllowedOrigins: []string{"http://localhost:5173"}, PublicURL: awsFedPublic, Sealer: sealer})
	h := srv.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		return serve(h, httptest.NewRequest("GET", path, nil))
	}

	for _, tn := range []storetest.Tenant{f.A, f.B} {
		rec := get("/t/" + tn.Slug + "/aws/.well-known/openid-configuration")
		var d map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
			t.Fatalf("discovery %s = %d %s", tn.Slug, rec.Code, rec.Body)
		}
		iss := awsFedPublic + "/t/" + tn.Slug + "/aws"
		if d["issuer"] != iss || d["jwks_uri"] != iss+"/.well-known/jwks.json" {
			t.Errorf("discovery = %v", d)
		}
		for _, k := range []string{"authorization_endpoint", "token_endpoint"} {
			if _, ok := d[k]; ok {
				t.Errorf("discovery advertises %s: this issuer has no endpoints but its keys", k)
			}
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", rec.Header().Get("Content-Type"))
		}
	}

	// a token minted for a connector verifies against its tenant's served JWKS only
	svc := &awsorg.Service{Sealer: sealer, Clock: func() time.Time { return storetest.Now }}
	fed := &awsorg.Federation{DB: f.DB, Sealer: sealer, PublicURL: awsFedPublic, Clock: func() time.Time { return storetest.Now }}
	tokens := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		var k *store.AWSConnector
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
			k, err = svc.CreateConnector(c, awsorg.CreateInput{Name: "prod", Config: awsorg.Config{Regions: []string{"us-east-1"},
				ManagementAccountID: "111111111111"}}, "admin", storetest.Now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if tokens[tn.Slug], err = fed.Token(context.Background(), tn.ID, k.ID); err != nil {
			t.Fatal(err)
		}
	}
	verifies := func(slug, tok string) bool {
		rec := get("/t/" + slug + "/aws/.well-known/jwks.json")
		var set jose.JSONWebKeySet
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &set) != nil || len(set.Keys) == 0 {
			t.Fatalf("jwks %s = %d %s", slug, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), `"d"`) {
			t.Errorf("the JWKS has a private member: %s", rec.Body)
		}
		parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		ks := set.Key(parsed.Headers[0].KeyID)
		if len(ks) == 0 {
			return false
		}
		var c map[string]any
		return parsed.Claims(ks[0].Key, &c) == nil
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		other := f.A
		if tn.Slug == f.A.Slug {
			other = f.B
		}
		if !verifies(tn.Slug, tokens[tn.Slug]) {
			t.Errorf("%s's token does not verify against its JWKS", tn.Slug)
		}
		if verifies(other.Slug, tokens[tn.Slug]) {
			t.Errorf("%s's token verifies against %s's JWKS", tn.Slug, other.Slug)
		}
	}

	// the AWS JWKS publishes the aws_federation keys only, never the API's access_token keys (#676)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		var access []*store.TenantSigningKey
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
			access, err = c.SigningKeys(store.KeyPurposeAccessToken)
			return err
		}); err != nil || len(access) == 0 {
			t.Fatalf("access_token keys: %v (%d)", err, len(access))
		}
		body := get("/t/" + tn.Slug + "/aws/.well-known/jwks.json").Body.String()
		for _, k := range access {
			if strings.Contains(body, k.KID) {
				t.Errorf("%s: the AWS JWKS publishes access_token key %s", tn.Slug, k.KID)
			}
		}
	}

	// unknown tenants and the platform's reserved slug answer 404, with no detail
	for _, slug := range []string{"nobody", "_platform", "Bad_Slug"} {
		for _, p := range []string{"openid-configuration", "jwks.json"} {
			if rec := get("/t/" + slug + "/aws/.well-known/" + p); rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d", slug, p, rec.Code)
			}
		}
	}
	// the token is served nowhere: no route returns one
	for _, p := range []string{"token", "oauth/token", "credentials"} {
		if rec := get("/t/" + f.A.Slug + "/aws/" + p); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /aws/%s = %d", p, rec.Code)
		}
	}
}

// TestAWSAPI_FederatedConnector: without credentials a connector is federated
// (the default): nothing secret is stored, and the response tells the customer
// what to trust. Stored keys are refused unless the server allows them.
func TestAWSAPI_FederatedConnector(t *testing.T) {
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	c := newRD(t, func(c *Config) { c.Sealer = s; c.PublicURL = awsFedPublic }) // AWSAllowStaticKeys is off
	rec := c.do("POST", "/api/aws/connectors", `{"name":"fed","config":{"regions":["us-east-1"],"management_account_id":"111111111111"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	var v struct {
		ID             string `json:"id"`
		ExternalID     string `json:"external_id"`
		CredentialsSet bool   `json:"credentials_set"`
		Auth           string `json:"auth"`
		Federation     struct {
			Issuer, Audience, Subject string
			TrustPolicy               string `json:"trust_policy"`
		} `json:"federation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Auth != "federated" || v.CredentialsSet || v.ExternalID != "" || v.Federation.Audience != "sts.amazonaws.com" ||
		!strings.HasPrefix(v.Federation.Issuer, awsFedPublic+"/t/") || !strings.HasSuffix(v.Federation.Issuer, "/aws") ||
		!strings.HasSuffix(v.Federation.Subject, ":aws-connector:"+v.ID) || !strings.Contains(v.Federation.TrustPolicy, "sts:AssumeRoleWithWebIdentity") ||
		!strings.Contains(v.Federation.TrustPolicy, v.Federation.Subject) {
		t.Errorf("connector = %s", rec.Body)
	}
	// the list shows the same, and stored keys are refused
	list := c.do("GET", "/api/aws/connectors", "").Body.String()
	if !strings.Contains(list, `"auth":"federated"`) || !strings.Contains(list, v.Federation.Subject) {
		t.Errorf("list = %s", list)
	}
	rec = c.do("POST", "/api/aws/connectors", awsCreateBody("keys"))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "static_keys_disabled") || strings.Contains(rec.Body.String(), awsTestSecret) {
		t.Errorf("keys with the flag off = %d: %s", rec.Code, rec.Body)
	}
	if rec := c.do("POST", "/api/aws/connectors", `{"name":"mixed","config":{"auth":"federated","regions":["us-east-1"],"management_account_id":"111111111111"},`+
		`"credentials":{"access_key_id":"AKIAEXAMPLEEXAMPLE1","secret_access_key":"`+awsTestSecret+`"}}`); rec.Code != http.StatusUnprocessableEntity || strings.Contains(rec.Body.String(), awsTestSecret) {
		t.Errorf("federated with keys = %d: %s", rec.Code, rec.Body)
	}
}
