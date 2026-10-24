package azurerbac_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const (
	tenant     = "11111111-2222-3333-4444-555555555555"
	clientID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	secret     = "s3cr3t-value-for-tests"
	subA       = "aaaa1111-0000-0000-0000-000000000001"
	subB       = "bbbb2222-0000-0000-0000-000000000002"
	userP      = "11110000-0000-0000-0000-000000000001"
	spP        = "22220000-0000-0000-0000-000000000002"
	groupP     = "33330000-0000-0000-0000-000000000003"
	ownerRole  = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	readerRole = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	customRole = "cccc0000-0000-0000-0000-00000000cccc"
)

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// fake is an Azure Resource Manager and Entra token endpoint in one.
type fake struct {
	srv       *connsynctest.Server
	cert      *x509.Certificate // when set, the token endpoint accepts only an assertion signed for it
	tokens    int
	deny      map[string]int // path prefix -> status
	evil      bool           // next links point at another host
	assertion string
}

func roleID(scope, guid string) string {
	return scope + "/providers/Microsoft.Authorization/roleDefinitions/" + guid
}

func assign(id, principal, ptype, scope, role string) map[string]any {
	return map[string]any{"id": id, "properties": map[string]any{"principalId": principal, "principalType": ptype, "scope": scope,
		"roleDefinitionId": roleID("/subscriptions/"+subA, role)}}
}

func (f *fake) handler(base func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if r.URL.Path == "/"+tenant+"/oauth2/v2.0/token" {
			f.tokenEndpoint(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer arm-token" {
			w.WriteHeader(http.StatusUnauthorized)
			write(map[string]any{"error": map[string]any{"code": "InvalidAuthenticationToken"}})
			return
		}
		for p, st := range f.deny {
			if strings.HasPrefix(r.URL.Path, p) {
				w.WriteHeader(st)
				write(map[string]any{"error": map[string]any{"code": "AuthorizationFailed"}})
				return
			}
		}
		q := r.URL.Query()
		path := r.URL.Path
		switch {
		case path == "/subscriptions":
			if q.Get("api-version") != "2022-12-01" {
				w.WriteHeader(400)
				return
			}
			if q.Get("page") == "" {
				next := base() + "/subscriptions?api-version=2022-12-01&page=2"
				if f.evil {
					next = "https://evil.example.com/subscriptions?page=2"
				}
				write(map[string]any{"value": []any{map[string]any{"subscriptionId": subA, "displayName": "Prod", "state": "Enabled"}}, "nextLink": next})
				return
			}
			write(map[string]any{"value": []any{
				map[string]any{"subscriptionId": subB, "displayName": "Dev", "state": "Enabled"},
				map[string]any{"subscriptionId": "cccc3333-0000-0000-0000-000000000003", "displayName": "Old", "state": "Disabled"}}})
		case path == "/providers/Microsoft.Management/managementGroups":
			if q.Get("api-version") != "2020-05-01" {
				w.WriteHeader(400)
				return
			}
			write(map[string]any{"value": []any{map[string]any{"name": "corp", "properties": map[string]any{"displayName": "Corp"}}}})
		case strings.HasSuffix(path, "/providers/Microsoft.Authorization/roleDefinitions"):
			if q.Get("api-version") != "2022-04-01" {
				w.WriteHeader(400)
				return
			}
			defs := []any{
				map[string]any{"id": roleID("/subscriptions/"+subA, ownerRole), "properties": map[string]any{"roleName": "Owner", "type": "BuiltInRole",
					"permissions": []any{map[string]any{"actions": []string{"*"}}}}},
				map[string]any{"id": roleID("/subscriptions/"+subA, readerRole), "properties": map[string]any{"roleName": "Reader", "type": "BuiltInRole",
					"permissions": []any{map[string]any{"actions": []string{"*/read"}}}}},
			}
			write(map[string]any{"value": defs})
		case strings.Contains(path, "/providers/Microsoft.Authorization/roleDefinitions/"):
			if strings.HasSuffix(path, customRole) {
				write(map[string]any{"id": path, "properties": map[string]any{"roleName": "Key Rotator", "type": "CustomRole",
					"permissions": []any{map[string]any{"actions": []string{"Microsoft.KeyVault/vaults/write"}}}}})
				return
			}
			w.WriteHeader(404)
		case strings.HasSuffix(path, "/providers/Microsoft.Authorization/roleAssignments"):
			if q.Get("api-version") != "2022-04-01" {
				w.WriteHeader(400)
				return
			}
			switch {
			case strings.HasPrefix(path, "/subscriptions/"+subA):
				write(map[string]any{"value": []any{
					assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleAssignments/1", userP, "User", "/subscriptions/"+subA, ownerRole),
					assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleAssignments/2", spP, "ServicePrincipal", "/subscriptions/"+subA+"/resourceGroups/rg1", readerRole),
					assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleAssignments/3", groupP, "Group", "/subscriptions/"+subA, customRole),
					// the same assignment, seen again from the management group
					assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleAssignments/1", userP, "User", "/subscriptions/"+subA, ownerRole)}})
			case strings.HasPrefix(path, "/subscriptions/"+subB):
				write(map[string]any{"value": []any{}})
			default: // management group corp
				if q.Get("$filter") != "atScope()" {
					w.WriteHeader(400)
					return
				}
				a := assign("/providers/Microsoft.Management/managementGroups/corp/providers/Microsoft.Authorization/roleAssignments/9", userP, "User",
					"/providers/Microsoft.Management/managementGroups/corp", readerRole)
				a["properties"].(map[string]any)["condition"] = "@Resource[x] StringEquals 'y'"
				write(map[string]any{"value": []any{a}})
			}
		case strings.HasSuffix(path, "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances"):
			if q.Get("api-version") != "2020-10-01" || q.Get("$filter") != "atScope()" {
				w.WriteHeader(400)
				return
			}
			if strings.HasPrefix(path, "/subscriptions/"+subA) {
				e := assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/e1", userP, "User", "/subscriptions/"+subA, ownerRole)
				e["properties"].(map[string]any)["status"] = "Provisioned"
				e["properties"].(map[string]any)["endDateTime"] = "2027-01-01T00:00:00Z"
				ex := assign("/subscriptions/"+subA+"/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/e2", spP, "User", "/subscriptions/"+subA, ownerRole)
				ex["properties"].(map[string]any)["status"] = "Revoked"
				write(map[string]any{"value": []any{e, ex}})
				return
			}
			write(map[string]any{"value": []any{}})
		default:
			w.WriteHeader(404)
		}
	})
}

func (f *fake) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	f.tokens++
	_ = r.ParseForm()
	fail := func() {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret ` + r.Form.Get("client_secret") + `"}`))
	}
	if r.Method != http.MethodPost || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != clientID ||
		!strings.HasSuffix(r.Form.Get("scope"), "/.default") {
		fail()
		return
	}
	if f.cert != nil {
		a := r.Form.Get("client_assertion")
		if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || r.Form.Get("client_secret") != "" || !f.verify(a, r.Host) {
			fail()
			return
		}
		f.assertion = a
	} else if r.Form.Get("client_secret") != secret {
		fail()
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "arm-token", "token_type": "Bearer", "expires_in": 3600})
}

func (f *fake) verify(a, host string) bool {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return false
	}
	var hdr map[string]string
	var claims map[string]any
	dec := func(s string, v any) bool {
		b, err := base64.RawURLEncoding.DecodeString(s)
		return err == nil && json.Unmarshal(b, v) == nil
	}
	if !dec(parts[0], &hdr) || !dec(parts[1], &claims) {
		return false
	}
	sum := sha256.Sum256(f.cert.Raw)
	aud, _ := claims["aud"].(string)
	if hdr["alg"] != "PS256" || hdr["typ"] != "JWT" || hdr["x5t#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]) ||
		claims["iss"] != clientID || claims["sub"] != clientID || claims["jti"] == "" || !strings.HasSuffix(aud, "/"+tenant+"/oauth2/v2.0/token") || !strings.Contains(aud, host) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPSS(f.cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
}

type rig struct {
	f  *fake
	hc *http.Client
}

func newRig(t *testing.T, f *fake) *rig {
	t.Helper()
	var srv *connsynctest.Server
	srv = connsynctest.New(t, f.handler(func() string { return srv.URL }))
	f.srv = srv
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{f, hc}
}

func (r *rig) cfg(mut ...func(*azurerbac.Config)) azurerbac.Config {
	c := azurerbac.Config{TenantID: tenant, ClientID: clientID, Credential: connsync.NewSecret(secret), IncludeEligible: true,
		ManagementURL: r.f.srv.URL, AuthorityURL: r.f.srv.URL}
	for _, m := range mut {
		m(&c)
	}
	return c
}

func (r *rig) open(t *testing.T, mut ...func(*azurerbac.Config)) *azurerbac.Connector {
	t.Helper()
	c, err := azurerbac.New(r.cfg(mut...), connsynctest.Runtime, r.hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDiscoverMapsAssignmentsAndEligibility(t *testing.T) {
	r := newRig(t, &fake{})
	res, err := r.open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial != "" {
		t.Errorf("partial = %q", res.Partial)
	}
	scope := "/subscriptions/" + subA
	perms := map[string]connectors.PermissionRecord{}
	for _, p := range res.Permissions {
		perms[p.ExternalID] = p
	}
	for id, want := range map[string]struct {
		action string
		priv   bool
		res    string
	}{
		scope + "|" + ownerRole:                     {"Owner", true, scope},
		scope + "/resourcegroups/rg1|" + readerRole: {"Reader", false, scope + "/resourcegroups/rg1"},
		scope + "|" + customRole:                    {"Key Rotator", false, scope},
		scope + "|" + ownerRole + "|eligible":       {"Owner (eligible)", true, scope},
	} {
		p, ok := perms[id]
		if !ok || p.Action != want.action || p.Privileged != want.priv || p.ResourceExternalID != want.res {
			t.Errorf("permission %s = %+v, want %+v", id, p, want)
		}
	}
	var cond string
	for id, p := range perms {
		if strings.HasPrefix(id, "/providers/microsoft.management/managementgroups/corp|"+readerRole+"|c") {
			cond = p.Action
		}
	}
	if cond != "Reader (conditional)" || len(res.Permissions) != 5 {
		t.Errorf("conditional = %q, %d permissions", cond, len(res.Permissions))
	}
	kinds := map[string]string{}
	for _, r := range res.Resources {
		kinds[r.ExternalID] = r.Kind
	}
	for id, k := range map[string]string{scope: "azure_subscription", scope + "/resourcegroups/rg1": "azure_resource_group",
		"/subscriptions/" + subB: "azure_subscription", "/providers/microsoft.management/managementgroups/corp": "azure_management_group"} {
		if kinds[id] != k {
			t.Errorf("resource %s kind = %q, want %q", id, kinds[id], k)
		}
	}
	if _, ok := kinds["/subscriptions/cccc3333-0000-0000-0000-000000000003"]; ok {
		t.Error("a disabled subscription was read")
	}
	accts := map[string]string{}
	for _, a := range res.Accounts {
		accts[a.ExternalID] = a.Kind
	}
	if len(accts) != 2 || accts[userP] != "user" || accts[spP] != "service" {
		t.Errorf("accounts = %v", accts)
	}
	if len(res.Groups) != 1 || res.Groups[0].ExternalID != groupP || res.Groups[0].Kind != "entra_group" {
		t.Errorf("groups = %+v", res.Groups)
	}
	edges := map[string]bool{}
	for _, e := range res.Edges {
		edges[e.Src.Kind+":"+e.Src.ExternalID+">"+e.Dst.ExternalID+":"+e.Relation] = true
	}
	for _, want := range []string{"account:" + userP + ">" + scope + "|" + ownerRole + ":direct_grant",
		"account:" + userP + ">" + scope + "|" + ownerRole + "|eligible:direct_grant",
		"group:" + groupP + ">" + scope + "|" + customRole + ":grants"} {
		if !edges[want] {
			t.Errorf("missing edge %s in %v", want, edges)
		}
	}
	if len(res.Edges) != 5 { // the duplicate assignment adds none; the revoked eligibility adds none
		t.Errorf("%d edges", len(res.Edges))
	}
}

func TestReadIsReadOnlyAndUsesDocumentedVersions(t *testing.T) {
	r := newRig(t, &fake{})
	if _, err := r.open(t).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range r.f.srv.Requests() {
		if q.Method != http.MethodGet && !strings.HasSuffix(q.Path, "/oauth2/v2.0/token") {
			t.Errorf("%s %s: not a read", q.Method, q.Path)
		}
		if strings.Contains(q.Path, "roleAssignments") && !strings.Contains(q.Query, "api-version=2022-04-01") {
			t.Errorf("roleAssignments query %q", q.Query)
		}
	}
	if r.f.tokens != 1 {
		t.Errorf("%d token requests, want the token reused", r.f.tokens)
	}
}

func TestConfiguredScopesAreTheOnlyOnesRead(t *testing.T) {
	r := newRig(t, &fake{})
	c := r.open(t, func(c *azurerbac.Config) {
		c.SubscriptionIDs, c.ManagementGroupIDs, c.IncludeEligible = []string{subB}, nil, false
	})
	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Permissions) != 0 || r.f.srv.Count("/subscriptions/"+subA) != 0 || r.f.srv.Count("/subscriptions") != 2 || r.f.srv.Count("/providers/Microsoft.Management") != 0 {
		t.Errorf("read %v", r.f.srv.Requests())
	}
}

func TestUnreadableScopeIsPartialAndNoReadableScopeIsAnError(t *testing.T) {
	r := newRig(t, &fake{deny: map[string]int{"/subscriptions/" + subB: 403}})
	res, err := r.open(t).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Partial, "1 of 3 scopes could not be read") {
		t.Errorf("partial = %q", res.Partial)
	}
	r = newRig(t, &fake{deny: map[string]int{"/subscriptions/" + subA: 403, "/subscriptions/" + subB: 403, "/providers/Microsoft.Management/managementGroups/corp": 403}})
	if _, err := r.open(t).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "no scope could be read") {
		t.Errorf("err = %v", err)
	}
	// PIM not available (no P2 licence): the rest is read, held back from deletions
	r = newRig(t, &fake{deny: map[string]int{"/subscriptions/" + subA + "/providers/Microsoft.Authorization/roleEligibility": 403}})
	res, err = r.open(t).Discover(context.Background())
	if err != nil || !strings.Contains(res.Partial, "eligible (PIM)") || len(res.Permissions) == 0 {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestWrongSecretIsAnErrorThatDoesNotEchoIt(t *testing.T) {
	r := newRig(t, &fake{})
	c := r.open(t, func(c *azurerbac.Config) { c.Credential = connsync.NewSecret("wrong-secret-value") })
	_, err := c.Discover(context.Background())
	if !errors.Is(err, azurerbac.ErrCredential) || strings.Contains(err.Error(), "wrong-secret-value") {
		t.Errorf("err = %v", err)
	}
}

func TestNextLinkLeavingTheHostIsRefused(t *testing.T) {
	r := newRig(t, &fake{evil: true})
	if _, err := r.open(t).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
		t.Errorf("err = %v", err)
	}
	for _, q := range r.f.srv.Requests() {
		if q.Query == "page=2" {
			t.Error("the evil link was followed")
		}
	}
}

func selfSigned(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tessera-test"}, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert, pemText
}

func TestCertificateAuthenticationSendsASignedAssertion(t *testing.T) {
	cert, pemText := selfSigned(t)
	r := newRig(t, &fake{cert: cert})
	c := r.open(t, func(c *azurerbac.Config) { c.Credential = connsync.NewSecret(pemText) })
	if c.Mode() != "certificate" {
		t.Errorf("mode = %q", c.Mode())
	}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Permissions) == 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if r.f.assertion == "" || strings.Contains(r.f.assertion, "PRIVATE") {
		t.Error("no assertion reached the token endpoint")
	}
}

func TestCredentialPEMIsChecked(t *testing.T) {
	_, pemText := selfSigned(t)
	_, otherPEM := selfSigned(t)
	keyOnly := pemText[:strings.Index(pemText, "-----BEGIN CERTIFICATE")]
	certOnly := pemText[strings.Index(pemText, "-----BEGIN CERTIFICATE"):]
	otherKey := otherPEM[:strings.Index(otherPEM, "-----BEGIN CERTIFICATE")]
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	for name, cred := range map[string]string{"key only": keyOnly, "certificate only": certOnly, "mismatched key": otherKey + certOnly,
		"garbage pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		_, err := azurerbac.New(azurerbac.Config{TenantID: tenant, ClientID: clientID, Credential: connsync.NewSecret(cred)}, connsync.Runtime{Env: config.Prod}, hc, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := azurerbac.New(azurerbac.Config{TenantID: tenant, ClientID: clientID, Credential: connsync.NewSecret(pemText)}, connsync.Runtime{Env: config.Prod}, hc, nil); err != nil {
		t.Errorf("a certificate and its key: %v", err)
	}
}

func TestOpenGuards(t *testing.T) {
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	prod := connsync.Runtime{Env: config.Prod}
	good := azurerbac.Config{TenantID: tenant, ClientID: clientID, Credential: connsync.NewSecret(secret)}
	if _, err := azurerbac.New(good, prod, hc, nil); err != nil {
		t.Fatalf("the public cloud in prod: %v", err)
	}
	for name, tc := range map[string]struct {
		mut func(*azurerbac.Config)
		rt  connsync.Runtime
	}{
		"management override in prod":   {func(c *azurerbac.Config) { c.ManagementURL = "https://arm.example.com" }, prod},
		"authority override in prod":    {func(c *azurerbac.Config) { c.AuthorityURL = "https://login.example.com" }, prod},
		"loopback override in prod":     {func(c *azurerbac.Config) { c.ManagementURL = "http://127.0.0.1:9" }, prod},
		"sovereign cloud not allowed":   {func(c *azurerbac.Config) { c.ManagementURL = "https://management.usgovcloudapi.net" }, prod},
		"management override in test":   {func(c *azurerbac.Config) { c.ManagementURL = "https://arm.example.com" }, connsync.Runtime{Env: "test"}},
		"tenant not a GUID":             {func(c *azurerbac.Config) { c.TenantID = "contoso.onmicrosoft.com" }, prod},
		"client not a GUID":             {func(c *azurerbac.Config) { c.ClientID = "x" }, prod},
		"no credential":                 {func(c *azurerbac.Config) { c.Credential = connsync.Secret{} }, prod},
		"subscription not a GUID":       {func(c *azurerbac.Config) { c.SubscriptionIDs = []string{"../x"} }, prod},
		"management group with a slash": {func(c *azurerbac.Config) { c.ManagementGroupIDs = []string{"a/b"} }, prod},
	} {
		c := good
		tc.mut(&c)
		if _, err := azurerbac.New(c, tc.rt, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the same override is fine in dev (a fake server), and the default spelled out is not an override
	dev := connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	c := good
	c.ManagementURL = "http://127.0.0.1:9"
	if _, err := azurerbac.New(c, dev, hc, nil); err != nil {
		t.Errorf("dev override: %v", err)
	}
	c.ManagementURL = azurerbac.DefaultManagementURL + "/"
	if _, err := azurerbac.New(c, prod, hc, nil); err != nil {
		t.Errorf("explicit default: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	r := newRig(t, &fake{})
	env := map[string]string{"TESSERA_AZURE_TENANT_ID": tenant, "TESSERA_AZURE_CLIENT_ID": clientID, "TESSERA_AZURE_CREDENTIAL": "env:AZ",
		"AZ": secret, "TESSERA_AZURE_SUBSCRIPTIONS": subA + ", " + subB, "TESSERA_AZURE_ELIGIBLE": "true",
		"TESSERA_AZURE_MANAGEMENT_URL": r.f.srv.URL, "TESSERA_AZURE_AUTHORITY_URL": r.f.srv.URL}
	c, err := azurerbac.FromEnv(func(k string) string { return env[k] }, connsynctest.Runtime, r.hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(context.Background())
	if err != nil || len(res.Accounts) == 0 || c.System() != "azure" {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	if _, err := azurerbac.FromEnv(func(k string) string { return "" }, connsynctest.Runtime, r.hc, nil); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("no credential reference: %v", err)
	}
	if got := connsync.NewSecret(secret).String(); got != "REDACTED" {
		t.Error(got)
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, &fake{})
	p, err := r.open(t).Probe(context.Background())
	if err != nil || p.Mode != "client_secret" || p.Scopes != 3 || p.Assignments == 0 || p.Roles == 0 {
		t.Errorf("probe = %+v, err = %v", p, err)
	}
	r = newRig(t, &fake{})
	c := r.open(t, func(c *azurerbac.Config) { c.Credential = connsync.NewSecret("nope") })
	if _, err := c.Probe(context.Background()); !errors.Is(err, azurerbac.ErrCredential) {
		t.Errorf("err = %v", err)
	}
}

// The result ingests into the graph: every edge names a record of the same result, and a second sync
// with the same data changes nothing.
func TestIngestsIntoTheGraph(t *testing.T) {
	r := newRig(t, &fake{})
	db := testkit.Open(t)
	tn := tenancy.MustParse("00000000-0000-4000-8000-0000000000e1")
	testkit.CreateTenant(t, db, tn, "azure-rbac")
	for i := 0; i < 2; i++ {
		var st ingest.SyncStats
		err := db.InTenant(context.Background(), tn, func(c *store.TenantTx) error {
			var err error
			st, err = ingest.Sync(c, testkit.Now, []connectors.Connector{r.open(t)}, nil)
			return err
		})
		if err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
		if d := st.Discovery; d.Accounts != 2 || d.Groups != 1 || d.Permissions != 5 || d.Edges != 5 || d.Resources != 4 {
			t.Errorf("sync %d: %+v", i, d)
		}
	}
}
