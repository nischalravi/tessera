package wire_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
)

const (
	azTenant = "11111111-2222-3333-4444-555555555555"
	azClient = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	azSub    = "aaaa1111-0000-0000-0000-000000000001"
	azUser   = "11110000-0000-0000-0000-000000000001"
	azSecret = "az-secret-value"
)

// azureFake answers the token endpoint and the four ARM reads the connector makes.
func azureFake() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		_ = r.ParseForm()
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			if r.Form.Get("client_secret") != azSecret {
				w.WriteHeader(401)
				out(map[string]string{"error": "invalid_client"})
				return
			}
			out(map[string]any{"access_token": "t", "token_type": "Bearer", "expires_in": 3600})
		case r.Header.Get("Authorization") != "Bearer t":
			w.WriteHeader(401)
		case r.URL.Path == "/subscriptions":
			out(map[string]any{"value": []any{map[string]any{"subscriptionId": azSub, "displayName": "Prod", "state": "Enabled"}}})
		case strings.HasSuffix(r.URL.Path, "/roleDefinitions"):
			out(map[string]any{"value": []any{map[string]any{"id": "/subscriptions/" + azSub + "/providers/Microsoft.Authorization/roleDefinitions/r1",
				"properties": map[string]any{"roleName": "Owner", "permissions": []any{map[string]any{"actions": []string{"*"}}}}}}})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments"):
			out(map[string]any{"value": []any{map[string]any{"id": "/subscriptions/" + azSub + "/providers/Microsoft.Authorization/roleAssignments/a1",
				"properties": map[string]any{"principalId": azUser, "principalType": "User", "scope": "/subscriptions/" + azSub,
					"roleDefinitionId": "/subscriptions/" + azSub + "/providers/Microsoft.Authorization/roleDefinitions/r1"}}}})
		default:
			w.WriteHeader(404)
		}
	})
}

func azureParams() governed.Params {
	return governed.Params{Type: governed.AzureRBAC, Secret: azSecret, Settings: map[string]string{"tenant_id": azTenant, "client_id": azClient}}
}

func azureNet(t *testing.T) governed.Net {
	srv, n := serve(t, azureFake())
	n.Endpoints = map[string]string{"TESSERA_AZURE_MANAGEMENT_URL": srv.URL, "TESSERA_AZURE_AUTHORITY_URL": srv.URL}
	return n
}

func TestAzureRBACProberAndConnector(t *testing.T) {
	n := azureNet(t)
	p := prober(t, azureParams(), n)
	wantPass(t, p, "azurerbac", "auth_ok", "read_probe")
	auth, err := p.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Identity != azClient || auth.Mode != "client_secret" {
		t.Errorf("auth = %+v, err = %v", auth, err)
	}
	st, err := p.Sample(context.Background(), connectors.SampleQuery{})
	if err != nil || !st.Available || st.PerClass["scope"] != 1 || st.PerClass["assignment"] != 1 {
		t.Errorf("sample = %+v, err = %v", st, err)
	}
	cn, err := wire.Connector(azureParams(), n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "azure" || len(res.Permissions) != 1 || !res.Permissions[0].Privileged || res.Stats == nil {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	// the wrong secret is an answer to the authentication check, not a failure of the probe
	bad := azureParams()
	bad.Secret = "wrong"
	auth, err = prober(t, bad, azureNet(t)).Authenticate(context.Background())
	if err != nil || auth.OK {
		t.Errorf("wrong secret: %+v, %v", auth, err)
	}
}

// gcpFake answers the token endpoint and the reads of one project.
func gcpFake() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.URL.Path == "/token":
			_ = r.ParseForm()
			if strings.Count(r.Form.Get("assertion"), ".") != 2 {
				w.WriteHeader(400)
				return
			}
			out(map[string]any{"access_token": "g", "token_type": "Bearer", "expires_in": 3600})
		case r.Header.Get("Authorization") != "Bearer g":
			w.WriteHeader(401)
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			out(map[string]any{"bindings": []any{map[string]any{"role": "roles/owner", "members": []string{"user:alice@example.com"}}}})
		case strings.HasPrefix(r.URL.Path, "/v1/roles/"):
			out(map[string]any{"title": "Owner", "includedPermissions": []string{"resourcemanager.projects.setIamPolicy"}})
		case strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
			out(map[string]any{})
		default:
			w.WriteHeader(404)
		}
	})
}

func gcpKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	js, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "r@proj-12345.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	return string(js)
}

func gcpParams(t *testing.T) governed.Params {
	return governed.Params{Type: governed.GCPIAM, Secret: gcpKey(t), Settings: map[string]string{"project_ids": "alpha-proj-1"}}
}

func TestGCPIAMProberAndConnector(t *testing.T) {
	srv, n := serve(t, gcpFake())
	n.Endpoints = map[string]string{"TESSERA_GCP_CRM_URL": srv.URL, "TESSERA_GCP_IAM_URL": srv.URL, "TESSERA_GCP_TOKEN_URL": srv.URL + "/token"}
	p := prober(t, gcpParams(t), n)
	wantPass(t, p, "gcpiam", "auth_ok", "read_probe")
	auth, err := p.Authenticate(context.Background())
	if err != nil || !auth.OK || auth.Identity != "r@proj-12345.iam.gserviceaccount.com" || auth.Mode != "json_key" {
		t.Errorf("auth = %+v, err = %v", auth, err)
	}
	cn, err := wire.Connector(gcpParams(t), n)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || cn.System() != "gcp" || len(res.Permissions) != 1 || !res.Permissions[0].Privileged {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

// A connection never carries an endpoint, so in prod (and in test) it reaches the public cloud only; an
// override handed to a non-dev runtime is refused by the wiring and again by the connector.
func TestCloudEndpointOverridesAreRefusedOutsideDev(t *testing.T) {
	srv, n := serve(t, azureFake())
	for _, env := range []string{config.Prod, config.Test} {
		n.RT = connsync.Runtime{Env: env}
		n.Endpoints = map[string]string{"TESSERA_AZURE_MANAGEMENT_URL": srv.URL}
		if _, err := wire.Prober(azureParams(), n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
			t.Errorf("%s prober: %v", env, err)
		}
		if _, err := wire.Connector(azureParams(), n); err == nil {
			t.Errorf("%s connector accepted an override", env)
		}
	}
	n.RT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}
	n.Endpoints = map[string]string{"TESSERA_AZURE_MANAGEMENT_URL": srv.URL, "HTTP_PROXY": "http://evil.example.com"}
	if _, err := wire.Prober(azureParams(), n); err == nil || !strings.Contains(err.Error(), "not an endpoint override") {
		t.Errorf("unknown key: %v", err)
	}
	// without overrides a prod connection builds against the public cloud and never dials at build time
	n.RT, n.Endpoints = connsync.Runtime{Env: config.Prod}, nil
	if _, err := wire.Prober(azureParams(), n); err != nil {
		t.Errorf("prod without overrides: %v", err)
	}
	if _, err := wire.Connector(gcpParams(t), n); err != nil {
		t.Errorf("prod gcp without overrides: %v", err)
	}
}

func TestCloudParamsNeverPrintTheSecret(t *testing.T) {
	p := azureParams()
	if s := p.String(); strings.Contains(s, azSecret) {
		t.Errorf("params print the secret: %s", s)
	}
	for _, typ := range []string{governed.AzureRBAC, governed.GCPIAM} {
		if ty, _ := governed.Lookup(typ); ty.Feature {
			t.Errorf("%s hands over to a feature; it is read by the connector sync", typ)
		}
	}
}
