package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// The connector types that have a connector (internal/connectors) are creatable
// as governed connections: the same create, checklist and credential routes as
// every other type, with the checklist of the type's template.
func TestGovernedConnections_CreateOverAPI(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	want := map[string]string{"awsorg": "awsorg", "githubscan": "githubscan", "sap": "erp", "oracle": "erp", "cyberark": "pam",
		"beyondtrust": "pam", "delinea": "pam", "fieldglass": "vms", "beeline": "vms", "csvfeed": "vms", "agentcore": "agentcore"}
	cfg := map[string]string{
		"awsorg":      `{"correlation_key":"arn","settings":{"regions":"us-east-1","management_account_id":"111111111111","external_id":"tessera-abc123"}}`,
		"githubscan":  `{"settings":{"org":"acme"}}`,
		"sap":         `{"base_url":"https://s4.example.com","settings":{"client_id":"tessera"}}`,
		"oracle":      `{"base_url":"https://fa.example.com","settings":{"client_id":"tessera"}}`,
		"cyberark":    `{"base_url":"https://pvwa.example.com","settings":{"username":"svc"}}`,
		"beyondtrust": `{"base_url":"https://bt.example.com","settings":{"username":"svc"}}`,
		"delinea":     `{"base_url":"https://ss.example.com","settings":{"username":"svc"}}`,
		"fieldglass":  `{"base_url":"https://fg.example.com","correlation_key":"worker_id"}`,
		"beeline":     `{"base_url":"https://bl.example.com","correlation_key":"worker_id"}`,
		"csvfeed":     `{"base_url":"https://feeds.example.com","correlation_key":"worker_id","settings":{"csv_path":"/c.csv"}}`,
		"agentcore":   `{"settings":{"snapshot":"agentcore.json"}}`,
	}
	for typ, tmpl := range want {
		v := c.json("POST", "/api/connections", `{"name":"Gov `+typ+`","connector_type":"`+typ+`","config":`+cfg[typ]+`}`, http.StatusCreated)
		id := v["id"].(string)
		gt, _ := governed.Lookup(typ)
		if v["connector_type"] != typ || v["system"] != gt.System || v["state"] != "draft" || v["simulated"] == true {
			t.Errorf("%s: %v", typ, v)
		}
		cl := c.json("GET", "/api/connections/"+id+"/checklist", "", http.StatusOK)
		if tr := cl["template"].(map[string]any); tr["id"] != tmpl || !strings.HasPrefix(tr["pin"].(string), tmpl+"@") {
			t.Errorf("%s: template %v", typ, cl["template"])
		}
		if len(cl["items"].([]any)) < 15 {
			t.Errorf("%s: %d checklist items", typ, len(cl["items"].([]any)))
		}
		// the credential is write-only, as for every type
		c.json("PUT", "/api/connections/"+id+"/credential", `{"secret":"a-secret-value"}`, http.StatusOK)
		if raw := c.do("GET", "/api/connections/"+id, "").Body.String(); strings.Contains(raw, "a-secret-value") {
			t.Errorf("%s: the secret is in the connection view", typ)
		}
	}
	// the templates are listed with their connector types
	raw := c.do("GET", "/api/readiness/templates", "").Body.String()
	for _, tmpl := range []string{"awsorg", "githubscan", "erp", "pam", "vms", "agentcore"} {
		if !strings.Contains(raw, `"`+tmpl+`"`) {
			t.Errorf("template %s is not listed", tmpl)
		}
	}

	// input is validated at the boundary
	bad := c.json("POST", "/api/connections", `{"name":"Smuggled","system":"smuggled","connector_type":"cyberark","config":{"settings":{"username":"svc"},"password":"p"}}`, http.StatusUnprocessableEntity)
	if bad["error"] != "invalid_config" {
		t.Errorf("a password in the config: %v", bad)
	}
}

// A config the type does not accept is reported field by field, and blocks the
// first transition rather than the create.
func TestGovernedConnections_FieldErrors(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	v := c.json("POST", "/api/connections", `{"name":"Vault","connector_type":"cyberark","config":{"base_url":"https://pvwa.example.com/PasswordVault","settings":{"username":"svc","api_root":"/a/../b","org":"x"}}}`, http.StatusCreated)
	id := v["id"].(string)
	c.json("PUT", "/api/connections/"+id+"/credential", `{"secret":"a-secret-value"}`, http.StatusOK)
	r := c.json("PATCH", "/api/connections/"+id+"/config", `{"settings":{"username":"svc","api_root":"/a/../b"}}`, http.StatusOK)
	fields := map[string]bool{}
	for _, f := range r["fields"].([]any) {
		fields[f.(map[string]any)["field"].(string)] = true
	}
	if !fields["base_url"] || !fields["settings.api_root"] {
		t.Errorf("field errors = %v", fields)
	}
	r = c.json("PATCH", "/api/connections/"+id+"/config", `{"base_url":"https://pvwa.example.com","settings":{"username":"svc"}}`, http.StatusOK)
	if f, _ := r["fields"].([]any); len(f) != 0 {
		t.Errorf("a valid config still has errors: %v", r["fields"])
	}
}

const awsSecret = `{"access_key_id":"AKIAEXAMPLEEXAMPLE1","secret_access_key":"baseSecretKeyForTestsOnly0123456789abcd"}`

// Activating a contractor-feed connection creates the feed in the contractor
// feature, through its own sealing: the credential is bound to the new row, the
// settings are the feed's own, and a second activation keeps what exists.
func TestHandover_VMS(t *testing.T) {
	t.Parallel()
	st := testkit.Demo(t)
	sealer := testSealer()
	typ, _ := governed.Lookup(governed.Fieldglass)
	p := governed.Params{Type: governed.Fieldglass, BaseURL: "https://fg.example.com",
		Settings: map[string]string{"workers_path": "/api/v1/workers", "page_size": "50"}, Secret: "client-1:s3cret-value"}
	var id string
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = handoverVMS(c, sealer, "Fieldglass contractors", "conn-1", typ, p, testkit.Now)
		return err
	})
	var src *store.VmsSource
	testkit.Read(t, st, func(c *store.TenantTx) (err error) {
		src, err = c.VmsSource(id)
		return err
	})
	if src.Vendor != "fieldglass" || src.Name != "Fieldglass contractors" || src.BaseURL != p.BaseURL || src.Status != store.VmsActive ||
		!strings.Contains(src.Settings, `"page_size":50`) || !strings.Contains(src.Settings, "/api/v1/workers") || src.CreatedBy != "connection:conn-1" {
		t.Errorf("source = %+v", src)
	}
	if strings.Contains(string(src.CredentialEnc), "s3cret-value") || src.CredentialVer == nil {
		t.Error("the credential is not sealed")
	}
	pt, err := sealer.Open(src.CredentialEnc, seal.AAD(st.Tenant, "vms_sources", "credential_enc", src.ID))
	if err != nil || string(pt) != p.Secret {
		t.Errorf("the contractor feature cannot open the credential: %v", err)
	}
	// idempotent by name
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if _, err := handoverVMS(c, sealer, "Fieldglass contractors", "conn-1", typ, p, testkit.Now); !errors.Is(err, errHandoverExists) {
			t.Errorf("second hand-over: %v", err)
		}
		return nil
	})
	// settings the feed refuses are refused here too
	bad := p
	bad.Settings = map[string]string{"workers_path": "/a/../b"}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if _, err := handoverVMS(c, sealer, "Other feed", "conn-2", typ, bad, testkit.Now); err == nil {
			t.Error("invalid settings accepted")
		}
		return nil
	})
}

func TestHandover_CSVFeed(t *testing.T) {
	t.Parallel()
	st := testkit.Demo(t)
	typ, _ := governed.Lookup(governed.CSVFeed)
	p := governed.Params{Type: governed.CSVFeed, BaseURL: "https://feeds.example.com", Settings: map[string]string{"csv_path": "/feeds/c.csv"}, Secret: "tok"}
	var id string
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = handoverVMS(c, testSealer(), "CSV contractors", "conn-3", typ, p, testkit.Now)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		src, err := c.VmsSource(id)
		if err != nil || src.Vendor != "csv" || !strings.Contains(src.Settings, "/feeds/c.csv") {
			t.Errorf("source = %+v, %v", src, err)
		}
		return nil
	})
}

// Activating an AWS Organizations connection creates the AWS connector through
// the AWS service: the external id the probe used is the one the connector holds.
func TestHandover_AWS(t *testing.T) {
	t.Parallel()
	st := testkit.Demo(t)
	sealer := testSealer()
	p := governed.Params{Type: governed.AWSOrg, Secret: awsSecret, Settings: map[string]string{"regions": "us-east-1,eu-west-1",
		"management_account_id": "111111111111", "external_id": "tessera-abc123", "role_name": "TesseraReader"}}
	var id string
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = handoverAWS(c, sealer, "AWS production", p, testkit.Now)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		k, err := c.AWSConnector(id)
		if err != nil {
			return err
		}
		if k.ExternalID != "tessera-abc123" || k.Name != "AWS production" || !strings.Contains(string(k.Config), "eu-west-1") ||
			!strings.Contains(string(k.Config), "111111111111") {
			t.Errorf("connector = %+v", k)
		}
		if strings.Contains(string(k.CredentialsEnc), "baseSecretKey") {
			t.Error("the keys are not sealed")
		}
		creds, err := awsorg.OpenCredentials(sealer, c.Tenant(), k.ID, k.CredentialsEnc)
		if err != nil || creds.AccessKeyID != "AKIAEXAMPLEEXAMPLE1" {
			t.Errorf("the AWS feature cannot open the keys: %v", err)
		}
		return nil
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if _, err := handoverAWS(c, sealer, "AWS production", p, testkit.Now); !errors.Is(err, errHandoverExists) {
			t.Errorf("second hand-over: %v", err)
		}
		bad := p
		bad.Secret = `{"access_key_id":"x"}`
		if _, err := handoverAWS(c, sealer, "Another", bad, testkit.Now); err == nil {
			t.Error("bad keys accepted")
		}
		return nil
	})
}
