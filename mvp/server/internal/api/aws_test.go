package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

const awsTestSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

func awsCreateBody(name string) string {
	return `{"name":"` + name + `","config":{"regions":["us-east-1"],"management_account_id":"111111111111"},` +
		`"credentials":{"access_key_id":"AKIAEXAMPLEEXAMPLE1","secret_access_key":"` + awsTestSecret + `"}}`
}

func newAWSClient(t *testing.T) rdClient {
	t.Helper()
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return newRD(t, func(c *Config) { c.Sealer = s })
}

func TestAWSAPI_ConnectorLifecycle(t *testing.T) {
	c := newAWSClient(t)

	rec := c.do("POST", "/api/aws/connectors", awsCreateBody("prod"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	created := rec.Body.String()
	v := c.json("GET", "/api/aws/connectors", "", 200)
	items := v["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	k := items[0].(map[string]any)
	if k["credentials_set"] != true || k["status"] != "idle" || !strings.HasPrefix(k["external_id"].(string), "tessera-") || k["name"] != "prod" {
		t.Errorf("connector = %v", k)
	}
	if cfg := k["config"].(map[string]any); cfg["role_name"] != "TesseraReader" {
		t.Errorf("config = %v", cfg)
	}
	if len(v["reader_actions"].([]any)) == 0 {
		t.Error("the reader actions are not listed")
	}

	// the credentials are never returned, by any route
	list := c.do("GET", "/api/aws/connectors", "").Body.String()
	for _, body := range []string{created, list} {
		for _, secret := range []string{awsTestSecret, "AKIAEXAMPLEEXAMPLE1", "credentials_enc", "secret_access_key"} {
			if strings.Contains(body, secret) {
				t.Errorf("a response contains %q: %s", secret, body)
			}
		}
	}

	// the sealed blob in the store is not the secret either
	c.read(func(tx *store.TenantTx) error {
		ks, err := tx.AWSConnectors()
		if err != nil || len(ks) != 1 || strings.Contains(string(ks[0].CredentialsEnc), awsTestSecret) || len(ks[0].CredentialsEnc) == 0 {
			t.Errorf("stored connector = %v, %v", ks, err)
		}
		return err
	})

	// duplicate name
	if rec := c.do("POST", "/api/aws/connectors", awsCreateBody("prod")); rec.Code != http.StatusConflict {
		t.Errorf("duplicate = %d: %s", rec.Code, rec.Body.String())
	}
	id := k["id"].(string)
	_ = c.json("DELETE", "/api/aws/connectors/"+id, "", 200)
	if rec := c.do("DELETE", "/api/aws/connectors/"+id, ""); rec.Code != http.StatusNotFound {
		t.Errorf("second delete = %d", rec.Code)
	}
	if rec := c.do("DELETE", "/api/aws/connectors/not-an-id", ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete of a malformed id = %d", rec.Code)
	}
}

func TestAWSAPI_CreateValidatesInput(t *testing.T) {
	c := newAWSClient(t)
	for name, body := range map[string]string{
		"no body":          ``,
		"unknown field":    `{"name":"x","config":{"regions":["us-east-1"],"management_account_id":"111111111111"},"credentials":{"access_key_id":"AKIAEXAMPLEEXAMPLE1","secret_access_key":"` + awsTestSecret + `"},"extra":1}`,
		"no name":          strings.Replace(awsCreateBody("x"), `"name":"x"`, `"name":""`, 1),
		"bad region":       strings.Replace(awsCreateBody("x"), "us-east-1", "us-east-1.evil.example", 1),
		"bad account":      strings.Replace(awsCreateBody("x"), "111111111111", "1111", 1),
		"short secret":     strings.Replace(awsCreateBody("x"), awsTestSecret, "short", 1),
		"no credentials":   `{"name":"x","config":{"regions":["us-east-1"],"management_account_id":"111111111111"}}`,
		"trailing garbage": awsCreateBody("x") + `{}`,
	} {
		if rec := c.do("POST", "/api/aws/connectors", body); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := c.do("POST", "/api/aws/connectors", awsCreateBody("x")); rec.Code != http.StatusCreated {
		t.Errorf("the valid body: %d %s", rec.Code, rec.Body.String())
	}
	// no secret in any error either
	rec := c.do("POST", "/api/aws/connectors", strings.Replace(awsCreateBody("x"), "111111111111", "1111", 1))
	if strings.Contains(rec.Body.String(), awsTestSecret) {
		t.Errorf("the error echoes the secret: %s", rec.Body.String())
	}
}

func TestAWSAPI_WithoutSealerRefuses(t *testing.T) {
	c := newRD(t)
	if rec := c.do("POST", "/api/aws/connectors", awsCreateBody("x")); rec.Code < 400 {
		t.Errorf("created a connector with no KEK: %d", rec.Code)
	}
}

func TestAWSAPI_Snapshots(t *testing.T) {
	c := newAWSClient(t)
	if items := c.json("GET", "/api/aws/snapshots", "", 200)["items"].([]any); len(items) != 0 {
		t.Fatalf("items = %v", items)
	}
	id := strings.Repeat("ab", 32)
	if err := c.st.DB.InTenant(context.Background(), c.st.Tenant, func(tx *store.TenantTx) error {
		if _, err := tx.PutAWSSnapshot(&store.AWSSnapshot{ID: id, TakenAt: testkit.Now, AccountIDs: []string{"111111111111"},
			CatalogVersion: "v", Source: store.AWSSourceConnector}); err != nil {
			return err
		}
		return tx.AddAWSFinding(&store.AWSFinding{SnapshotID: id, Kind: store.AWSFindingPolicyUnparseable, SourceARN: "arn:x", PolicyKind: "scp",
			Code: "invalid_json", Detail: "bad", Scope: []byte(`{"type":"accounts","targets":[]}`)})
	}); err != nil {
		t.Fatal(err)
	}
	items := c.json("GET", "/api/aws/snapshots", "", 200)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != id {
		t.Fatalf("items = %v", items)
	}
	got := c.json("GET", "/api/aws/snapshots/"+id, "", 200)
	fs := got["findings"].([]any)
	if len(fs) != 1 || fs[0].(map[string]any)["code"] != "invalid_json" || got["snapshot"].(map[string]any)["source"] != "connector" {
		t.Errorf("snapshot = %v", got)
	}
	for _, bad := range []string{"nope", strings.Repeat("0", 64), strings.Repeat("A", 64)} {
		if rec := c.do("GET", "/api/aws/snapshots/"+bad, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d", bad, rec.Code)
		}
	}
}
