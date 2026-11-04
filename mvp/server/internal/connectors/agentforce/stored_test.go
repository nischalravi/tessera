package agentforce_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the org URL and API version from the stored config and the key bundle from the
// credential; only the dev override replaces the URL, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r := newRig(t, nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := func(k string) string {
		if k == "TESSERA_AGENTFORCE_BASE_URL" {
			return r.srv.URL
		}
		return ""
	}
	c, err := agentforce.FromStored(agentforce.Stored{BaseURL: "https://other.example.com", Credential: r.cred}, env, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Agents) != 2 || c.System() != "salesforce-agentforce" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	prod := connsync.Runtime{Env: "prod"}
	for name, s := range map[string]agentforce.Stored{
		"no credential": {BaseURL: "https://acme.my.salesforce.com"},
		"no url":        {Credential: r.cred},
		"other host":    {BaseURL: "https://evil.example.com", Credential: r.cred},
		"metadata":      {BaseURL: "https://169.254.169.254", Credential: r.cred},
		"bad version":   {BaseURL: "https://acme.my.salesforce.com", APIVersion: "../x", Credential: r.cred},
		"not json":      {BaseURL: "https://acme.my.salesforce.com", Credential: "not-json-secret-value"},
	} {
		if _, err := agentforce.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "not-json-secret-value") || strings.Contains(err.Error(), r.cred) {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
