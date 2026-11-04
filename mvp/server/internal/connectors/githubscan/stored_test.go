package githubscan

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
)

// FromStored reads the organization and API URL from the stored config and the token from the
// credential, never from the environment; only the dev override replaces the API URL.
func TestFromStored(t *testing.T) {
	f := newFakeGitHub(t)
	hc := testClient(t, f.srv, 0)
	noEnv := func(string) string { return "" }
	c, err := FromStored(Stored{Org: "acme", BaseURL: f.srv.URL, Credential: testToken}, noEnv, connsynctest.Runtime, hc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Discover(context.Background())
	if err != nil || c.System() != System || len(res.AgentSnapshotOf) != 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	// the dev override replaces the stored URL
	env := func(k string) string {
		if k == "TESSERA_GITHUB_SCAN_API_URL" {
			return f.srv.URL
		}
		return ""
	}
	if _, err := FromStored(Stored{Org: "acme", BaseURL: "https://other.example.com", Credential: testToken}, env, connsynctest.Runtime, hc); err != nil {
		t.Errorf("override: %v", err)
	}
	prod := connsync.Runtime{Env: "prod"}
	for name, s := range map[string]Stored{
		"no credential": {Org: "acme", BaseURL: f.srv.URL},
		"bad org":       {Org: "../acme", BaseURL: f.srv.URL, Credential: testToken},
		"no org":        {BaseURL: f.srv.URL, Credential: testToken},
		"http":          {Org: "acme", BaseURL: "http://ghe.example.com/api/v3", Credential: testToken},
		"metadata":      {Org: "acme", BaseURL: "https://169.254.169.254/api/v3", Credential: testToken},
		"metadata name": {Org: "acme", BaseURL: "https://metadata.google.internal", Credential: testToken},
	} {
		_, err := FromStored(s, noEnv, prod, hc)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: the error echoes the token: %v", name, err)
		}
	}
	// GitHub.com is the default when no URL is stored
	if _, err := FromStored(Stored{Org: "acme", Credential: testToken}, noEnv, prod, hc); err != nil {
		t.Errorf("default URL: %v", err)
	}
}
