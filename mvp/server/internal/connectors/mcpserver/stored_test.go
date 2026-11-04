package mcpserver_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/mcpserver"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the endpoint and settings from the stored config and the token from the credential;
// only the dev override replaces the URL, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r := newRig(t, nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, connsynctest.New(t, r.fake).Options(0))
	c, err := mcpserver.FromStored(mcpserver.Stored{URL: r.cfg.URL, Owner: "olu@acme.example", Credential: token}, noEnv, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Identities) != 1 || len(res.MCPFindings) != 1 || c.System() != "mcp" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	env := func(k string) string {
		if k == "TESSERA_MCP_URL" {
			return r.cfg.URL
		}
		return ""
	}
	if _, err := mcpserver.FromStored(mcpserver.Stored{URL: "https://other.example.com/mcp", Credential: token}, env, connsynctest.Runtime, hc, nil); err != nil {
		t.Errorf("override: %v", err)
	}
	prod := connsync.Runtime{Env: "prod"}
	for name, s := range map[string]mcpserver.Stored{
		"no credential": {URL: r.cfg.URL},
		"no url":        {Credential: token},
		"http":          {URL: "http://tools.acme.example/mcp", Credential: token},
		"metadata":      {URL: "https://169.254.169.254/mcp", Credential: token},
		"bad header":    {URL: "https://tools.acme.example/mcp", AuthHeader: "Host", Credential: token},
		"bad owner":     {URL: "https://tools.acme.example/mcp", Owner: "not an email", Credential: token},
	} {
		if _, err := mcpserver.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), token) {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
