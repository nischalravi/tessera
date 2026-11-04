package foundryagents_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/foundryagents"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the endpoint and app registration from the stored config and the secret from the
// credential; only the dev overrides replace the endpoint and authority, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r, _ := newRig(t, nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := func(k string) string {
		switch k {
		case "TESSERA_FOUNDRY_ENDPOINT":
			return r.cfg.BaseURL
		case "TESSERA_FOUNDRY_AUTHORITY_URL":
			return r.srv.URL
		}
		return ""
	}
	// the dev override replaces the stored endpoint
	c, err := foundryagents.FromStored(foundryagents.Stored{BaseURL: "https://other.example.com", TenantID: tenant, ClientID: client, Credential: secret}, env, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Agents) != 3 || c.System() != "azure-foundry" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	prod := connsync.Runtime{Env: "prod"}
	good := foundryagents.Stored{BaseURL: "https://acme.services.ai.azure.com/api/projects/support", TenantID: tenant, ClientID: client, Credential: secret}
	if _, err := foundryagents.FromStored(good, noEnv, prod, hc, nil); err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("the error echoes the credential: %v", err)
	}
	for name, mut := range map[string]func(*foundryagents.Stored){
		"no credential": func(s *foundryagents.Stored) { s.Credential = "" },
		"no endpoint":   func(s *foundryagents.Stored) { s.BaseURL = "" },
		"other host":    func(s *foundryagents.Stored) { s.BaseURL = "https://evil.example.com/api/projects/x" },
		"metadata":      func(s *foundryagents.Stored) { s.BaseURL = "https://169.254.169.254" },
		"bad tenant":    func(s *foundryagents.Stored) { s.TenantID = "not-a-guid" },
		"bad client":    func(s *foundryagents.Stored) { s.ClientID = "" },
	} {
		s := good
		mut(&s)
		if _, err := foundryagents.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
