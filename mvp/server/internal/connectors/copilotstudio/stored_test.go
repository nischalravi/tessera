package copilotstudio_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/copilotstudio"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the endpoint and app registration from the stored config and the secret from the
// credential; only the dev overrides replace the endpoint and authority, and a refusal never echoes the credential.
func TestFromStored(t *testing.T) {
	r := newRig(t, nil)
	noEnv := func(string) string { return "" }
	hc, _ := safehttp.NewForTest(t, r.srv.Options(0))
	env := func(k string) string {
		switch k {
		case "TESSERA_COPILOT_URL":
			return r.srv.URL
		case "TESSERA_COPILOT_AUTHORITY_URL":
			return r.srv.URL
		}
		return ""
	}
	// the dev override replaces the stored endpoint
	c, err := copilotstudio.FromStored(copilotstudio.Stored{BaseURL: "https://other.example.com", TenantID: tenant, ClientID: client, Credential: secret}, env, connsynctest.Runtime, hc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Discover(context.Background()); err != nil || len(res.Agents) != 3 || c.System() != "copilot-studio" {
		t.Errorf("Discover = %v, %v", res, err)
	}
	prod := connsync.Runtime{Env: "prod"}
	good := copilotstudio.Stored{BaseURL: "https://acme.crm.dynamics.com", TenantID: tenant, ClientID: client, Credential: secret}
	if _, err := copilotstudio.FromStored(good, noEnv, prod, hc, nil); err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("the error echoes the credential: %v", err)
	}
	for name, mut := range map[string]func(*copilotstudio.Stored){
		"no credential": func(s *copilotstudio.Stored) { s.Credential = "" },
		"no endpoint":   func(s *copilotstudio.Stored) { s.BaseURL = "" },
		"other host":    func(s *copilotstudio.Stored) { s.BaseURL = "https://evil.example.com" },
		"metadata":      func(s *copilotstudio.Stored) { s.BaseURL = "https://169.254.169.254" },
		"bad tenant":    func(s *copilotstudio.Stored) { s.TenantID = "not-a-guid" },
		"bad client":    func(s *copilotstudio.Stored) { s.ClientID = "" },
	} {
		s := good
		mut(&s)
		if _, err := copilotstudio.FromStored(s, noEnv, prod, hc, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}
