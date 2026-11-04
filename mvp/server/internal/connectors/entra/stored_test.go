package entra

import (
	"strings"
	"testing"
)

// FromStored reads the tenant and cloud from the stored config and the client from the sealed
// credential, refuses what does not open without echoing the credential, and lets only the dev
// overrides replace the cloud's endpoints.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	const tenant = "11111111-2222-3333-4444-555555555555"
	const cred = `{"client_id":"app-1","client_secret":"S3CRET-VALUE"}`
	for _, tc := range []struct {
		name       string
		s          Stored
		graph      string
		good       bool
		wantNoLeak string
	}{
		{"default cloud", Stored{TenantID: tenant, Credential: cred}, "https://graph.microsoft.com", true, ""},
		{"global", Stored{TenantID: tenant, Cloud: "global", Credential: cred}, "https://graph.microsoft.com", true, ""},
		{"usgov", Stored{TenantID: tenant, Cloud: "usgov", Credential: cred}, "https://graph.microsoft.us", true, ""},
		{"china", Stored{TenantID: tenant, Cloud: "china", Credential: cred}, "https://microsoftgraph.chinacloudapi.cn", true, ""},
		{"unknown cloud", Stored{TenantID: tenant, Cloud: "evil.example", Credential: cred}, "", false, "S3CRET-VALUE"},
		{"no credential", Stored{TenantID: tenant}, "", false, ""},
		{"credential is not JSON", Stored{TenantID: tenant, Credential: "S3CRET-VALUE-plain"}, "", false, "S3CRET-VALUE-plain"},
		{"no secret", Stored{TenantID: tenant, Credential: `{"client_id":"app-1"}`}, "", false, ""},
		{"no client id", Stored{TenantID: tenant, Credential: `{"client_secret":"S3CRET-VALUE"}`}, "", false, "S3CRET-VALUE"},
		{"tenant is a domain", Stored{TenantID: "acme.onmicrosoft.com", Credential: cred}, "", false, "S3CRET-VALUE"},
		{"no tenant", Stored{Credential: cred}, "", false, "S3CRET-VALUE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := FromStored(tc.s, noEnv, prodRT, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if tc.wantNoLeak != "" && strings.Contains(err.Error(), tc.wantNoLeak) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			e := c.(*Connector)
			if e.base.String() != tc.graph || e.cfg.TenantID != tenant || !e.cfg.EmitIdentities || !e.cfg.SignInActivity || e.cfg.SkipAuthMethods {
				t.Errorf("base %s, config %+v", e.base, e.cfg)
			}
		})
	}
	env := func(k string) string {
		switch k {
		case "TESSERA_ENTRA_GRAPH_URL":
			return "https://graph.override.example"
		case "TESSERA_ENTRA_AUTHORITY_URL":
			return "https://login.override.example"
		}
		return ""
	}
	c, err := FromStored(Stored{TenantID: tenant, Credential: cred}, env, prodRT, hc, nil)
	if err != nil || c.(*Connector).base.Host != "graph.override.example" {
		t.Errorf("override: %v", err)
	}
}
