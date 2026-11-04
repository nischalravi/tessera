package azurerbac_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/azurerbac"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the app registration and scope from the stored config and the secret from the
// credential, refuses what does not open without echoing the secret, and lets only the dev overrides
// replace the Azure endpoints (a loopback fake is refused in prod).
func TestFromStored(t *testing.T) {
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	noEnv := func(string) string { return "" }
	prod := connsync.Runtime{Env: "prod"}
	const sec = "AZ-SECRET-VALUE"
	ok := azurerbac.Stored{TenantID: tenant, ClientID: clientID, Credential: sec}
	with := func(f func(*azurerbac.Stored)) azurerbac.Stored { s := ok; f(&s); return s }
	for _, tc := range []struct {
		name string
		s    azurerbac.Stored
		good bool
	}{
		{"secret", ok, true},
		{"scopes", with(func(s *azurerbac.Stored) {
			s.SubscriptionIDs, s.ManagementGroupIDs, s.IncludeEligible = subA+", "+subB, "mg-root", "true"
		}), true},
		{"no credential", with(func(s *azurerbac.Stored) { s.Credential = "" }), false},
		{"no tenant", with(func(s *azurerbac.Stored) { s.TenantID = "" }), false},
		{"bad tenant", with(func(s *azurerbac.Stored) { s.TenantID = "contoso.onmicrosoft.com" }), false},
		{"bad client", with(func(s *azurerbac.Stored) { s.ClientID = "x" }), false},
		{"bad subscription", with(func(s *azurerbac.Stored) { s.SubscriptionIDs = "not-a-guid" }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := azurerbac.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), sec) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "azure" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	for _, key := range []string{"TESSERA_AZURE_MANAGEMENT_URL", "TESSERA_AZURE_AUTHORITY_URL"} {
		env := func(k string) string {
			if k == key {
				return "https://127.0.0.1:9"
			}
			return ""
		}
		if _, err := azurerbac.FromStored(ok, env, prod, hc, nil); err == nil {
			t.Errorf("prod accepted %s", key)
		}
	}
}
