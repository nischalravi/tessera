package servicenow_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func prodClient(t testing.TB) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

// FromStored reads the instance and sign-in from the stored config and the secret from the credential,
// refuses what does not open without echoing the secret, and lets only the dev override replace the base URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	const secret = "SN-SECRET-VALUE"
	for _, tc := range []struct {
		name string
		s    servicenow.Stored
		good bool
	}{
		{"basic", servicenow.Stored{BaseURL: "https://acme.service-now.com", Username: "svc", Credential: secret}, true},
		{"oauth", servicenow.Stored{BaseURL: "https://acme.service-now.com", AuthMode: "oauth", Username: "client-1", Credential: secret}, true},
		{"gov cloud", servicenow.Stored{BaseURL: "https://acme.servicenowservices.com", Username: "svc", Credential: secret}, true},
		{"no credential", servicenow.Stored{BaseURL: "https://acme.service-now.com", Username: "svc"}, false},
		{"no base url", servicenow.Stored{Username: "svc", Credential: secret}, false},
		{"no user", servicenow.Stored{BaseURL: "https://acme.service-now.com", Credential: secret}, false},
		{"bad mode", servicenow.Stored{BaseURL: "https://acme.service-now.com", AuthMode: "saml", Username: "svc", Credential: secret}, false},
		{"http", servicenow.Stored{BaseURL: "http://acme.service-now.com", Username: "svc", Credential: secret}, false},
		{"not servicenow", servicenow.Stored{BaseURL: "https://evil.example.com", Username: "svc", Credential: secret}, false},
		{"metadata host", servicenow.Stored{BaseURL: "https://169.254.169.254", Username: "svc", Credential: secret}, false},
		{"path", servicenow.Stored{BaseURL: "https://acme.service-now.com/api", Username: "svc", Credential: secret}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := servicenow.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error echoes the secret: %v", err)
				}
				return
			}
			if c.System() != "servicenow" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	env := func(k string) string {
		if k == "TESSERA_SERVICENOW_BASE_URL" {
			return "https://other.service-now.com"
		}
		return ""
	}
	if _, err := servicenow.FromStored(servicenow.Stored{Username: "svc", Credential: secret}, env, prod, hc, nil); err != nil {
		t.Errorf("override: %v", err)
	}
}
