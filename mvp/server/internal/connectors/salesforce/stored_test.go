package salesforce_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
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

// FromStored reads the base URL and API version from the stored config and the client from the
// sealed credential, refuses what does not open without echoing the key, and lets only the dev
// override replace the stored base URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	_, pemText := keyPEM(t)
	cred := func(m map[string]string) string {
		b, _ := json.Marshal(m)
		return string(b)
	}
	good := cred(map[string]string{"client_id": consumerKey, "username": integration, "private_key": pemText})
	const org = "https://acme.my.salesforce.com"
	for _, tc := range []struct {
		name string
		s    salesforce.Stored
		good bool
		leak string
	}{
		{"ok", salesforce.Stored{BaseURL: org, Credential: good}, true, ""},
		{"api version", salesforce.Stored{BaseURL: org, APIVersion: "v58.0", Credential: good}, true, ""},
		{"sandbox login", salesforce.Stored{BaseURL: org, Credential: cred(map[string]string{"client_id": "k", "username": integration, "private_key": pemText, "login_url": "https://test.salesforce.com"})}, true, ""},
		{"no credential", salesforce.Stored{BaseURL: org}, false, ""},
		{"not JSON", salesforce.Stored{BaseURL: org, Credential: "PLAIN-SECRET"}, false, "PLAIN-SECRET"},
		{"no key", salesforce.Stored{BaseURL: org, Credential: cred(map[string]string{"client_id": "k", "username": integration})}, false, ""},
		{"no base url", salesforce.Stored{Credential: good}, false, pemText},
		{"http", salesforce.Stored{BaseURL: "http://acme.my.salesforce.com", Credential: good}, false, pemText},
		{"not salesforce", salesforce.Stored{BaseURL: "https://evil.example.com", Credential: good}, false, pemText},
		{"metadata host", salesforce.Stored{BaseURL: "https://169.254.169.254", Credential: good}, false, pemText},
		{"path", salesforce.Stored{BaseURL: org + "/services", Credential: good}, false, pemText},
		{"login not salesforce", salesforce.Stored{BaseURL: org, Credential: cred(map[string]string{"client_id": "k", "username": integration, "private_key": pemText, "login_url": "https://evil.example.com"})}, false, pemText},
		{"bad version", salesforce.Stored{BaseURL: org, APIVersion: "61", Credential: good}, false, pemText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := salesforce.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if tc.leak != "" && strings.Contains(err.Error(), tc.leak) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "salesforce" {
				t.Errorf("connector %T (system %q)", c, c.System())
			}
		})
	}
	// the dev override replaces the stored base URL (refused outside dev by the caller)
	env := func(k string) string {
		if k == "TESSERA_SALESFORCE_BASE_URL" {
			return "https://other.my.salesforce.com"
		}
		return ""
	}
	if _, err := salesforce.FromStored(salesforce.Stored{Credential: good}, env, prod, hc, nil); err != nil {
		t.Errorf("override: %v", err)
	}
}
