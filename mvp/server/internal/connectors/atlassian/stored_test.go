package atlassian_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
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

// FromStored reads the site, account and scope from the stored config and the token (and the optional
// admin key) from the credential, refuses what does not open without echoing them, and lets only the dev
// overrides replace the site and admin URLs.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	const token = "ATATT-SECRET-TOKEN"
	const site = "https://acme.atlassian.net"
	withAdmin := `{"api_token":"` + token + `","admin_api_key":"ADMIN-SECRET"}`
	for _, tc := range []struct {
		name string
		s    atlassian.Stored
		good bool
	}{
		{"token", atlassian.Stored{BaseURL: site, Email: "a@acme.example", Credential: token}, true},
		{"projects", atlassian.Stored{BaseURL: site, Email: "a@acme.example", ProjectKeys: "PROJ, OPS", Credential: token}, true},
		{"admin", atlassian.Stored{BaseURL: site, Email: "a@acme.example", OrgID: "org-1", Credential: withAdmin}, true},
		{"org without key", atlassian.Stored{BaseURL: site, Email: "a@acme.example", OrgID: "org-1", Credential: token}, false},
		{"key without org", atlassian.Stored{BaseURL: site, Email: "a@acme.example", Credential: withAdmin}, false},
		{"no credential", atlassian.Stored{BaseURL: site, Email: "a@acme.example"}, false},
		{"bad credential", atlassian.Stored{BaseURL: site, Email: "a@acme.example", Credential: "two words"}, false},
		{"no email", atlassian.Stored{BaseURL: site, Credential: token}, false},
		{"no base url", atlassian.Stored{Email: "a@acme.example", Credential: token}, false},
		{"bad project key", atlassian.Stored{BaseURL: site, Email: "a@acme.example", ProjectKeys: "x y", Credential: token}, false},
		{"http", atlassian.Stored{BaseURL: "http://acme.atlassian.net", Email: "a@acme.example", Credential: token}, false},
		{"not atlassian", atlassian.Stored{BaseURL: "https://evil.example.com", Email: "a@acme.example", Credential: token}, false},
		{"admin host as site", atlassian.Stored{BaseURL: "https://api.atlassian.com", Email: "a@acme.example", Credential: token}, false},
		{"metadata host", atlassian.Stored{BaseURL: "https://169.254.169.254", Email: "a@acme.example", Credential: token}, false},
		{"path", atlassian.Stored{BaseURL: site + "/wiki", Email: "a@acme.example", Credential: token}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := atlassian.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "ADMIN-SECRET") {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "atlassian" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	// the admin URL override is a dev setting: in prod the loopback fake is refused
	env := func(k string) string {
		if k == "TESSERA_ATLASSIAN_ADMIN_URL" {
			return "https://127.0.0.1:9"
		}
		return ""
	}
	if _, err := atlassian.FromStored(atlassian.Stored{BaseURL: site, Email: "a@acme.example", OrgID: "org-1", Credential: withAdmin}, env, prod, hc, nil); err == nil {
		t.Error("prod accepted an admin URL override")
	}
	env = func(k string) string {
		if k == "TESSERA_ATLASSIAN_BASE_URL" {
			return "https://other.atlassian.net"
		}
		return ""
	}
	if _, err := atlassian.FromStored(atlassian.Stored{Email: "a@acme.example", Credential: token}, env, prod, hc, nil); err != nil {
		t.Errorf("base override: %v", err)
	}
}
