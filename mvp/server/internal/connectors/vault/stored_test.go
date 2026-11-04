package vault_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vault"
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

// FromStored reads the server and namespace from the stored config and the token from the credential,
// refuses what does not open without echoing the token, and lets only the dev override replace the URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	const tok = "hvs.SECRET-TOKEN"
	const srv = "https://vault.example.com:8200"
	for _, tc := range []struct {
		name string
		s    vault.Stored
		good bool
	}{
		{"token", vault.Stored{BaseURL: srv, Credential: tok}, true},
		{"namespace", vault.Stored{BaseURL: srv, Namespace: "admin/team-a", Credential: tok}, true},
		{"default port", vault.Stored{BaseURL: "https://vault.example.com", Credential: tok}, true},
		{"no credential", vault.Stored{BaseURL: srv}, false},
		{"bad credential", vault.Stored{BaseURL: srv, Credential: "two words"}, false},
		{"no base url", vault.Stored{Credential: tok}, false},
		{"bad namespace", vault.Stored{BaseURL: srv, Namespace: "a b", Credential: tok}, false},
		{"http", vault.Stored{BaseURL: "http://vault.example.com", Credential: tok}, false},
		{"metadata host", vault.Stored{BaseURL: "https://169.254.169.254", Credential: tok}, false},
		{"other port", vault.Stored{BaseURL: "https://vault.example.com:9999", Credential: tok}, false},
		{"path", vault.Stored{BaseURL: srv + "/v1", Credential: tok}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := vault.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), tok) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "vault" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	env := func(k string) string {
		if k == "TESSERA_VAULT_BASE_URL" {
			return "https://other.example.com:8200"
		}
		return ""
	}
	if _, err := vault.FromStored(vault.Stored{Credential: tok}, env, prod, hc, nil); err != nil {
		t.Errorf("base override: %v", err)
	}
}

func TestCheckURL(t *testing.T) {
	for _, tc := range []struct {
		raw string
		bad bool
	}{
		{"https://vault.example.com:8200", false},
		{"http://vault.example.com", true},
		{"https://169.254.169.254", true},
		{"https://vault.example.com:22", true},
		{"https://vault.example.com/ui", true},
	} {
		if _, err := vault.CheckURL(tc.raw, connsync.Runtime{Env: "prod"}); (err != nil) != tc.bad {
			t.Errorf("CheckURL(%q) = %v", tc.raw, err)
		}
	}
}
