package successfactors_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/successfactors"
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

// FromStored reads the data center, company and sign-in from the stored config and the password or key
// from the credential, refuses what does not open without echoing it, and lets only the dev override
// replace the stored base URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	hc := prodClient(t)
	prod := connsync.Runtime{Env: "prod"}
	const pw = "SF-SECRET-PASSWORD"
	ok := successfactors.Stored{BaseURL: "https://api4.successfactors.com", CompanyID: "acme", Username: "tessera-api", Credential: pw}
	with := func(f func(*successfactors.Stored)) successfactors.Stored {
		s := ok
		f(&s)
		return s
	}
	for _, tc := range []struct {
		name string
		s    successfactors.Stored
		good bool
	}{
		{"basic", ok, true},
		{"legal entity", with(func(s *successfactors.Stored) { s.LegalEntity = "ACME_US" }), true},
		{"no credential", with(func(s *successfactors.Stored) { s.Credential = "" }), false},
		{"no base url", with(func(s *successfactors.Stored) { s.BaseURL = "" }), false},
		{"no company", with(func(s *successfactors.Stored) { s.CompanyID = "" }), false},
		{"no user", with(func(s *successfactors.Stored) { s.Username = "" }), false},
		{"bad auth", with(func(s *successfactors.Stored) { s.Auth = "oauth" }), false},
		{"saml without client", with(func(s *successfactors.Stored) { s.Auth = "saml_bearer" }), false},
		{"saml with a password", with(func(s *successfactors.Stored) { s.Auth, s.ClientID = "saml_bearer", "client-1" }), false},
		{"http", with(func(s *successfactors.Stored) { s.BaseURL = "http://api4.successfactors.com" }), false},
		{"not successfactors", with(func(s *successfactors.Stored) { s.BaseURL = "https://evil.example.com" }), false},
		{"look-alike", with(func(s *successfactors.Stored) { s.BaseURL = "https://successfactors.com.evil.example" }), false},
		{"metadata host", with(func(s *successfactors.Stored) { s.BaseURL = "https://169.254.169.254" }), false},
		{"path", with(func(s *successfactors.Stored) { s.BaseURL += "/odata" }), false},
		{"port", with(func(s *successfactors.Stored) { s.BaseURL += ":8443" }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := successfactors.FromStored(tc.s, noEnv, prod, hc)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), pw) {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "successfactors" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	env := func(k string) string {
		if k == "TESSERA_SUCCESSFACTORS_BASE_URL" {
			return "https://api2.successfactors.eu"
		}
		return ""
	}
	if _, err := successfactors.FromStored(with(func(s *successfactors.Stored) { s.BaseURL = "" }), env, prod, hc); err != nil {
		t.Errorf("override: %v", err)
	}
}
