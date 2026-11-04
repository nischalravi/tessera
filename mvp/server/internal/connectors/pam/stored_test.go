package pam_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the server, user and API root from the stored config and the secret from the
// credential for every vendor, and only the dev override replaces the URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, vendor := range []string{pam.CyberArk, pam.Delinea, pam.BeyondTrust} {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			hc, err := safehttp.NewForTest(t, r.srv.Options(0))
			if err != nil {
				t.Fatal(err)
			}
			c, err := pam.FromStored(pam.Stored{Vendor: vendor, BaseURL: r.srv.URL, Username: user, Credential: secret}, noEnv, connsynctest.Runtime, hc, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res, err := c.Discover(context.Background()); err != nil || len(res.Resources) != 1 || c.System() != vendor {
				t.Errorf("Discover = %v, %v", res, err)
			}
			env := func(k string) string {
				if k == "TESSERA_"+strings.ToUpper(vendor)+"_BASE_URL" {
					return r.srv.URL
				}
				return ""
			}
			if _, err := pam.FromStored(pam.Stored{Vendor: vendor, BaseURL: "https://other.example.com", Username: user, Credential: secret}, env, connsynctest.Runtime, hc, nil); err != nil {
				t.Errorf("override: %v", err)
			}
			prod := connsync.Runtime{Env: "prod"}
			for name, s := range map[string]pam.Stored{
				"no credential": {Vendor: vendor, BaseURL: r.srv.URL, Username: user},
				"no user":       {Vendor: vendor, BaseURL: r.srv.URL, Credential: secret},
				"no base url":   {Vendor: vendor, Username: user, Credential: secret},
				"http":          {Vendor: vendor, BaseURL: "http://pvwa.example.com", Username: user, Credential: secret},
				"metadata":      {Vendor: vendor, BaseURL: "https://169.254.169.254", Username: user, Credential: secret},
				"path":          {Vendor: vendor, BaseURL: "https://pvwa.example.com/PasswordVault", Username: user, Credential: secret},
				"bad api root":  {Vendor: vendor, BaseURL: "https://pvwa.example.com", Username: user, APIRoot: "../x", Credential: secret},
				"unknown":       {Vendor: "nope", BaseURL: "https://pvwa.example.com", Username: user, Credential: secret},
			} {
				_, err := pam.FromStored(s, noEnv, prod, hc, nil)
				if err == nil {
					t.Errorf("%s: accepted", name)
				} else if strings.Contains(err.Error(), secret) {
					t.Errorf("%s: the error echoes the credential: %v", name, err)
				}
			}
		})
	}
}
