package erp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the server, client and paths from the stored config and the client secret from the
// credential for both systems, and only the dev override replaces the URL.
func TestFromStored(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, system := range []string{erp.SAP, erp.Oracle} {
		t.Run(system, func(t *testing.T) {
			r := newRig(t, system)
			hc, err := safehttp.NewForTest(t, r.srv.Options(0))
			if err != nil {
				t.Fatal(err)
			}
			c, err := erp.FromStored(erp.Stored{System: system, BaseURL: r.srv.URL, ClientID: id, Credential: secret}, noEnv, connsynctest.Runtime, hc, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res, err := c.Discover(context.Background()); err != nil || len(res.Permissions) == 0 || c.System() != system {
				t.Errorf("Discover = %v, %v", res, err)
			}
			env := func(k string) string {
				if k == "TESSERA_"+strings.ToUpper(system)+"_BASE_URL" {
					return r.srv.URL
				}
				return ""
			}
			if _, err := erp.FromStored(erp.Stored{System: system, BaseURL: "https://other.example.com", ClientID: id, Credential: secret}, env, connsynctest.Runtime, hc, nil); err != nil {
				t.Errorf("override: %v", err)
			}
			prod := connsync.Runtime{Env: "prod"}
			for name, s := range map[string]erp.Stored{
				"no credential":  {System: system, BaseURL: r.srv.URL, ClientID: id},
				"no client":      {System: system, BaseURL: r.srv.URL, Credential: secret},
				"no base url":    {System: system, ClientID: id, Credential: secret},
				"http":           {System: system, BaseURL: "http://s4.example.com", ClientID: id, Credential: secret},
				"metadata":       {System: system, BaseURL: "https://169.254.169.254", ClientID: id, Credential: secret},
				"path":           {System: system, BaseURL: "https://s4.example.com/sap", ClientID: id, Credential: secret},
				"bad token path": {System: system, BaseURL: "https://s4.example.com", ClientID: id, TokenPath: "oauth", Credential: secret},
				"unknown":        {System: "nope", BaseURL: "https://s4.example.com", ClientID: id, Credential: secret},
			} {
				_, err := erp.FromStored(s, noEnv, prod, hc, nil)
				if err == nil {
					t.Errorf("%s: accepted", name)
				} else if strings.Contains(err.Error(), secret) {
					t.Errorf("%s: the error echoes the credential: %v", name, err)
				}
			}
		})
	}
}
