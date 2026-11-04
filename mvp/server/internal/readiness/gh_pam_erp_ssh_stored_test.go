package readiness

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// A live GitHub scan, PAM vault, ERP, Unix SSH or SFTP drop connection's connector is opened from its
// stored config (issue #814): its base_url and settings reach the builder with the opened credential, and
// a connection that does not open fails closed, naming the system its connector reports (not the type id),
// so the env-configured connector is not read in its place.
func TestGitHubPAMERPSSHAreOpenedFromTheStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		typ, system, base, setting, want string
	}{
		{"githubscan", "github-scan", "", "org", "acme"},
		{"cyberark", "cyberark", "https://pvwa.example.com", "username", "svc-tessera"},
		{"delinea", "delinea", "https://ss.example.com", "username", "tessera"},
		{"beyondtrust", "beyondtrust", "https://bt.example.com", "username", "tessera"},
		{"sap", "sap", "https://s4.example.com", "client_id", "tessera"},
		{"oracle", "oracle", "https://fa.example.com", "client_id", "tessera"},
		{"unixssh", "unix", "", "host", "host1.example.com"},
		{"sftpdrop", "sftp", "", "directory", "/drop/hr"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			passingEvidence(s, t0.Add(48*time.Hour))
			var built []governed.Params
			s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
				built = append(built, p)
				return fakeConnector{tc.system}, nil
			}
			st := newStore(t)
			activateGov(t, s, st, tc.typ)
			cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != tc.system {
				t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
			}
			if len(built) != 1 {
				t.Fatalf("connector built %d times", len(built))
			}
			if p := built[0]; p.Type != tc.typ || p.BaseURL != tc.base || p.Settings[tc.setting] != tc.want || p.Secret != govSecret {
				t.Errorf("opened with %+v", p)
			}
			read(t, st, func(c *store.TenantTx) error {
				got, err := s.StoredSystems(c)
				if err != nil || !slices.Equal(got, []string{tc.system}) {
					t.Errorf("stored systems = %v, %v", got, err)
				}
				return nil
			})

			s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
				return nil, errors.New(tc.typ + ": bad credential")
			}
			cns, failed, err = s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(cns) != 0 || len(failed) != 1 {
				t.Fatalf("after a failure: %v, failed %v, %v", cns, failed, err)
			}
			for name, e := range failed {
				var no *connectors.NotOpenedError
				if !errors.As(e, &no) || no.System != tc.system {
					t.Errorf("%s: failure %v does not name the %s system", name, e, tc.system)
				}
			}
		})
	}
}

// The server URL of these types and the host of an SSH or SFTP connection are refused on save unless the
// connector would open them: https, a public host name, never a cloud metadata service.
func TestGitHubPAMERPSSHConfigRefusesUnopenableHosts(t *testing.T) {
	for _, tc := range []struct {
		typ, name, cfg, field string
		bad                   bool
	}{
		{"cyberark", "ok", `{"correlation_key":"id","base_url":"https://pvwa.example.com","settings":{"username":"u"}}`, "base_url", false},
		{"cyberark", "metadata", `{"correlation_key":"id","base_url":"https://169.254.169.254","settings":{"username":"u"}}`, "base_url", true},
		{"cyberark", "metadata name", `{"correlation_key":"id","base_url":"https://metadata.google.internal","settings":{"username":"u"}}`, "base_url", true},
		{"cyberark", "http", `{"correlation_key":"id","base_url":"http://pvwa.example.com","settings":{"username":"u"}}`, "base_url", true},
		{"sap", "metadata", `{"correlation_key":"id","base_url":"https://169.254.169.254","settings":{"client_id":"c"}}`, "base_url", true},
		{"oracle", "ok", `{"correlation_key":"id","base_url":"https://fa.example.com","settings":{"client_id":"c"}}`, "base_url", false},
		{"githubscan", "ok", `{"correlation_key":"id","base_url":"https://ghe.example.com/api/v3","settings":{"org":"acme"}}`, "base_url", false},
		{"githubscan", "default", `{"correlation_key":"id","settings":{"org":"acme"}}`, "base_url", false},
		{"githubscan", "metadata", `{"correlation_key":"id","base_url":"https://169.254.169.254/api/v3","settings":{"org":"acme"}}`, "base_url", true},
		{"unixssh", "ok", `{"correlation_key":"id","settings":{"host":"host1.example.com","username":"t","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}}`, "settings.host", false},
		{"unixssh", "metadata", `{"correlation_key":"id","settings":{"host":"169.254.169.254","username":"t","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}}`, "settings.host", true},
		{"unixssh", "metadata name", `{"correlation_key":"id","settings":{"host":"metadata.google.internal","username":"t","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}}`, "settings.host", true},
		{"unixssh", "no host key", `{"correlation_key":"id","settings":{"host":"host1.example.com","username":"t"}}`, "settings.host_key", true},
		{"sftpdrop", "metadata", `{"correlation_key":"id","settings":{"host":"169.254.169.254","username":"t","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8","directory":"/d","accounts_file":"a.csv","accounts_account_id":"ID","accounts_username":"L"}}`, "settings.host", true},
		{"sftpdrop", "no host key", `{"correlation_key":"id","settings":{"host":"files.example.com","username":"t","directory":"/d","accounts_file":"a.csv","accounts_account_id":"ID","accounts_username":"L"}}`, "settings.host_key", true},
		{"sftpdrop", "ok", `{"correlation_key":"id","settings":{"host":"files.example.com","username":"t","host_key":"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8","directory":"/d","accounts_file":"a.csv","accounts_account_id":"ID","accounts_username":"L"}}`, "settings.host", false},
	} {
		t.Run(tc.typ+" "+tc.name, func(t *testing.T) {
			gt, _ := governed.Lookup(tc.typ)
			r, ok := template.MustDefault().Get(gt.Template)
			if !ok {
				t.Fatal("no template")
			}
			cfg, err := DecodeConfig([]byte(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			errs := ValidateConnEnv(cfg, r, tc.typ, "prod")
			var onField bool
			for _, fe := range errs {
				onField = onField || fe.Field == tc.field
			}
			if onField != tc.bad || (!tc.bad && len(errs) != 0) {
				t.Errorf("errors %v, want an error on %s: %v", errs, tc.field, tc.bad)
			}
		})
	}
}
