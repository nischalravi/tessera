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

// A live Kubernetes, Vault, Azure RBAC or GCP IAM connection's connector is opened from its stored
// config (issue #814): its base_url and settings reach the builder with the opened credential, and a
// connection that does not open fails closed, naming its system, so the env-configured connector is
// not read in its place.
func TestK8sVaultCloudAreOpenedFromTheStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		typ, base, setting, want string
	}{
		{"kubernetes", "https://api.k8s.example.com:6443", "namespaces", "payments, web"},
		{"vault", "https://vault.example.com:8200", "namespace", "team-a/prod"},
		{"azurerbac", "", "tenant_id", "11111111-2222-3333-4444-555555555555"},
		{"gcpiam", "", "organization_id", "123456789012"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			passingEvidence(s, t0.Add(48*time.Hour))
			var built []governed.Params
			s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
				built = append(built, p)
				return fakeConnector{tc.typ}, nil
			}
			st := newStore(t)
			activateGov(t, s, st, tc.typ)
			cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != tc.typ {
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
				if err != nil || !slices.Equal(got, []string{tc.typ}) {
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
				if !errors.As(e, &no) || no.System != tc.typ {
					t.Errorf("%s: failure %v does not name the %s system", name, e, tc.typ)
				}
			}
		})
	}
}

// The API server and Vault URLs are refused on save unless the connector would open them: https, no
// metadata host, a supported port and no path.
func TestK8sVaultConfigRefusesUnopenableURLs(t *testing.T) {
	for _, tc := range []struct {
		typ, name, url string
		bad            bool
	}{
		{"kubernetes", "ok", "https://api.k8s.example.com:6443", false},
		{"kubernetes", "default port", "https://api.k8s.example.com", false},
		{"kubernetes", "http", "http://api.k8s.example.com", true},
		{"kubernetes", "metadata", "https://169.254.169.254", true},
		{"kubernetes", "metadata name", "https://metadata.google.internal", true},
		{"kubernetes", "port", "https://api.k8s.example.com:9999", true},
		{"kubernetes", "path", "https://api.k8s.example.com:6443/api", true},
		{"vault", "ok", "https://vault.example.com:8200", false},
		{"vault", "http", "http://vault.example.com:8200", true},
		{"vault", "metadata", "https://169.254.169.254:8200", true},
		{"vault", "port", "https://vault.example.com:6443", true},
		{"vault", "path", "https://vault.example.com:8200/ui", true},
	} {
		t.Run(tc.typ+" "+tc.name, func(t *testing.T) {
			r, ok := template.MustDefault().Get(tc.typ)
			if !ok {
				t.Fatal("no template")
			}
			cfg, err := DecodeConfig([]byte(`{"correlation_key":"id","base_url":"` + tc.url + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			errs := ValidateConnEnv(cfg, r, tc.typ, "prod")
			var onURL bool
			for _, fe := range errs {
				onURL = onURL || fe.Field == "base_url"
			}
			if onURL != tc.bad || (!tc.bad && len(errs) != 0) {
				t.Errorf("errors %v, want a base_url error: %v", errs, tc.bad)
			}
		})
	}
}
