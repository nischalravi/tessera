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

const sfStoredConfig = `{"base_url":"https://acme.my.salesforce.com","api_version":"v60.0","correlation_key":"employee_number"}`

// A live Salesforce connection's connector is opened from its stored config (issue #814): its
// base_url and api_version reach the builder with the opened credential, for the sync and
// for OpenConnector.
func TestSalesforceConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["salesforce"] = sfStoredConfig
	t.Cleanup(func() { delete(govConfig, "salesforce") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var built []governed.Params
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		built = append(built, p)
		return fakeConnector{"salesforce"}, nil
	}
	st := newStore(t)
	activateGov(t, s, st, "salesforce")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != "salesforce" {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	if len(built) != 1 {
		t.Fatalf("connector built %d times", len(built))
	}
	if p := built[0]; p.Type != governed.Salesforce || p.BaseURL != "https://acme.my.salesforce.com" || p.APIVersion != "v60.0" || p.Secret != govSecret {
		t.Errorf("opened with %+v", p)
	}
	read(t, st, func(c *store.TenantTx) error {
		live, err := s.ActiveConnections(c)
		if err != nil || len(live) != 1 {
			t.Fatalf("active connections: %v, %v", live, err)
		}
		if cn, ok, err := s.OpenConnector(c, live[0], t0); err != nil || !ok || cn == nil {
			t.Errorf("OpenConnector: ok %v, err %v", ok, err)
		}
		return nil
	})
}

// A live Salesforce connection that cannot be opened fails closed: the env-configured salesforce
// connector must not read in its place.
func TestSalesforceConnectionThatDoesNotOpenFailsClosed(t *testing.T) {
	govConfig["salesforce"] = sfStoredConfig
	t.Cleanup(func() { delete(govConfig, "salesforce") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
		return nil, errors.New("salesforce: bad credential")
	}
	st := newStore(t)
	activateGov(t, s, st, "salesforce")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 1 {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	for name, e := range failed {
		var no *connectors.NotOpenedError
		if !errors.As(e, &no) || no.System != "salesforce" {
			t.Errorf("%s: failure %v does not name the salesforce system", name, e)
		}
	}
	read(t, st, func(c *store.TenantTx) error {
		got, err := s.StoredSystems(c)
		if err != nil || !slices.Equal(got, []string{"salesforce"}) {
			t.Errorf("stored systems = %v, %v", got, err)
		}
		return nil
	})
}

// A Salesforce connection's base_url is refused on save unless it is an https Salesforce domain.
func TestSalesforceConfigRefusesOtherHosts(t *testing.T) {
	r, _ := template.MustDefault().Get("salesforce")
	for _, tc := range []struct {
		name string
		cfg  ConnConfig
		bad  string
	}{
		{"ok", ConnConfig{CorrelationKey: "employee_number", BaseURL: "https://acme.my.salesforce.com", APIVersion: "v61.0"}, ""},
		{"other host", ConnConfig{CorrelationKey: "employee_number", BaseURL: "https://evil.example.com"}, "base_url"},
		{"metadata host", ConnConfig{CorrelationKey: "employee_number", BaseURL: "https://169.254.169.254"}, "base_url"},
		{"http", ConnConfig{CorrelationKey: "employee_number", BaseURL: "http://acme.my.salesforce.com"}, "base_url"},
		{"bad version", ConnConfig{CorrelationKey: "employee_number", BaseURL: "https://acme.my.salesforce.com", APIVersion: "61"}, "api_version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, fe := range ValidateConnEnv(tc.cfg, r, "salesforce", "prod") {
				if fe.Field == tc.bad {
					got = fe.Field
				}
			}
			if got != tc.bad {
				t.Errorf("field errors for %q: want %q", tc.name, tc.bad)
			}
			if tc.bad == "" {
				if errs := ValidateConnEnv(tc.cfg, r, "salesforce", "prod"); len(errs) != 0 {
					t.Errorf("errors: %v", errs)
				}
			}
		})
	}
}
