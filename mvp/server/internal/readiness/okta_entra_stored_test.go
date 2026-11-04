package readiness

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const oktaStoredConfig = `{"org_url":"https://acme.okta.com","correlation_key":"employee_number"}`

// A live Okta connection's connector is opened from its stored config (issue #814): its
// tenant_host and api_version reach the builder with the opened credential, for the sync and
// for OpenConnector.
func TestOktaConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["okta"] = oktaStoredConfig
	t.Cleanup(func() { delete(govConfig, "okta") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var built []governed.Params
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		built = append(built, p)
		return fakeConnector{"okta"}, nil
	}
	st := newStore(t)
	activateGov(t, s, st, "okta")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != "okta" {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	if len(built) != 1 {
		t.Fatalf("connector built %d times", len(built))
	}
	if p := built[0]; p.Type != governed.Okta || p.OrgURL != "https://acme.okta.com" || p.Secret != govSecret {
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

// A live Okta connection that cannot be opened fails closed: the env-configured okta
// connector must not read in its place.
func TestOktaConnectionThatDoesNotOpenFailsClosed(t *testing.T) {
	govConfig["okta"] = oktaStoredConfig
	t.Cleanup(func() { delete(govConfig, "okta") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
		return nil, errors.New("okta: bad credential")
	}
	st := newStore(t)
	activateGov(t, s, st, "okta")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 1 {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	for name, e := range failed {
		var no *connectors.NotOpenedError
		if !errors.As(e, &no) || no.System != "okta" {
			t.Errorf("%s: failure %v does not name the okta system", name, e)
		}
	}
	read(t, st, func(c *store.TenantTx) error {
		got, err := s.StoredSystems(c)
		if err != nil || !slices.Equal(got, []string{"okta"}) {
			t.Errorf("stored systems = %v, %v", got, err)
		}
		return nil
	})
}

const entraStoredConfig = `{"tenant_id":"11111111-2222-3333-4444-555555555555","cloud":"usgov","correlation_key":"employee_id"}`

// A live Entra connection's connector is opened from its stored config (issue #814): its
// tenant_host and api_version reach the builder with the opened credential, for the sync and
// for OpenConnector.
func TestEntraConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["entra"] = entraStoredConfig
	t.Cleanup(func() { delete(govConfig, "entra") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var built []governed.Params
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		built = append(built, p)
		return fakeConnector{"entra"}, nil
	}
	st := newStore(t)
	activateGov(t, s, st, "entra")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != "entra" {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	if len(built) != 1 {
		t.Fatalf("connector built %d times", len(built))
	}
	if p := built[0]; p.Type != governed.Entra || p.TenantID != "11111111-2222-3333-4444-555555555555" || p.Cloud != "usgov" || p.Secret != govSecret {
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

// A live Entra connection that cannot be opened fails closed: the env-configured entra
// connector must not read in its place.
func TestEntraConnectionThatDoesNotOpenFailsClosed(t *testing.T) {
	govConfig["entra"] = entraStoredConfig
	t.Cleanup(func() { delete(govConfig, "entra") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
		return nil, errors.New("entra: bad credential")
	}
	st := newStore(t)
	activateGov(t, s, st, "entra")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 1 {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	for name, e := range failed {
		var no *connectors.NotOpenedError
		if !errors.As(e, &no) || no.System != "entra" {
			t.Errorf("%s: failure %v does not name the entra system", name, e)
		}
	}
	read(t, st, func(c *store.TenantTx) error {
		got, err := s.StoredSystems(c)
		if err != nil || !slices.Equal(got, []string{"entra"}) {
			t.Errorf("stored systems = %v, %v", got, err)
		}
		return nil
	})
}
