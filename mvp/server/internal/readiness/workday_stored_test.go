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

const workdayStoredConfig = `{"tenant_host":"wd2-impl-services1.workday.com","api_version":"v44.0","interface":"get_workers","correlation_key":"worker_id"}`

// A live Workday connection's connector is opened from its stored config (issue #814): its
// tenant_host and api_version reach the builder with the opened credential, for the sync and
// for OpenConnector.
func TestWorkdayConnectorIsOpenedFromTheStoredConfig(t *testing.T) {
	govConfig["workday"] = workdayStoredConfig
	t.Cleanup(func() { delete(govConfig, "workday") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var built []governed.Params
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		built = append(built, p)
		return fakeConnector{"workday"}, nil
	}
	st := newStore(t)
	activateGov(t, s, st, "workday")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 || len(cns) != 1 || cns[0].System() != "workday" {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	if len(built) != 1 {
		t.Fatalf("connector built %d times", len(built))
	}
	if p := built[0]; p.Type != governed.Workday || p.TenantHost != "wd2-impl-services1.workday.com" || p.APIVersion != "v44.0" || p.Secret != govSecret {
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

// A live Workday connection that cannot be opened fails closed: the env-configured workday
// connector must not read in its place.
func TestWorkdayConnectionThatDoesNotOpenFailsClosed(t *testing.T) {
	govConfig["workday"] = workdayStoredConfig
	t.Cleanup(func() { delete(govConfig, "workday") })
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
		return nil, errors.New("workday: bad credential")
	}
	st := newStore(t)
	activateGov(t, s, st, "workday")

	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 1 {
		t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
	}
	for name, e := range failed {
		var no *connectors.NotOpenedError
		if !errors.As(e, &no) || no.System != "workday" {
			t.Errorf("%s: failure %v does not name the workday system", name, e)
		}
	}
	read(t, st, func(c *store.TenantTx) error {
		got, err := s.StoredSystems(c)
		if err != nil || !slices.Equal(got, []string{"workday"}) {
			t.Errorf("stored systems = %v, %v", got, err)
		}
		return nil
	})
}
