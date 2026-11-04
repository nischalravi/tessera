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

const (
	restStoredConfig = `{"correlation_key":"id","rest":{"system":"hr-api","base_url":"https://api.example.com","auth":{"type":"bearer"},
		"users":{"path":"/users","fields":{"id":"$.id","username":"$.login"}}}}`
	sqlStoredConfig = `{"correlation_key":"username","sql":{"engine":"postgres","host":"db.example.com","database":"app","username":"ro","mode":"native"}}`
)

// A live REST or SQL connection's connector is opened from its stored spec or settings (issue
// #814): they reach the builder with the opened credential, and the stored system is the one the
// env-configured connector of the same system is replaced for.
func TestRestAndSQLConnectorsAreOpenedFromTheStoredConfig(t *testing.T) {
	for _, tc := range []struct {
		typ, cfg, system string
	}{
		{governed.RestGeneric, restStoredConfig, "hr-api"},
		{governed.SQL, sqlStoredConfig, "sql"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			govConfig[tc.typ] = tc.cfg
			t.Cleanup(func() { delete(govConfig, tc.typ) })
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
			if err != nil || len(failed) != 0 || len(cns) != 1 || len(built) != 1 {
				t.Fatalf("governed connectors: %v, failed %v, built %d, %v", cns, failed, len(built), err)
			}
			p := built[0]
			if p.Type != tc.typ || p.Secret != govSecret || (tc.typ == governed.SQL) != (p.SQL != nil) || (tc.typ == governed.RestGeneric) != (p.Rest != nil) {
				t.Errorf("opened with %+v", p)
			}
			if p.Rest != nil && p.Rest.BaseURL != "https://api.example.com" || p.SQL != nil && p.SQL.Host != "db.example.com" {
				t.Errorf("stored settings did not reach the builder: %+v %+v", p.Rest, p.SQL)
			}
		})
	}
}

// A REST or SQL connection that cannot be opened fails closed, naming the system its env-configured
// connector reports, so that one does not read in its place.
func TestRestAndSQLConnectionsThatDoNotOpenFailClosed(t *testing.T) {
	for _, tc := range []struct {
		typ, cfg, system string
	}{
		{governed.RestGeneric, restStoredConfig, "hr-api"},
		{governed.SQL, sqlStoredConfig, "sql"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			govConfig[tc.typ] = tc.cfg
			t.Cleanup(func() { delete(govConfig, tc.typ) })
			var opened []governed.Params
			s := govSvc(t, &opened, stubProber{})
			passingEvidence(s, t0.Add(48*time.Hour))
			s.Runner.Gov.Connector = func(governed.Params, governed.Net) (connectors.Connector, error) {
				return nil, errors.New("bad credential")
			}
			st := newStore(t)
			activateGov(t, s, st, tc.typ)

			cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
			if err != nil || len(cns) != 0 || len(failed) != 1 {
				t.Fatalf("governed connectors: %v, failed %v, %v", cns, failed, err)
			}
			for name, e := range failed {
				var no *connectors.NotOpenedError
				if !errors.As(e, &no) || no.System != tc.system {
					t.Errorf("%s: failure %v does not name the %s system", name, e, tc.system)
				}
			}
			read(t, st, func(c *store.TenantTx) error {
				got, err := s.StoredSystems(c)
				if err != nil || !slices.Equal(got, []string{tc.system}) {
					t.Errorf("stored systems = %v, %v", got, err)
				}
				return nil
			})
		})
	}
}
