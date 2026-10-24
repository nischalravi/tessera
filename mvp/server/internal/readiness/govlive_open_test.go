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

// fakeConnector is what a stubbed GovOptions.Connector returns.
type fakeConnector struct{ system string }

func (f fakeConnector) System() string    { return f.system }
func (fakeConnector) DisplayName() string { return "fake" }
func (fakeConnector) TypeName() string    { return "FakeConnector" }
func (fakeConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	return &connectors.DiscoveryResult{}, nil
}
func (fakeConnector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// activateGov takes a read-only governed connection to active on passing
// evidence (every item attested that can be).
func activateGov(t *testing.T, s *Service, st Scope, typ string) (id string) {
	t.Helper()
	id = createGov(t, s, st, typ, "Live "+typ, govConfig[typ])
	write(t, st, func(c *store.TenantTx) error {
		if typ != "agentcore" {
			if _, err := s.SetCredential(c, id, CredentialInput{Secret: govSecret}, "admin", t0); err != nil {
				return err
			}
		}
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		for _, it := range b.Eval.Items {
			if it.Applicable && it.HasKind(template.Attestation) {
				if _, err := s.Attest(c, id, it.ID, "confirmed in CHG-2210", "admin", t0); err != nil {
					return err
				}
			}
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0); err != nil {
			return err
		}
		if b, err = s.Current(c, id, t0); err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateDryRunReconciled, "admin", t0); err != nil {
			return err
		}
		_, _, err = s.Activate(c, id, "admin", t0)
		return err
	})
	return id
}

// A live governed connection's connector is opened from its live revision with
// the credential Tessera holds sealed; the types that hand over to their own
// feature, retired connections and failures are not in the list, and a failure
// is reported by name rather than hiding the others.
func TestGoverned_GovernedConnectorsOpenFromTheLiveRevision(t *testing.T) {
	var opened []governed.Params
	s := govSvc(t, &opened, stubProber{})
	passingEvidence(s, t0.Add(48*time.Hour))
	var fail error
	s.Runner.Gov.Connector = func(p governed.Params, _ governed.Net) (connectors.Connector, error) {
		opened = append(opened, p)
		if fail != nil {
			return nil, fail
		}
		gt, _ := governed.Lookup(p.Type)
		return fakeConnector{gt.System}, nil
	}
	st := newStore(t)
	pamID := activateGov(t, s, st, "cyberark")
	activateGov(t, s, st, "sap")
	activateGov(t, s, st, "fieldglass") // read by the contractor feature
	activateGov(t, s, st, "agentcore")  // no credential

	opened = nil
	cns, failed, err := s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(failed) != 0 {
		t.Fatalf("governed connectors: %v, failed %v", err, failed)
	}
	var systems []string
	for _, c := range cns {
		systems = append(systems, c.System())
	}
	slices.Sort(systems)
	if !slices.Equal(systems, []string{"aws-agentcore", "cyberark", "sap"}) {
		t.Errorf("systems = %v; the contractor feed is read by its own feature", systems)
	}
	for _, p := range opened {
		switch p.Type {
		case "cyberark":
			if p.Secret != govSecret || p.Settings["username"] != "svc-tessera" || p.BaseURL != "https://pvwa.example.com" {
				t.Errorf("cyberark opened with %+v", p)
			}
		case "agentcore":
			if p.Secret != "" || p.Settings["snapshot"] != "agentcore.json" || p.Tenant != st.Tenant.String() {
				t.Errorf("agentcore opened with %+v", p)
			}
		}
	}

	// one connection that cannot be opened does not hide the others
	fail = errors.New("the vault refused the setting")
	cns, failed, err = s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 0 || len(failed) != 3 || failed["Live cyberark"] == nil {
		t.Errorf("failing connectors: %d connectors, failed %v, %v", len(cns), failed, err)
	}
	fail = nil

	// OpenConnector is what the first sync and the on-demand sync use; the features' types have none
	read(t, st, func(c *store.TenantTx) error {
		live, err := s.ActiveConnections(c)
		if err != nil {
			return err
		}
		for _, ac := range live {
			cn, ok, err := s.OpenConnector(c, ac, t0)
			gt, _ := governed.Lookup(ac.ConnectorType())
			if gt.Feature == ok || err != nil || (ok && cn == nil) {
				t.Errorf("%s: ok %v err %v", ac.ConnectorType(), ok, err)
			}
			if gt.Feature {
				// the hand-over reads the same settings and credential
				p, err := s.GovernedParams(c, ac, t0)
				if err != nil || p.Secret != govSecret || p.Type != "fieldglass" {
					t.Errorf("params of %s: %+v %v", ac.ConnectorType(), p, err)
				}
			}
		}
		return nil
	})

	write(t, st, func(c *store.TenantTx) error { return s.Retire(c, pamID, "admin", t0) })
	cns, _, err = s.GovernedConnectors(context.Background(), st.DB, st.Tenant, t0)
	if err != nil || len(cns) != 2 {
		t.Errorf("after retiring the vault: %d connectors, %v", len(cns), err)
	}
}
