package worker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// sysConnector reads nothing; it only says which system it is and counts reads.
type sysConnector struct {
	connectors.Connector
	system string
	reads  chan string
}

func (c *sysConnector) System() string { return c.system }
func (c *sysConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	c.reads <- c.system
	return &connectors.DiscoveryResult{System: c.system}, nil
}
func (c *sysConnector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// The connector_sync job reads the tenant's governed connections next to the
// configured connectors, once per system: a configured connector of the same
// system keeps working as it did and the governed one is not read as well.
func TestSyncJobReadsGovernedConnections(t *testing.T) {
	e := newEnv(t)
	reads := make(chan string, 8)
	legacy := &sysConnector{system: "sap", reads: reads}
	vault := &sysConnector{system: "cyberark", reads: reads}
	twin := &sysConnector{system: "sap", reads: reads} // a governed SAP connection beside the env-configured one
	var asked tenancy.ID
	deps := &worker.Deps{
		Connectors: func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{legacy}, nil },
		Governed: func(_ context.Context, tn tenancy.ID, _ time.Time) ([]connectors.Connector, map[string]error, error) {
			asked = tn
			return []connectors.Connector{vault, twin}, map[string]error{"Broken vault": errors.New("the vault refused the setting")}, nil
		},
	}
	q := e.queue(t, "w", time.Minute, deps, jobs.ConnectorSync)
	e.enqueue(t, q, tenantA, jobs.ConnectorSync, "k1")
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	close(reads)
	got := map[string]int{}
	for s := range reads {
		got[s]++
	}
	if got["cyberark"] != 1 || got["sap"] != 1 || len(got) != 2 {
		t.Errorf("reads = %v; each system once, the configured SAP connector not duplicated", got)
	}
	if asked != tenantA {
		t.Errorf("the governed connections of tenant %s were asked for, not %s", asked, tenantA)
	}
}

func TestMergeGoverned(t *testing.T) {
	mk := func(s string) connectors.Connector { return &sysConnector{system: s} }
	conns := []connectors.Connector{mk("okta"), mk("sap")}
	got := worker.MergeGoverned(conns, []connectors.Connector{mk("sap"), mk("cyberark"), mk("cyberark")})
	var systems []string
	for _, c := range got {
		systems = append(systems, c.System())
	}
	if len(systems) != 3 || systems[0] != "okta" || systems[1] != "sap" || systems[2] != "cyberark" {
		t.Errorf("systems = %v", systems)
	}
	if len(conns) != 2 {
		t.Error("the configured list was modified")
	}
	if got := worker.MergeGoverned(nil, nil); len(got) != 0 {
		t.Errorf("empty merge = %v", got)
	}
}
