package worker_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
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
	got := worker.MergeGoverned(conns, []connectors.Connector{mk("sap"), mk("cyberark"), mk("cyberark")}, nil)
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
	if got := worker.MergeGoverned(nil, nil, nil); len(got) != 0 {
		t.Errorf("empty merge = %v", got)
	}
}

// A stored Google connection that fails to open must not let the env-configured
// google connector read in its place (issue #823): it would read the whole customer,
// not the connection's org units. The connection is reported by name, the other
// connectors still sync.
func TestSyncJobFailsClosedWhenAStoredConnectionDoesNotOpen(t *testing.T) {
	e := newEnv(t)
	reads := make(chan string, 8)
	envGoogle := &sysConnector{system: "google", reads: reads}
	okta := &sysConnector{system: "okta", reads: reads}
	var logs bytes.Buffer
	deps := &worker.Deps{
		Log:        slog.New(slog.NewTextHandler(&logs, nil)),
		Connectors: func(time.Time) ([]connectors.Connector, error) { return []connectors.Connector{envGoogle, okta}, nil },
		Governed: func(context.Context, tenancy.ID, time.Time) ([]connectors.Connector, map[string]error, error) {
			return nil, map[string]error{"Eng Google": &connectors.NotOpenedError{System: "google", Err: errors.New("no admin_email")}}, nil
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
	if got["google"] != 0 || got["okta"] != 1 {
		t.Errorf("reads = %v; the env google connector must not read, okta must", got)
	}
	if !strings.Contains(logs.String(), "Eng Google") {
		t.Errorf("the failed connection is not reported by name: %s", logs.String())
	}
}

func TestMergeGovernedDropsTheEnvConnectorOfAFailedStoredConnection(t *testing.T) {
	mk := func(s string) connectors.Connector { return &sysConnector{system: s} }
	env := []connectors.Connector{mk("google"), mk("okta")}
	cases := []struct {
		name   string
		failed map[string]error
		want   []string
	}{
		{"no failure", nil, []string{"google", "okta"}},
		{"stored google failed", map[string]error{"G": &connectors.NotOpenedError{System: "google", Err: errors.New("x")}}, []string{"okta"}},
		{"other connection failed", map[string]error{"V": errors.New("x")}, []string{"google", "okta"}},
	}
	for _, tc := range cases {
		var got []string
		for _, c := range worker.MergeGoverned(env, nil, tc.failed) {
			got = append(got, c.System())
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: systems = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDropSystems(t *testing.T) {
	mk := func(s string) connectors.Connector { return &sysConnector{system: s} }
	in := []connectors.Connector{mk("google"), mk("okta")}
	var got []string
	for _, c := range worker.DropSystems(in, []string{"google"}) {
		got = append(got, c.System())
	}
	if !slices.Equal(got, []string{"okta"}) || len(in) != 2 || len(worker.DropSystems(in, nil)) != 2 {
		t.Errorf("DropSystems = %v (input %d)", got, len(in))
	}
}
