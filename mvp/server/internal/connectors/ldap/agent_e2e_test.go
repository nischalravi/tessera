package ldap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/agent/agenttest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

type credMap map[string]string

func (c credMap) Get(name string) (string, error) {
	if v, ok := c[name]; ok {
		return v, nil
	}
	return "", agent.ErrNoCredential
}

// TestAgent_EndToEndLDAP runs the whole readiness LDAP live-check catalogue
// through a real enrolled Directory Agent (mutual TLS, typed jobs, the
// agent-side allowlist and safedial) against the in-process LDAP server, and
// compares every result with a direct run against the same server: the agent
// changes the path, never the answer. The bind password exists only on the
// agent side.
func TestAgent_EndToEndLDAP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tn store.Tenant
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) (err error) {
		tn, err = s.CreateTenant(store.Tenant{Slug: "larkspur", Name: "Larkspur Labs"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc := &agent.Service{DB: db, Hub: agent.NewHub(nil), Clock: func() time.Time { return now }}
	pki := agenttest.NewPKI(t)
	tlsCfg, err := agent.ServerTLSConfig(pki.CertFile, pki.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(svc.Handler(100 * time.Millisecond))
	listener.TLS = tlsCfg
	listener.StartTLS()
	defer listener.Close()

	// Enrol the agent.
	var enrolment *agent.Enrolment
	if err := db.InTenant(ctx, tn.ID, func(c *store.TenantTx) (err error) {
		enrolment, err = svc.Create(c, "dc-agent", "admin", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cert, err := agent.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.NewClient(listener.URL, pki.CAPEM, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enrol(ctx, enrolment.Code, agent.Telemetry{Hostname: "h", OS: "linux", Version: agent.Version}); err != nil {
		t.Fatal(err)
	}

	// The directory: the OpenLDAP-shaped lab server, with its own CA.
	d := loadFixture(t, "openldap.json")
	srvTLS, _ := labCert(t, time.Now().Add(90*24*time.Hour))
	fake := startFake(t, d, srvTLS)
	labCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvTLS.Certificates[0].Certificate[1]}))

	const credName = "svc-ldap"
	exec := &agent.Executor{
		Allow: mustAllow(t, labHost+":636"),
		Creds: credMap{credName: openldapLab.password},
		New: func(s agent.ProberSpec) (connectors.Prober, error) {
			return New(Config{Host: s.Target.Host, Port: s.Target.Port, BindDN: s.Config.BindDN, Password: Secret(s.Password),
				BaseDNs: s.Config.BaseDNs, UserFilter: s.Config.UserFilter, RootCAs: s.RootCAs, Dialer: s.Dialer})
		},
		Resolver: labResolver{},
		TestDial: fakeTransport{fake}.dial,
	}
	runner := &agent.Runner{Client: client, Exec: exec, HeartbeatEvery: time.Hour,
		Telemetry: agent.Telemetry{Hostname: "h", OS: "linux", Version: agent.Version}}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for !svc.Hub.Online(tn.ID, enrolment.Agent.ID) {
		if time.Now().After(deadline) {
			t.Fatal("the agent never started polling")
		}
		time.Sleep(10 * time.Millisecond)
	}

	remote, err := agent.NewRemoteProber(svc, tn.ID, enrolment.Agent.ID, agent.Target{Host: labHost, Port: 636},
		agent.ProbeConfig{BindDN: openldapLab.bindDN, CredName: credName, BaseDNs: openldapLab.bases,
			UserFilter: "(objectClass=inetOrgPerson)", CABundle: labCA})
	if err != nil {
		t.Fatal(err)
	}
	viaAgent := runChecks(t, remote, openldapLab.bases, "(objectClass=inetOrgPerson)")
	direct := runLive(t, newEnv(t, openldapLab))
	if len(viaAgent) == 0 || len(viaAgent) != len(direct) {
		t.Fatalf("%d results via the agent, %d direct", len(viaAgent), len(direct))
	}
	for check, want := range direct {
		got, ok := viaAgent[check]
		if !ok || got.Status != want.Status {
			t.Errorf("%s: via the agent %q (%s), direct %q (%s)", check, got.Status, got.Message, want.Status, want.Message)
		}
	}
	want(t, viaAgent, "bind", checks.Pass)
	want(t, viaAgent, "tls_handshake", checks.Pass)

	// The directory saw only reads (the read-only recorder of the lab server).
	if _, writes := fake.snapshot(); len(writes) != 0 {
		t.Errorf("the agent sent write operations: %v", writes)
	}
	// The password is not in anything Tessera received.
	raw, _ := json.Marshal(viaAgent)
	if strings.Contains(string(raw), openldapLab.password) {
		t.Error("a result carries the bind password")
	}

	// Another target: refused by the agent's allowlist, with the directory untouched.
	other, _ := agent.NewRemoteProber(svc, tn.ID, enrolment.Agent.ID, agent.Target{Host: "hr-db.lab.example", Port: 636},
		agent.ProbeConfig{BindDN: openldapLab.bindDN, CredName: credName, CABundle: labCA})
	before, _ := fake.snapshot()
	if _, err := other.Connect(ctx); !errors.Is(err, connectors.ErrAgentRefused) {
		t.Errorf("a target outside the allowlist: %v", err)
	}
	if after, _ := fake.snapshot(); len(after) != len(before) {
		t.Error("the agent contacted a directory for a refused target")
	}
	// A credential the agent does not hold.
	nocred, _ := agent.NewRemoteProber(svc, tn.ID, enrolment.Agent.ID, agent.Target{Host: labHost, Port: 636},
		agent.ProbeConfig{BindDN: openldapLab.bindDN, CredName: "not-here", CABundle: labCA})
	if _, err := nocred.Authenticate(ctx); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Errorf("a missing credential: %v", err)
	}
	// The agent's Dialer is the agent-local one: it refuses a private address
	// that is not on the list even if a job named it (the allowlist is also
	// checked first; this proves the second layer).
	d2, err := safedial.New(safedial.Options{Env: "prod", AgentLocal: true, Allow: mustAllow(t, labHost+":636")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d2.Dial(ctx, "10.1.2.3", 636, false); !errors.Is(err, safedial.ErrBlockedAddress) {
		t.Errorf("agent-local dialer: %v", err)
	}
}

func mustAllow(t *testing.T, s string) []safedial.AllowEntry {
	t.Helper()
	a, err := safedial.ParseAllow(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
