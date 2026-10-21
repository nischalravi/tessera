package worker_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/agent/agenttest"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

const ldapConfig = `{"host":"ldap.corp.example","port":636,"bind_dn":"uid=svc,ou=people,dc=corp,dc=example","base_dns":["dc=corp,dc=example"]}`

func pinOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// addAgent inserts an agent of the tenant: active (key pinned) or revoked.
func (e *env) addAgent(t *testing.T, tn tenancy.ID, name string, revoke bool) string {
	t.Helper()
	id := store.NewID()
	if err := e.db.InTenant(t.Context(), tn, func(tx *store.TenantTx) error {
		if err := tx.InsertDirectoryAgent(&store.DirectoryAgent{ID: id, Name: name, CreatedBy: "t", CreatedAt: e.clk.Now()}); err != nil {
			return err
		}
		if err := tx.ActivateDirectoryAgent(id, pinOf(id), store.AgentTelemetry{Version: agent.Version}, e.clk.Now()); err != nil {
			return err
		}
		if revoke {
			return tx.RevokeDirectoryAgent(id, "admin", e.clk.Now())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// addConn inserts a connection with a live revision whose credential is ref.
func (e *env) addConn(t *testing.T, tn tenancy.ID, name, template, ref, config string) string {
	t.Helper()
	id, rev := store.NewID(), store.NewID()
	now := e.clk.Now()
	if err := e.db.InTenant(t.Context(), tn, func(tx *store.TenantTx) error {
		if err := tx.InsertConnection(&store.Connection{ID: id, Name: name, ConnectorType: template, System: name, Role: "account_source",
			CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		r := &store.ConnectionRevision{ID: rev, ConnectionID: id, Rev: 1, TemplateID: template, TemplateVersion: "1.0", Config: config,
			ConfigHash: "h", WriteMode: "off", CreatedBy: "t", CreatedAt: now, UpdatedAt: now}
		if ref != "" {
			r.SecretRef = &ref
		}
		if err := tx.InsertRevision(r); err != nil {
			return err
		}
		return tx.SetConnectionLive(id, &rev, "ok", now)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) agentJobs(t *testing.T, tn tenancy.ID) []*store.AgentJob {
	t.Helper()
	var js []*store.AgentJob
	if err := e.db.ReadTenant(t.Context(), tn, func(tx *store.TenantTx) (err error) {
		js, err = tx.AgentJobs(store.AgentJobFilter{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return js
}

func (e *env) queueSyncs(t *testing.T, tn tenancy.ID, window string) int {
	t.Helper()
	var n int
	if err := e.db.InTenant(t.Context(), tn, func(tx *store.TenantTx) (err error) {
		n, err = worker.QueueAgentSyncs(tx, e.clk.Now(), window)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestQueueAgentSyncs_OnlyConnectionsBoundToAnAgent: a sync job is queued for
// a live connection only when its credential reference names an active agent
// of the same tenant, and it is addressed to that agent. Two tenants, two
// agents each: nobody gets another's connection, and a reference to another
// tenant's agent, a revoked agent, a sealed credential or a non-LDAP type
// queues nothing.
func TestQueueAgentSyncs_OnlyConnectionsBoundToAnAgent(t *testing.T) {
	e := newEnv(t, tenantA, tenantB)
	a1, a2 := e.addAgent(t, tenantA, "dc-1", false), e.addAgent(t, tenantA, "dc-2", false)
	b1 := e.addAgent(t, tenantB, "dc-1", false)
	revoked := e.addAgent(t, tenantA, "old", true)
	c1 := e.addConn(t, tenantA, "corp-1", "ldap", "agent:"+a1+"/svc", ldapConfig)
	c2 := e.addConn(t, tenantA, "corp-2", "ldap", "agent:"+a2+"/svc", ldapConfig)
	e.addConn(t, tenantA, "sealed", "ldap", "sealed:abc", ldapConfig)
	e.addConn(t, tenantA, "foreign", "ldap", "agent:"+b1+"/svc", ldapConfig) // B's agent named in A
	e.addConn(t, tenantA, "dead-agent", "ldap", "agent:"+revoked+"/svc", ldapConfig)
	e.addConn(t, tenantA, "not-ldap", "okta", "agent:"+a1+"/svc", `{}`)
	e.addConn(t, tenantA, "no-ref", "ldap", "", ldapConfig)
	cb := e.addConn(t, tenantB, "corp-1", "ldap", "agent:"+b1+"/svc", ldapConfig)

	if n := e.queueSyncs(t, tenantA, "w1"); n != 2 {
		t.Fatalf("queued %d jobs in A, want 2", n)
	}
	if n := e.queueSyncs(t, tenantB, "w1"); n != 1 {
		t.Fatalf("queued %d jobs in B, want 1", n)
	}
	got := map[string]string{} // connection -> agent
	for _, j := range e.agentJobs(t, tenantA) {
		got[j.ConnectionID] = j.AgentID
		var spec agent.SyncSpec
		if err := json.Unmarshal([]byte(j.Payload), &spec); err != nil || spec.Validate() != nil ||
			spec.Target != (agent.Target{Host: "ldap.corp.example", Port: 636}) || spec.Config.CredName != "svc" {
			t.Errorf("payload %s: %+v %v", j.Payload, spec, err)
		}
		if strings.Contains(j.Payload, "password") || strings.Contains(j.Payload, "secret") {
			t.Errorf("the payload carries a secret: %s", j.Payload)
		}
	}
	if len(got) != 2 || got[c1] != a1 || got[c2] != a2 {
		t.Errorf("A's jobs = %v, want %s->%s and %s->%s", got, c1, a1, c2, a2)
	}
	if bj := e.agentJobs(t, tenantB); len(bj) != 1 || bj[0].AgentID != b1 || bj[0].ConnectionID != cb {
		t.Errorf("B's jobs = %+v", bj)
	}
	// the same window again, and the next window while the jobs are still
	// open, queue nothing more
	if n := e.queueSyncs(t, tenantA, "w1") + e.queueSyncs(t, tenantA, "w2"); n != 0 {
		t.Errorf("queued %d more jobs behind open ones", n)
	}
	// once a connection's job is finished, the next window queues it again
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		claimed, _, err := tx.ClaimAgentJobs(a1, e.clk.Now(), time.Minute, 5)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: %v %v", claimed, err)
		}
		return tx.CompleteAgentJob(claimed[0].ID, a1, "{}", e.clk.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.queueSyncs(t, tenantA, "w3"); n != 1 {
		t.Errorf("queued %d jobs after one finished, want 1", n)
	}
}

// TestConnectorSyncJobQueuesTheAgentSyncs: the queue kind that reads the
// connectors also hands the agent-bound connections to their agents.
func TestConnectorSyncJobQueuesTheAgentSyncs(t *testing.T) {
	e := newEnv(t)
	a1 := e.addAgent(t, tenantA, "dc-1", false)
	e.addConn(t, tenantA, "corp-1", "ldap", "agent:"+a1+"/svc", ldapConfig)
	q := e.queue(t, "w", time.Minute, &worker.Deps{Connectors: noConnectors}, "connector_sync")
	e.enqueue(t, q, tenantA, "connector_sync", "k")
	if err := q.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	q.Wait()
	if j := e.onlyJob(t, tenantA, "connector_sync"); j.Status != store.QueueSucceeded {
		t.Fatalf("job: %+v", j)
	}
	js := e.agentJobs(t, tenantA)
	if len(js) != 1 || js[0].AgentID != a1 || js[0].Status != store.AgentJobQueued {
		t.Fatalf("agent jobs = %+v", js)
	}
	// a retry of the same queue job window does not stack a second one
	if n := e.queueSyncs(t, tenantA, "retry"); n != 0 {
		t.Errorf("queued %d", n)
	}
}

// TestRecordAgentSync: an agent's typed listing goes through the same ingest
// as any connector, into the connection's own system, with the sync audited.
func TestRecordAgentSync(t *testing.T) {
	e := newEnv(t)
	a1 := e.addAgent(t, tenantA, "dc-1", false)
	conn := e.addConn(t, tenantA, "corp-ldap", "ldap", "agent:"+a1+"/svc", ldapConfig)
	res := &agent.SyncResult{
		Accounts: []agent.SyncAccount{
			{ExternalID: "uid=alice,dc=corp", Username: "alice", Email: "alice@corp.example", Status: "active"},
			{ExternalID: "uid=bob,dc=corp", Username: "bob", Status: "disabled"}},
		Groups:  []agent.SyncGroup{{ExternalID: "cn=devs,dc=corp", Name: "devs"}},
		Members: []agent.SyncMember{{Account: "uid=alice,dc=corp", Group: "cn=devs,dc=corp"}},
	}
	record := func() {
		t.Helper()
		if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
			sum, err := worker.RecordAgentSync(tx, e.clk.Now(), &store.AgentJob{ID: "job-1", AgentID: a1, ConnectionID: conn}, agent.SyncSpec{}, res)
			if v, _ := sum.Get("accounts"); v != 2 {
				t.Errorf("summary = %v", sum)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	record()
	record() // a repeated sync converges
	if err := e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		as, err := tx.Accounts()
		if err != nil || len(as) != 2 {
			t.Fatalf("accounts: %v %v", as, err)
		}
		for _, a := range as {
			if a.System != "corp-ldap" {
				t.Errorf("account %+v is not in the connection's system", a)
			}
			if a.Username == "bob" && a.Status != "disabled" {
				t.Errorf("bob = %+v", a)
			}
		}
		if gs, err := tx.Groups(); err != nil || len(gs) != 1 || gs[0].System != "corp-ldap" || gs[0].Name != "devs" {
			t.Errorf("groups: %v %v", gs, err)
		}
		if es, err := tx.Edges(); err != nil || len(es) != 1 {
			t.Errorf("edges: %v %v", es, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	evs := e.audit(t, tenantA, "connectors.sync")
	if len(evs) != 2 {
		t.Fatalf("connectors.sync events: %d", len(evs))
	}
	// a membership the listing does not define is refused by the agent
	// service's validation, and ingest refuses it too (no half-written sync)
	bad := &agent.SyncResult{Members: []agent.SyncMember{{Account: "ghost", Group: "nope"}}}
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		_, err := worker.RecordAgentSync(tx, e.clk.Now(), &store.AgentJob{ID: "job-2", AgentID: a1, ConnectionID: conn}, agent.SyncSpec{}, bad)
		return err
	}); err == nil {
		t.Error("a membership to an unknown account was ingested")
	}
}

// TestAgentSyncEndToEnd: the whole pull path over mutual TLS, as the binaries
// wire it. A worker queues the sync, the agent in the customer network
// claims it, reads its (stubbed) directory under its own allowlist and
// credential store, reports, and the API's agent listener records it through
// ingest. Another tenant's agent, polling at the same time, never gets it and
// nothing of it lands in the other tenant.
func TestAgentSyncEndToEnd(t *testing.T) {
	e := newEnv(t, tenantA, tenantB)
	pki := agenttest.NewPKI(t)
	svc := &agent.Service{DB: e.db, Hub: agent.NewHub(nil), Clock: e.clk.Now, Recorder: worker.RecordAgentSync, PullPoll: 20 * time.Millisecond}
	tlsCfg, err := agent.ServerTLSConfig(pki.CertFile, pki.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(svc.Handler(100 * time.Millisecond))
	srv.TLS = tlsCfg
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	enrol := func(tn tenancy.ID, name string) (*agent.Client, string) {
		var en *agent.Enrolment
		if err := e.db.InTenant(ctx, tn, func(tx *store.TenantTx) (err error) {
			en, err = svc.Create(tx, name, "admin", e.clk.Now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		cert, err := agent.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "id"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := agent.NewClient(srv.URL, pki.CAPEM, cert)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Enrol(ctx, en.Code, agent.Telemetry{Hostname: "h", OS: "linux", Version: agent.Version, AllowlistHash: strings.Repeat("a", 64)}); err != nil {
			t.Fatal(err)
		}
		return c, en.Agent.ID
	}
	cA, idA := enrol(tenantA, "dc-a")
	cB, _ := enrol(tenantB, "dc-b")
	connA := e.addConn(t, tenantA, "corp-ldap", "ldap", "agent:"+idA+"/svc", ldapConfig)

	allow, err := safedial.ParseAllow("ldap.corp.example:636")
	if err != nil {
		t.Fatal(err)
	}
	listing := &agent.SyncResult{
		Accounts: []agent.SyncAccount{{ExternalID: "uid=alice,dc=corp", Username: "alice", Status: "active"}},
		Groups:   []agent.SyncGroup{{ExternalID: "cn=devs,dc=corp", Name: "devs"}},
		Members:  []agent.SyncMember{{Account: "uid=alice,dc=corp", Group: "cn=devs,dc=corp"}}}
	run := func(c *agent.Client, sy agent.SyncerFactory) chan error {
		r := &agent.Runner{Client: c, HeartbeatEvery: time.Hour, Telemetry: agent.Telemetry{Version: agent.Version},
			Exec: &agent.Executor{Allow: allow, Creds: credFunc(func(string) (string, error) { return "pw", nil }), NewSyncer: sy}}
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx) }()
		return done
	}
	doneA := run(cA, func(agent.ProberSpec) (agent.Syncer, error) {
		return syncFunc(func() *agent.SyncResult { return listing }), nil
	})
	doneB := run(cB, func(agent.ProberSpec) (agent.Syncer, error) {
		t.Error("tenant B's agent was handed a sync")
		return syncFunc(func() *agent.SyncResult { return &agent.SyncResult{} }), nil
	})

	// the worker side: the connector_sync job queues the agent's sync
	q := e.queue(t, "w", time.Minute, &worker.Deps{Connectors: noConnectors}, "connector_sync")
	e.enqueue(t, q, tenantA, "connector_sync", "k")
	if err := q.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	q.Wait()

	deadline := time.Now().Add(15 * time.Second)
	var job *store.AgentJob
	for {
		js := e.agentJobs(t, tenantA)
		if len(js) == 1 && js[0].Status == store.AgentJobDone {
			job = js[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sync never finished: %+v", js)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.ConnectionID != connA || job.AgentID != idA || job.ResultSummary == nil {
		t.Errorf("job = %+v", job)
	}
	if err := e.db.ReadTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		as, err := tx.Accounts()
		if err != nil || len(as) != 1 || as[0].Username != "alice" || as[0].System != "corp-ldap" {
			t.Errorf("A's accounts: %v %v", as, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.ReadTenant(ctx, tenantB, func(tx *store.TenantTx) error {
		if as, err := tx.Accounts(); err != nil || len(as) != 0 {
			t.Errorf("B's accounts: %v %v", as, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if evs := e.audit(t, tenantA, "agent.job_done"); len(evs) != 1 {
		t.Errorf("agent.job_done events: %d", len(evs))
	}
	if len(e.agentJobs(t, tenantB)) != 0 {
		t.Error("B has agent jobs")
	}
	cancel()
	for _, d := range []chan error{doneA, doneB} {
		if err := <-d; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
	if !slices.Contains(worker.Kinds, "connector_sync") {
		t.Fatal("unreachable")
	}
}

type credFunc func(string) (string, error)

func (f credFunc) Get(n string) (string, error) { return f(n) }

type syncFunc func() *agent.SyncResult

func (f syncFunc) Discover(context.Context, agent.SyncLimits) (*agent.SyncResult, error) {
	return f(), nil
}
