package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Pulled sync jobs (issue #302): an agent in a customer network long-polls
// Tessera over mutual TLS, receives only the jobs addressed to its own
// (tenant, agent), and reports a typed listing that the server records.

var pullSpec = agent.SyncSpec{System: "corp-ldap", Target: agent.Target{Host: "ldap.corp.example", Port: 636},
	Config: agent.ProbeConfig{BindDN: "uid=svc,dc=corp,dc=example", CredName: "svc", BaseDNs: []string{"dc=corp,dc=example"}}}

var pullResult = &agent.SyncResult{
	Accounts: []agent.SyncAccount{{ExternalID: "uid=alice,dc=corp", Username: "alice", Email: "alice@corp.example", Status: "active"}},
	Groups:   []agent.SyncGroup{{ExternalID: "cn=devs,dc=corp", Name: "devs"}},
	Members:  []agent.SyncMember{{Account: "uid=alice,dc=corp", Group: "cn=devs,dc=corp"}},
}

// recorder is a SyncRecorder that remembers what it was given.
type recorder struct {
	mu    sync.Mutex
	calls []recorded
}

type recorded struct {
	tenant string
	job    string
	conn   string
	res    *agent.SyncResult
}

func (r *recorder) record(tx *store.TenantTx, _ time.Time, j *store.AgentJob, _ agent.SyncSpec, res *agent.SyncResult) (ojson.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recorded{tenant: tx.Tenant().String(), job: j.ID, conn: j.ConnectionID, res: res})
	return ojson.Object{{Key: "accounts", Value: len(res.Accounts)}}, nil
}

func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.calls) }

type pullStack struct {
	*stack
	rec *recorder
}

func newPullStack(t *testing.T) *pullStack {
	t.Helper()
	s := newStack(t)
	p := &pullStack{stack: s, rec: &recorder{}}
	s.svc.Recorder = p.rec.record
	s.svc.PullPoll = 20 * time.Millisecond
	return p
}

// enrol creates and enrols an agent of the tenant and returns its client and id.
func (p *pullStack) enrol(t *testing.T, tn storetest.Tenant, name string) (*agent.Client, string) {
	t.Helper()
	e := p.issue(t, tn, name)
	c := p.client(t, filepath.Join(t.TempDir(), "id"))
	if _, err := c.Enrol(context.Background(), e.Code, tel); err != nil {
		t.Fatal(err)
	}
	return c, e.Agent.ID
}

func (p *pullStack) enqueue(t *testing.T, tn storetest.Tenant, agentID, conn, key string) string {
	t.Helper()
	raw, _ := json.Marshal(pullSpec)
	j := &store.AgentJob{AgentID: agentID, ConnectionID: conn, Kind: store.AgentJobSync, Payload: string(raw), IdempotencyKey: &key}
	if err := p.f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		created, err := c.EnqueueAgentJob(j, p.clock.Now())
		if err == nil && !created {
			t.Fatal("job not created")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return j.ID
}

func (p *pullStack) job(t *testing.T, tn storetest.Tenant, id string) *store.AgentJob {
	t.Helper()
	var j *store.AgentJob
	if err := p.f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
		j, err = c.AgentJob(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return j
}

func statusOf(err error) int {
	var se *agent.StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// TestPull_ScopedToAgentAndTenant: two agents of one tenant and one agent of
// another each see only the jobs addressed to them. Another agent's job id,
// or another tenant's, is "unknown job" for a report; a job that was never
// claimed cannot be reported by anyone.
func TestPull_ScopedToAgentAndTenant(t *testing.T) {
	p := newPullStack(t)
	ctx := context.Background()
	cA1, idA1 := p.enrol(t, p.f.A, "dc-1")
	cA2, idA2 := p.enrol(t, p.f.A, "dc-2")
	cB1, idB1 := p.enrol(t, p.f.B, "dc-1")
	connA, connB := p.f.A.Refs["connection:ad"], p.f.B.Refs["connection:ad"]
	jA1 := p.enqueue(t, p.f.A, idA1, connA, "k-a1")
	jA2 := p.enqueue(t, p.f.A, idA2, connA, "k-a2")
	jB1 := p.enqueue(t, p.f.B, idB1, connB, "k-b1")

	got, err := cB1.Claim(ctx)
	if err != nil || got == nil || got.ID != jB1 || got.ConnectionID != connB || got.Spec.System != "corp-ldap" || got.Attempt != 1 {
		t.Fatalf("B's agent claimed %+v, %v", got, err)
	}
	if again, err := cB1.Claim(ctx); err != nil || again != nil {
		t.Fatalf("B's agent claimed a second job: %+v, %v", again, err)
	}
	got, err = cA1.Claim(ctx)
	if err != nil || got == nil || got.ID != jA1 || got.ConnectionID != connA {
		t.Fatalf("A's first agent claimed %+v, %v", got, err)
	}
	if again, err := cA1.Claim(ctx); err != nil || again != nil {
		t.Fatalf("A's first agent claimed a second job: %+v, %v", again, err)
	}

	// reports: not mine, not leased, or in another tenant
	for name, tc := range map[string]struct {
		c  *agent.Client
		id string
	}{
		"another agent of the tenant": {cA1, jA2},
		"another tenant's agent":      {cB1, jA1},
		"another tenant's job":        {cA1, jB1},
		"a job never claimed":         {cA2, jA2},
		"an unknown id":               {cA1, "no-such-job"},
	} {
		err := tc.c.Report(ctx, agent.PullResult{JobID: tc.id, Sync: pullResult})
		if statusOf(err) != http.StatusNotFound {
			t.Errorf("%s: %v", name, err)
		}
	}
	if p.rec.count() != 0 {
		t.Fatalf("a rejected report was recorded: %+v", p.rec.calls)
	}
	for id, tn := range map[string]storetest.Tenant{jA1: p.f.A, jA2: p.f.A, jB1: p.f.B} {
		if st := p.job(t, tn, id).Status; st == store.AgentJobDone {
			t.Errorf("job %s finished by a report that was refused", id)
		}
	}

	// the right agents finish their own
	if got, err = cA2.Claim(ctx); err != nil || got == nil || got.ID != jA2 {
		t.Fatalf("A's second agent claimed %+v, %v", got, err)
	}
	if err := cA2.Report(ctx, agent.PullResult{JobID: jA2, Sync: pullResult}); err != nil {
		t.Fatal(err)
	}
	if err := cA1.Report(ctx, agent.PullResult{JobID: jA1, Sync: pullResult}); err != nil {
		t.Fatal(err)
	}
	if err := cB1.Report(ctx, agent.PullResult{JobID: jB1, Sync: pullResult}); err != nil {
		t.Fatal(err)
	}
	if err := cB1.Report(ctx, agent.PullResult{JobID: jB1, Sync: pullResult}); statusOf(err) != http.StatusNotFound {
		t.Errorf("a result reported twice: %v", err)
	}
	if p.rec.count() != 3 {
		t.Fatalf("recorded %d syncs, want 3", p.rec.count())
	}
	byJob := map[string]recorded{}
	for _, c := range p.rec.calls {
		byJob[c.job] = c
	}
	if byJob[jA1].tenant != p.f.A.ID.String() || byJob[jA2].tenant != p.f.A.ID.String() || byJob[jB1].tenant != p.f.B.ID.String() ||
		byJob[jA1].conn != connA || byJob[jB1].conn != connB {
		t.Errorf("a sync was recorded in the wrong tenant or connection: %+v", byJob)
	}
	for id, tn := range map[string]storetest.Tenant{jA1: p.f.A, jA2: p.f.A, jB1: p.f.B} {
		if j := p.job(t, tn, id); j.Status != store.AgentJobDone || j.ResultSummary == nil || *j.ResultSummary != `{"accounts":1}` {
			t.Errorf("job %s = %+v", id, j)
		}
	}
	if evs := auditActions(t, p.stack, p.f.A, "agent.job_done"); len(evs) != 2 {
		t.Errorf("agent.job_done events in A: %d", len(evs))
	}
	if evs := auditActions(t, p.stack, p.f.B, "agent.job_done"); len(evs) != 1 {
		t.Errorf("agent.job_done events in B: %d", len(evs))
	}
}

// TestPull_RefusesWhatIsNotAnEnrolledAgent: the pull endpoints need the pinned
// client key like every other agent endpoint.
func TestPull_RefusesWhatIsNotAnEnrolledAgent(t *testing.T) {
	p := newPullStack(t)
	ctx := context.Background()
	stranger := p.client(t, filepath.Join(t.TempDir(), "id")) // a key nobody pinned
	if _, err := stranger.Claim(ctx); !agent.IsUnauthorized(err) {
		t.Errorf("claim by an unknown key: %v", err)
	}
	if err := stranger.Report(ctx, agent.PullResult{JobID: "x", Sync: pullResult}); !agent.IsUnauthorized(err) {
		t.Errorf("report by an unknown key: %v", err)
	}
	// a pending agent (code issued, not enrolled) has no key either
	p.issue(t, p.f.A, "pending")
	pending := p.client(t, filepath.Join(t.TempDir(), "id"))
	if _, err := pending.Claim(ctx); !agent.IsUnauthorized(err) {
		t.Errorf("claim by a pending agent: %v", err)
	}
}

// TestPull_ReportValidationAndFailures: a listing that breaks the bounds is
// refused and leaves the job leased; an error report requeues what may work
// later and fails what never will.
func TestPull_ReportValidationAndFailures(t *testing.T) {
	p := newPullStack(t)
	ctx := context.Background()
	c, id := p.enrol(t, p.f.A, "dc-1")
	conn := p.f.A.Refs["connection:ad"]
	j := p.enqueue(t, p.f.A, id, conn, "k1")
	if got, err := c.Claim(ctx); err != nil || got == nil {
		t.Fatalf("claim: %v %v", got, err)
	}
	huge := &agent.SyncResult{}
	for i := 0; i <= agent.MaxSyncAccounts; i++ {
		huge.Accounts = append(huge.Accounts, agent.SyncAccount{ExternalID: "a", Username: "a", Status: "active"})
	}
	for name, res := range map[string]*agent.SyncResult{
		"a membership to an unknown account": {Groups: pullResult.Groups, Members: []agent.SyncMember{{Account: "ghost", Group: "cn=devs,dc=corp"}}},
		"an unknown status":                  {Accounts: []agent.SyncAccount{{ExternalID: "a", Username: "a", Status: "root"}}},
		"a control character":                {Accounts: []agent.SyncAccount{{ExternalID: "a\nb", Username: "a", Status: "active"}}},
		"an empty username":                  {Accounts: []agent.SyncAccount{{ExternalID: "a", Status: "active"}}},
		"more accounts than the limit":       huge,
	} {
		if err := c.Report(ctx, agent.PullResult{JobID: j, Sync: res}); statusOf(err) != http.StatusBadRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := c.Report(ctx, agent.PullResult{JobID: j}); statusOf(err) != http.StatusBadRequest {
		t.Errorf("a report with neither error nor result: %v", err)
	}
	if j := p.job(t, p.f.A, j); j.Status != store.AgentJobLeased || p.rec.count() != 0 {
		t.Fatalf("a refused report changed the job: %+v", j)
	}

	// a transient failure goes back to the queue
	if err := c.Report(ctx, agent.PullResult{JobID: j, Error: &agent.ResultError{Code: agent.CodeFailed, Message: "ldap timeout"}}); err != nil {
		t.Fatal(err)
	}
	if got := p.job(t, p.f.A, j); got.Status != store.AgentJobQueued || !strings.Contains(got.LastError, "ldap timeout") {
		t.Fatalf("after a transient failure: %+v", got)
	}
	// a refused target or a missing credential will not get better by retrying
	if got, err := c.Claim(ctx); err != nil || got == nil || got.Attempt != 2 {
		t.Fatalf("second claim: %+v %v", got, err)
	}
	if err := c.Report(ctx, agent.PullResult{JobID: j, Error: &agent.ResultError{Code: agent.CodeTargetNotAllowed}}); err != nil {
		t.Fatal(err)
	}
	if got := p.job(t, p.f.A, j); got.Status != store.AgentJobFailed || got.FinishedAt == nil {
		t.Fatalf("after a permanent failure: %+v", got)
	}
	if evs := auditActions(t, p.stack, p.f.A, "agent.job_failed"); len(evs) != 2 {
		t.Errorf("agent.job_failed events: %d", len(evs))
	}
	if again, err := c.Claim(ctx); err != nil || again != nil {
		t.Errorf("a failed job was handed out again: %+v %v", again, err)
	}
}

// TestPull_LeaseExpiryAndRevocation: a job claimed by an agent that never
// reports is handed out again after JobLease, up to its attempts; revoking the
// agent cancels what it holds and locks it out.
func TestPull_LeaseExpiryAndRevocation(t *testing.T) {
	p := newPullStack(t)
	ctx := context.Background()
	c, id := p.enrol(t, p.f.A, "dc-1")
	j := p.enqueue(t, p.f.A, id, p.f.A.Refs["connection:ad"], "k1")
	for attempt := 1; attempt <= 3; attempt++ {
		got, err := c.Claim(ctx)
		if err != nil || got == nil || got.Attempt != attempt {
			t.Fatalf("claim %d: %+v %v", attempt, got, err)
		}
		if again, _ := c.Claim(ctx); again != nil {
			t.Fatalf("a leased job was handed out twice")
		}
		p.clock.Advance(agent.JobLease + time.Second)
	}
	// attempts used up: the next claim buries it instead of handing it out
	if got, err := c.Claim(ctx); err != nil || got != nil {
		t.Fatalf("claim after the last attempt: %+v %v", got, err)
	}
	if got := p.job(t, p.f.A, j); got.Status != store.AgentJobFailed || !strings.Contains(got.LastError, "did not report") {
		t.Fatalf("exhausted job = %+v", got)
	}

	j2 := p.enqueue(t, p.f.A, id, p.f.A.Refs["connection:ad"], "k2")
	if got, err := c.Claim(ctx); err != nil || got == nil || got.ID != j2 {
		t.Fatalf("claim: %+v %v", got, err)
	}
	if err := p.f.DB.InTenant(ctx, p.f.A.ID, func(cx *store.TenantTx) error {
		return p.svc.Revoke(cx, id, "admin", p.clock.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if got := p.job(t, p.f.A, j2); got.Status != store.AgentJobCancelled {
		t.Errorf("the revoked agent's job = %+v", got)
	}
	if _, err := c.Claim(ctx); !agent.IsUnauthorized(err) {
		t.Errorf("a revoked agent claimed: %v", err)
	}
	if err := c.Report(ctx, agent.PullResult{JobID: j2, Sync: pullResult}); !agent.IsUnauthorized(err) {
		t.Errorf("a revoked agent reported: %v", err)
	}
	if p.rec.count() != 0 {
		t.Error("a revoked agent's report was recorded")
	}
}

// TestPull_RunnerEndToEnd: the agent's own loop pulls a job over mTLS, reads
// the directory through its Syncer under its local allowlist and credential
// store, and reports. A target that is not on the allowlist fails the job
// without the credential being read.
func TestPull_RunnerEndToEnd(t *testing.T) {
	p := newPullStack(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, id := p.enrol(t, p.f.A, "dc-1")
	conn := p.f.A.Refs["connection:ad"]
	creds := &memCreds{m: map[string]string{"svc": "pw-secret"}}
	var built int
	var mu sync.Mutex
	r := &agent.Runner{Client: c, Telemetry: tel, HeartbeatEvery: time.Hour,
		Exec: &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds,
			NewSyncer: func(s agent.ProberSpec) (agent.Syncer, error) {
				mu.Lock()
				built++
				mu.Unlock()
				if s.Password != "pw-secret" {
					t.Errorf("the syncer got password %q", s.Password)
				}
				return syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) { return pullResult, nil }), nil
			}}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	j := p.enqueue(t, p.f.A, id, conn, "k1")
	waitFor(t, "the sync to be recorded", func() bool { return p.rec.count() == 1 })
	waitFor(t, "the job to finish", func() bool { return p.job(t, p.f.A, j).Status == store.AgentJobDone })
	if got := p.rec.calls[0]; got.job != j || len(got.res.Accounts) != 1 || got.res.Accounts[0].Username != "alice" {
		t.Errorf("recorded %+v", got)
	}

	// a job for a target the agent's own allowlist does not name
	raw, _ := json.Marshal(agent.SyncSpec{System: "other", Target: agent.Target{Host: "hr-db.corp.example", Port: 636},
		Config: pullSpec.Config})
	key := "k-off"
	off := &store.AgentJob{AgentID: id, ConnectionID: conn, Kind: store.AgentJobSync, Payload: string(raw), IdempotencyKey: &key}
	reads := creds.reads
	if err := p.f.DB.InTenant(ctx, p.f.A.ID, func(cx *store.TenantTx) error {
		_, err := cx.EnqueueAgentJob(off, p.clock.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the refused job to fail", func() bool { return p.job(t, p.f.A, off.ID).Status == store.AgentJobFailed })
	if got := p.job(t, p.f.A, off.ID); !strings.Contains(got.LastError, agent.CodeTargetNotAllowed) {
		t.Errorf("refused job = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if built != 1 || creds.reads != reads {
		t.Errorf("a refused target built %d syncers and read %d credentials", built, creds.reads-reads)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

type syncerFunc func(context.Context, agent.SyncLimits) (*agent.SyncResult, error)

func (f syncerFunc) Discover(ctx context.Context, l agent.SyncLimits) (*agent.SyncResult, error) {
	return f(ctx, l)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestExecuteSync: the agent-side checks of a pulled job, before anything is
// dialed and without the credential ever leaving the agent.
func TestExecuteSync(t *testing.T) {
	job := func(mut func(*agent.PulledJob)) agent.PulledJob {
		j := agent.PulledJob{ID: "j1", Kind: agent.KindSync, ConnectionID: "c1", Attempt: 1, Spec: pullSpec, TimeoutSecs: 60}
		if mut != nil {
			mut(&j)
		}
		return j
	}
	ok := syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) { return pullResult, nil })
	exec := func(creds *memCreds, sy agent.SyncerFactory) *agent.Executor {
		return &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds, NewSyncer: sy}
	}
	good := func(agent.ProberSpec) (agent.Syncer, error) { return ok, nil }
	for name, tc := range map[string]struct {
		e    *agent.Executor
		j    agent.PulledJob
		code string
	}{
		"no syncer in this build": {exec(&memCreds{m: map[string]string{"svc": "pw"}}, nil), job(nil), agent.CodeUnsupported},
		"an unknown kind":         {exec(&memCreds{}, good), job(func(j *agent.PulledJob) { j.Kind = "exec" }), agent.CodeUnknownOp},
		"a port that is not LDAP": {exec(&memCreds{}, good), job(func(j *agent.PulledJob) { j.Spec.Target.Port = 22 }), agent.CodeBadRequest},
		"an invalid system name":  {exec(&memCreds{}, good), job(func(j *agent.PulledJob) { j.Spec.System = "" }), agent.CodeBadRequest},
		"not on the allowlist": {exec(&memCreds{m: map[string]string{"svc": "pw"}}, good),
			job(func(j *agent.PulledJob) { j.Spec.Target.Host = "evil.example" }), agent.CodeTargetNotAllowed},
		"no such credential": {exec(&memCreds{m: map[string]string{}}, good), job(nil), agent.CodeNoCredential},
		"a listing that breaks the limits": {exec(&memCreds{m: map[string]string{"svc": "pw"}}, func(agent.ProberSpec) (agent.Syncer, error) {
			return syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) {
				return &agent.SyncResult{Members: []agent.SyncMember{{Account: "x", Group: "y"}}}, nil
			}), nil
		}), job(nil), agent.CodeFailed},
	} {
		res := tc.e.ExecuteSync(context.Background(), tc.j)
		if res.JobID != "j1" || res.Error == nil || res.Error.Code != tc.code || res.Sync != nil {
			t.Errorf("%s: %+v", name, res)
		}
		if tc.code == agent.CodeTargetNotAllowed || tc.code == agent.CodeBadRequest {
			if c, isMem := tc.e.Creds.(*memCreds); isMem && c.reads != 0 {
				t.Errorf("%s: the credential was read before the checks passed", name)
			}
		}
	}
	// success: the typed listing, and a library error never carries the secret
	res := exec(&memCreds{m: map[string]string{"svc": "pw-secret"}}, good).ExecuteSync(context.Background(), job(nil))
	if res.Error != nil || res.Sync == nil || len(res.Sync.Accounts) != 1 {
		t.Fatalf("success = %+v", res)
	}
	leaky := exec(&memCreds{m: map[string]string{"svc": "pw-secret"}}, func(agent.ProberSpec) (agent.Syncer, error) {
		return syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) {
			return nil, errors.New("bind failed with password pw-secret")
		}), nil
	})
	res = leaky.ExecuteSync(context.Background(), job(nil))
	if res.Error == nil || strings.Contains(res.Error.Message, "pw-secret") {
		t.Errorf("the credential leaked into the report: %+v", res.Error)
	}
}
