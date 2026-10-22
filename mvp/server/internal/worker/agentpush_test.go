package worker_test

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/agent/agenttest"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// Provisioning pushes through a remote agent (issue #302), end to end: the
// engine queues a provision_push job for the agent that reaches the target, the
// agent pulls it over mutual TLS, opens the credential sealed to its key,
// pushes to a private HTTPS SCIM target and reports, and the server finishes
// the operation and audits it in one transaction.

const (
	pushToken = "scim-bearer-token-for-the-private-target"
	pushHost  = "scim.corp.example"
	pushUser  = "alice@corp.example"
)

var failPushCompletion bool

func init() {
	provision.RegisterCompletion("worker.agentpush.mark", func(_ *store.TenantTx, _ time.Time, _ json.RawMessage) error {
		if failPushCompletion {
			return errors.New("the graph changed under the completion")
		}
		return nil
	})
}

type mapResolver map[string][]netip.Addr

func (m mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := m[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

type pushStack struct {
	t       *testing.T
	f       *storetest.Fixture
	pki     *agenttest.PKI
	svc     *agent.Service
	srv     *httptest.Server
	scim    *fake.Server
	scimSrv *httptest.Server
	sealer  *seal.Sealer
	eng     *provision.Engine
	now     time.Time
	system  string
}

type pushAgent struct {
	id     string
	client *agent.Client
	key    *ecdh.PrivateKey
	exec   *agent.Executor
}

func newPushStack(t *testing.T, o fake.Options) *pushStack {
	t.Helper()
	f := storetest.TwoTenants(t)
	s := &pushStack{t: t, f: f, pki: agenttest.NewPKI(t), now: storetest.Now}
	var err error
	if s.sealer, err = seal.New(seal.RandomBytes(seal.KeySize)); err != nil {
		t.Fatal(err)
	}
	s.svc = &agent.Service{DB: f.DB, Hub: agent.NewHub(nil), Clock: func() time.Time { return s.now },
		Recorder: worker.RecordAgentSync, Push: &worker.AgentPush{Sealer: s.sealer}, PullPoll: 10 * time.Millisecond}
	tlsCfg, err := agent.ServerTLSConfig(s.pki.CertFile, s.pki.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	s.srv = httptest.NewUnstartedServer(s.svc.Handler(50 * time.Millisecond))
	s.srv.TLS = tlsCfg
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)

	o.Token = pushToken
	s.scim = fake.New(o)
	s.scim.AddUser(pushUser, "Alice", true)
	s.scimSrv = httptest.NewUnstartedServer(s.scim.Handler())
	s.scimSrv.TLS = &tls.Config{Certificates: []tls.Certificate{s.pki.Issue(t, pushHost)}, MinVersion: tls.VersionTLS12}
	s.scimSrv.StartTLS()
	t.Cleanup(s.scimSrv.Close)

	// no HTTP client: a target reached through an agent must never be called by the server
	s.eng = &provision.Engine{DB: f.DB, Sealer: s.sealer, Clock: func() time.Time { return s.now }, MaxAttempts: 3, MaxVerifies: 3,
		Backoff: func(int) time.Duration { return 0 }}
	if err := f.DB.ReadTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		cn, err := c.Connection(f.A.Refs["connection:ad"])
		s.system = cn.System
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// enrol creates and enrols an agent of tn that reaches the private SCIM target
// (and, when register, has registered its sealing key).
func (s *pushStack) enrol(tn storetest.Tenant, name string, register bool) *pushAgent {
	s.t.Helper()
	var e *agent.Enrolment
	if err := s.f.DB.InTenant(s.t.Context(), tn.ID, func(c *store.TenantTx) (err error) {
		e, err = s.svc.Create(c, name, "admin@"+tn.Slug, s.now)
		return err
	}); err != nil {
		s.t.Fatal(err)
	}
	cert, err := agent.LoadOrCreateIdentity(filepath.Join(s.t.TempDir(), "id"))
	if err != nil {
		s.t.Fatal(err)
	}
	c, err := agent.NewClient(s.srv.URL, s.pki.CAPEM, cert)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := c.Enrol(s.t.Context(), e.Code, agent.Telemetry{Hostname: "dc-1", OS: "linux", Version: agent.Version,
		AllowlistHash: strings.Repeat("a", 64)}); err != nil {
		s.t.Fatal(err)
	}
	key, err := seal.GenerateAgentKey()
	if err != nil {
		s.t.Fatal(err)
	}
	if register {
		if _, err := c.RegisterSealKey(s.t.Context(), key.PublicKey().Bytes()); err != nil {
			s.t.Fatal(err)
		}
	}
	allow, err := safedial.ParseAllowHTTPS(pushHost + ":443")
	if err != nil {
		s.t.Fatal(err)
	}
	ex := &agent.Executor{AllowPush: allow, PushRoots: s.pki.Roots(), SealKey: key, PushVerifyWait: time.Millisecond,
		Resolver: mapResolver{pushHost: {netip.MustParseAddr("10.1.2.3")}},
		TestDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, s.scimSrv.Listener.Addr().String())
		}}
	return &pushAgent{id: e.Agent.ID, client: c, key: key, exec: ex}
}

// target points tenant A's connection at the private SCIM target through the agent.
func (s *pushStack) target(agentID string) {
	s.t.Helper()
	settings, _ := json.Marshal(provision.Settings{AgentID: agentID})
	id := store.NewID()
	enc, err := provision.SealToken(s.sealer, s.f.A.ID, id, pushToken)
	if err != nil {
		s.t.Fatal(err)
	}
	s.inA(func(c *store.TenantTx) error {
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: s.f.A.Refs["connection:ad"], Kind: provision.KindSCIM,
			BaseURL: "https://" + pushHost + "/scim/v2", Settings: string(settings), CredentialEnc: enc, WriteBack: true, CreatedBy: "admin"}, s.now)
	})
}

func (s *pushStack) inA(fn func(*store.TenantTx) error) {
	s.t.Helper()
	if err := s.f.DB.InTenant(s.t.Context(), s.f.A.ID, fn); err != nil {
		s.t.Fatal(err)
	}
}

func (s *pushStack) submit(kind, key string) *store.ProvOp {
	s.t.Helper()
	var op *store.ProvOp
	s.inA(func(c *store.TenantTx) error {
		var routed bool
		var err error
		op, routed, err = provision.Submit(c, s.now, provision.Change{System: s.system, Kind: kind,
			Account: target.Account{Username: pushUser}, Source: provision.SourceAPI, Key: key, Completion: "worker.agentpush.mark",
			Data: map[string]int{"n": 1}})
		if err == nil && !routed {
			err = errors.New("not routed")
		}
		return err
	})
	return op
}

func (s *pushStack) run() provision.Stats {
	s.t.Helper()
	st, err := s.eng.RunTenant(s.t.Context(), s.f.A.ID)
	if err != nil {
		s.t.Fatal(err)
	}
	return st
}

func (s *pushStack) op(id string) *store.ProvOp {
	s.t.Helper()
	var op *store.ProvOp
	s.inA(func(c *store.TenantTx) (err error) { op, err = c.ProvOp(id); return })
	return op
}

func (s *pushStack) jobs() []*store.AgentJob {
	s.t.Helper()
	var js []*store.AgentJob
	s.inA(func(c *store.TenantTx) (err error) { js, err = c.AgentJobs(store.AgentJobFilter{}); return })
	return js
}

func (s *pushStack) audit(action string) []*store.AuditEvent {
	s.t.Helper()
	var evs []*store.AuditEvent
	s.inA(func(c *store.TenantTx) (err error) {
		evs, err = c.AuditEvents(store.AuditFilter{Action: action})
		return
	})
	return evs
}

// pull claims the agent's next job, runs it and reports the result.
func (s *pushStack) pull(a *pushAgent) (*agent.PulledJob, agent.PullResult) {
	s.t.Helper()
	j, err := a.client.Claim(s.t.Context())
	if err != nil || j == nil {
		s.t.Fatalf("claim = %+v, %v", j, err)
	}
	res := a.exec.ExecutePulled(s.t.Context(), *j)
	if err := a.client.Report(s.t.Context(), res); err != nil {
		s.t.Fatalf("report: %v", err)
	}
	return j, res
}

func (s *pushStack) assertNoToken(what string, v any) {
	s.t.Helper()
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), pushToken) {
		s.t.Errorf("%s holds the credential in the clear: %s", what, b)
	}
}

// The whole path for a disable: queued for the agent, claimed with the
// credential sealed to the agent's key, applied and re-read inside the
// network, reported, and finished with its audit in one transaction.
func TestAgentPush_EndToEnd(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", true)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:disable:1")

	if st := s.run(); st.Processed != 1 || st.Failed != 0 {
		t.Fatalf("pass = %+v", st)
	}
	if got := s.op(op.ID); got.Status != provision.Sent || got.Attempts != 1 {
		t.Fatalf("a dispatched operation waits for its agent as 'sent': %+v", got)
	}
	if reqs := s.scim.Requests(); len(reqs) != 0 {
		t.Fatalf("the server called the private target itself: %v", reqs)
	}
	js := s.jobs()
	if len(js) != 1 || js[0].Kind != store.AgentJobProvisionPush || js[0].AgentID != a.id || js[0].OpID == nil || *js[0].OpID != op.ID ||
		js[0].Status != store.AgentJobQueued || js[0].ConnectionID != s.f.A.Refs["connection:ad"] {
		t.Fatalf("agent jobs = %+v", js)
	}
	s.assertNoToken("the agent job row", js)
	if evs := s.audit("provision.dispatched"); len(evs) != 1 {
		t.Errorf("provision.dispatched events: %d", len(evs))
	}
	// another pass spends no attempt and queues no second job while the agent has it
	s.run()
	if got := s.op(op.ID); got.Attempts != 1 || len(s.jobs()) != 1 {
		t.Errorf("a second pass: attempts = %d, jobs = %d", got.Attempts, len(s.jobs()))
	}

	j, res := s.pull(a)
	if res.Error != nil || res.Push == nil || !res.Push.Applied || !res.Push.Verified {
		t.Fatalf("agent result = %+v", res)
	}
	if j.Kind != store.AgentJobProvisionPush || j.Push == nil || j.Push.AgentID != a.id || j.Push.TenantID != s.f.A.ID.String() ||
		j.Push.Spec.OpID != op.ID || j.Push.Spec.BaseURL != "https://"+pushHost+"/scim/v2" || j.Push.Spec.CredName != "" {
		t.Fatalf("pulled job = %+v", j)
	}
	if len(j.Push.SealedCredential) == 0 || strings.Contains(string(j.Push.SealedCredential), pushToken) || j.Push.SealKeyID != seal.AgentKeyID(a.key.PublicKey().Bytes()) {
		t.Errorf("the credential did not arrive sealed to the agent's key: %d bytes, key %q", len(j.Push.SealedCredential), j.Push.SealKeyID)
	}
	// the target received the bearer token (the sealed credential opened on the agent) and was changed
	if exists, active := s.scim.Active(pushUser); !exists || active {
		t.Errorf("the user was not disabled in the target: exists=%v active=%v", exists, active)
	}

	got := s.op(op.ID)
	if got.Status != provision.Verified || got.CompletedAt == nil {
		t.Fatalf("operation after the report = %+v", got)
	}
	js = s.jobs()
	if js[0].Status != store.AgentJobDone || js[0].ResultSummary == nil || !strings.Contains(*js[0].ResultSummary, `"outcome":"verified"`) {
		t.Errorf("job after the report = %+v", js[0])
	}
	// one audit trail for the outcome: the operation's and the job's events, both naming the agent
	ver, done := s.audit("provision.verified"), s.audit("agent.job_done")
	if len(ver) != 1 || len(done) != 1 || ver[0].Seq != done[0].Seq-1 && ver[0].Seq != done[0].Seq+1 {
		t.Fatalf("verified = %d, job_done = %d (want one each, adjacent in the chain: one transaction)", len(ver), len(done))
	}
	vb, _ := json.Marshal(ver[0])
	if !strings.Contains(string(vb), a.id) || !strings.Contains(string(vb), `"via_agent"`) {
		t.Errorf("the verified event does not name the agent: %s", vb)
	}
	for _, evs := range [][]*store.AuditEvent{ver, done, s.audit("provision.dispatched")} {
		s.assertNoToken("an audit event", evs)
	}
	s.assertNoToken("the operation", got)
	if again := s.run(); again.Processed != 0 {
		t.Errorf("a verified operation ran again: %+v", again)
	}
}

// A push whose re-read does not show the change is a mismatch with a finding,
// like a direct push, and the agent's job is still done.
func TestAgentPush_MismatchRaisesAFinding(t *testing.T) {
	s := newPushStack(t, fake.Options{Fault: fake.DropWrites})
	a := s.enrol(s.f.A, "dc-1", true)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:drop")
	s.run()
	_, res := s.pull(a)
	if res.Push == nil || !res.Push.Applied || res.Push.Verified || res.Push.Expected == "" {
		t.Fatalf("agent result = %+v", res)
	}
	got := s.op(op.ID)
	if got.Status != provision.Mismatch || got.LastError == nil || !strings.Contains(*got.LastError, "does not show the change") {
		t.Fatalf("operation = %+v", got)
	}
	var fs []*store.ProvFinding
	s.inA(func(c *store.TenantTx) (err error) { fs, err = c.ProvFindings("open", op.ID); return })
	if len(fs) != 1 || fs[0].Code != "verify_mismatch" || fs[0].Severity != "high" {
		t.Errorf("findings = %+v", fs)
	}
	if js := s.jobs(); js[0].Status != store.AgentJobDone || !strings.Contains(*js[0].ResultSummary, "mismatch") {
		t.Errorf("job = %+v", js[0])
	}
	if len(s.audit("provision.mismatch")) != 1 || len(s.audit("agent.job_done")) != 1 {
		t.Error("the mismatch and the job's end are not both audited")
	}
}

// A failing target is retried by the agent job (three tries), then the
// operation fails with the reason; a permanent refusal fails at once.
func TestAgentPush_FailuresRetryThenFailTheOperation(t *testing.T) {
	s := newPushStack(t, fake.Options{Fault: fake.FailWrites})
	a := s.enrol(s.f.A, "dc-1", true)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:fail")
	s.run()
	for i := 1; i <= 3; i++ {
		_, res := s.pull(a)
		if res.Error == nil || res.Error.Code != agent.CodeFailed || !strings.Contains(res.Error.Message, "503") {
			t.Fatalf("attempt %d: %+v", i, res)
		}
		js := s.jobs()
		want := store.AgentJobQueued
		if i == 3 {
			want = store.AgentJobFailed
		}
		if js[0].Status != want || js[0].Attempts != i {
			t.Fatalf("after attempt %d: job %s attempts %d", i, js[0].Status, js[0].Attempts)
		}
		if got := s.op(op.ID); (i < 3 && got.Status != provision.Sent) || (i == 3 && got.Status != provision.Failed) {
			t.Fatalf("after attempt %d: operation %s", i, got.Status)
		}
	}
	got := s.op(op.ID)
	if got.LastError == nil || !strings.Contains(*got.LastError, "503") || strings.Contains(*got.LastError, pushToken) {
		t.Errorf("operation error = %v", got.LastError)
	}
	if len(s.audit("provision.failed")) != 1 {
		t.Error("provision.failed was not audited once")
	}
	// the operator fixes the target and retries: a new job, the same operation, verified
	s.scim.SetFault("")
	s.inA(func(c *store.TenantTx) error { _, err := provision.Retry(c, s.now, op.ID); return err })
	s.run()
	if _, res := s.pull(a); res.Push == nil || !res.Push.Verified {
		t.Fatalf("after the retry: %+v", res)
	}
	if got := s.op(op.ID); got.Status != provision.Verified {
		t.Errorf("after the retry the operation is %s", got.Status)
	}
	if n := len(s.jobs()); n != 2 {
		t.Errorf("jobs = %d, want the failed one and the retry", n)
	}
}

// A target that is not on the agent's own allowed_push_targets is refused by
// the agent before anything is dialed, and the operation fails at once.
func TestAgentPush_AgentRefusesATargetNotOnItsAllowlist(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", true)
	a.exec.AllowPush = nil
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:refused")
	s.run()
	_, res := s.pull(a)
	if res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed {
		t.Fatalf("result = %+v", res)
	}
	got := s.op(op.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "allowed_push_targets") {
		t.Errorf("operation = %+v", got)
	}
	if len(s.scim.Requests()) != 0 {
		t.Error("the target was contacted")
	}
	if js := s.jobs(); js[0].Status != store.AgentJobFailed || js[0].Attempts != 1 {
		t.Errorf("a refusal is not retried: %+v", js[0])
	}
}

// An agent that has not registered a sealing key cannot be handed a credential:
// the job fails when it is claimed, with the reason, and so does the operation.
func TestAgentPush_NoSealingKeyFailsWithAReason(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "old-agent", false)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:nokey")
	s.run()
	if j, err := a.client.Claim(t.Context()); err != nil || j != nil {
		t.Fatalf("claim = %+v, %v", j, err)
	}
	got := s.op(op.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "sealing key") {
		t.Fatalf("operation = %+v", got)
	}
	if js := s.jobs(); js[0].Status != store.AgentJobFailed {
		t.Errorf("job = %+v", js[0])
	}
}

// The credential is sealed to one agent for one job: another agent of the same
// tenant, another tenant's agent and the same agent for another job cannot open
// it, and none of them can claim or report the job.
func TestAgentPush_ScopedToTheAgentAndTheJob(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", true)
	other := s.enrol(s.f.A, "dc-2", true)
	foreign := s.enrol(s.f.B, "dc-1", true)
	s.target(a.id)
	s.submit(target.DisableAccount, "t:scoped")
	s.run()

	for name, c := range map[string]*pushAgent{"another agent of the tenant": other, "another tenant's agent": foreign} {
		if j, err := c.client.Claim(t.Context()); err != nil || j != nil {
			t.Errorf("%s claimed %+v, %v", name, j, err)
		}
	}
	j, err := a.client.Claim(t.Context())
	if err != nil || j == nil || j.Push == nil {
		t.Fatalf("claim = %+v, %v", j, err)
	}
	// a report for the job from anyone else is unknown_job, and changes nothing
	for name, c := range map[string]*pushAgent{"another agent of the tenant": other, "another tenant's agent": foreign} {
		err := c.client.Report(t.Context(), agent.PullResult{JobID: j.ID, Push: &agent.PushResult{Applied: true, Verified: true}})
		var se *agent.StatusError
		if !errors.As(err, &se) || se.Status != http.StatusNotFound {
			t.Errorf("%s reported the job: %v", name, err)
		}
	}
	if got := s.jobs()[0]; got.Status != store.AgentJobLeased {
		t.Errorf("a stranger's report changed the job: %+v", got)
	}
	// the sealed blob opens for this agent and this job only
	aad, _ := seal.AgentAAD(s.f.A.ID, a.id, j.ConnectionID, j.ID)
	if tok, err := seal.OpenFromAgent(a.key, j.Push.SealedCredential, aad); err != nil || string(tok) != pushToken {
		t.Fatalf("the agent could not open its credential: %q, %v", tok, err)
	}
	if _, err := seal.OpenFromAgent(other.key, j.Push.SealedCredential, aad); err == nil {
		t.Error("another agent's key opened the credential")
	}
	badAAD, _ := seal.AgentAAD(s.f.A.ID, a.id, j.ConnectionID, "another-job")
	if _, err := seal.OpenFromAgent(a.key, j.Push.SealedCredential, badAAD); err == nil {
		t.Error("the credential opened for another job")
	}
	// a spec edited in flight is refused by the agent (an http URL)
	bad := *j
	push := *j.Push
	push.Spec.BaseURL = "http://" + pushHost + "/scim/v2"
	bad.Push = &push
	if r := a.exec.ExecutePulled(t.Context(), bad); r.Error == nil || r.Error.Code != agent.CodeBadRequest {
		t.Errorf("an http target: %+v", r)
	}
}

// Revoking the agent fails the operations it was holding, with the reason, in the
// revoking transaction; an operation dispatched to a revoked agent fails at once.
func TestAgentPush_RevokedAgent(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", true)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:revoke")
	s.run()
	s.inA(func(c *store.TenantTx) error { return s.svc.Revoke(c, a.id, "admin", s.now) })
	got := s.op(op.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "revoked") {
		t.Fatalf("operation after the revoke = %+v", got)
	}
	if js := s.jobs(); js[0].Status != store.AgentJobCancelled {
		t.Errorf("job = %+v", js[0])
	}
	// a later operation for the same target
	op2 := s.submit(target.DisableAccount, "t:after-revoke")
	s.run()
	got = s.op(op2.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "revoked or no longer exists") {
		t.Errorf("operation dispatched to a revoked agent = %+v", got)
	}
	if len(s.jobs()) != 1 {
		t.Error("a job was queued for a revoked agent")
	}
}

// Tessera could not apply its side of a change the target shows: the operation
// fails with that reason and the job ends failed, in a transaction of its own;
// nothing is half done.
func TestAgentPush_CompletionFailureFailsTheOperation(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", true)
	s.target(a.id)
	op := s.submit(target.DisableAccount, "t:completion")
	s.run()
	failPushCompletion = true
	defer func() { failPushCompletion = false }()
	_, res := s.pull(a)
	if res.Push == nil || !res.Push.Verified {
		t.Fatalf("result = %+v", res)
	}
	got := s.op(op.ID)
	if got.Status != provision.Failed || got.LastError == nil || !strings.Contains(*got.LastError, "could not apply the change") {
		t.Fatalf("operation = %+v", got)
	}
	if len(s.audit("provision.verified")) != 0 {
		t.Error("an unfinished operation was audited as verified")
	}
	if js := s.jobs(); js[0].Status != store.AgentJobFailed {
		t.Errorf("job = %+v", js[0])
	}
}

// The agent registers its sealing key over its authenticated channel; a repeat
// of the same key changes nothing, a new key replaces it (audited); a bad key
// and a wrong protocol are refused.
func TestAgentPush_SealKeyRegistration(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", false)
	key, _ := seal.GenerateAgentKey()
	pub := key.PublicKey().Bytes()
	id, err := a.client.RegisterSealKey(t.Context(), pub)
	if err != nil || id != seal.AgentKeyID(pub) {
		t.Fatalf("register = %q, %v", id, err)
	}
	if _, err := a.client.RegisterSealKey(t.Context(), pub); err != nil {
		t.Fatal(err)
	}
	if evs := s.audit("agent.seal_key_registered"); len(evs) != 1 {
		t.Fatalf("a repeated registration was audited again: %d events", len(evs))
	}
	key2, _ := seal.GenerateAgentKey()
	if _, err := a.client.RegisterSealKey(t.Context(), key2.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	evs := s.audit("agent.seal_key_registered")
	if len(evs) != 2 {
		t.Fatalf("events = %d", len(evs))
	}
	b, _ := json.Marshal(evs)
	if strings.Contains(string(b), string(pub)) || !strings.Contains(string(b), `"replaced":true`) {
		t.Errorf("seal key events = %s", b)
	}
	var k *store.AgentSealKey
	s.inA(func(c *store.TenantTx) (err error) { k, err = c.AgentSealKey(a.id); return })
	if k == nil || k.KeyID != seal.AgentKeyID(key2.PublicKey().Bytes()) {
		t.Errorf("stored key = %+v", k)
	}
	for name, bad := range map[string][]byte{"short": make([]byte, 31), "zero": make([]byte, 32), "long": make([]byte, 64)} {
		var se *agent.StatusError
		if _, err := a.client.RegisterSealKey(t.Context(), bad); !errors.As(err, &se) || se.Status != http.StatusBadRequest {
			t.Errorf("%s key: %v", name, err)
		}
	}
	// a revoked agent can no longer register
	s.inA(func(c *store.TenantTx) error { return s.svc.Revoke(c, a.id, "admin", s.now) })
	if _, err := a.client.RegisterSealKey(t.Context(), pub); !agent.IsUnauthorized(err) {
		t.Errorf("a revoked agent registered a key: %v", err)
	}
}

// The agent's own runner does all of it unattended: registers its sealing key
// with its heartbeat, pulls the push, executes it and reports.
func TestAgentPush_RunnerEndToEnd(t *testing.T) {
	s := newPushStack(t, fake.Options{})
	a := s.enrol(s.f.A, "dc-1", false) // the runner registers the key itself
	s.target(a.id)
	r := &agent.Runner{Client: a.client, Exec: a.exec, SealKey: a.key, HeartbeatEvery: 20 * time.Millisecond,
		Telemetry: agent.Telemetry{Hostname: "dc-1", OS: "linux", Version: agent.Version, AllowlistHash: strings.Repeat("a", 64)},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	wait := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	wait("the sealing key", func() bool {
		var k *store.AgentSealKey
		_ = s.f.DB.ReadTenant(t.Context(), s.f.A.ID, func(c *store.TenantTx) error { k, _ = c.AgentSealKey(a.id); return nil })
		return k != nil
	})
	op := s.submit(target.DisableAccount, "t:runner")
	s.run()
	wait("the operation to be verified", func() bool { return s.op(op.ID).Status == provision.Verified })
	if exists, active := s.scim.Active(pushUser); !exists || active {
		t.Errorf("the user was not disabled: exists=%v active=%v", exists, active)
	}
	if got := s.jobs(); len(got) != 1 || got[0].Status != store.AgentJobDone {
		t.Errorf("jobs = %+v", got)
	}
}
