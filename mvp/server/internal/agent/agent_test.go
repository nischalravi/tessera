package agent_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/agent/agenttest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- stubs

// memCreds is an in-memory CredentialStore that counts reads.
type memCreds struct {
	mu    sync.Mutex
	m     map[string]string
	reads int
}

func (c *memCreds) Get(name string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if v, ok := c.m[name]; ok {
		return v, nil
	}
	return "", agent.ErrNoCredential
}

// stubProber answers every operation with a canned value and records the
// operations it ran.
type stubProber struct {
	mu  sync.Mutex
	ops []string
	err error
}

func (p *stubProber) rec(op string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ops = append(p.ops, op)
	return p.err
}

var stubNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func (p *stubProber) Connect(context.Context) (connectors.ConnInfo, error) {
	return connectors.ConnInfo{Reachable: true, TLSVersion: "1.3", ChainValid: true, HostnameMatch: true, NotAfter: stubNow,
		Issuer: "Lab CA"}, p.rec("connect")
}
func (p *stubProber) Authenticate(context.Context) (connectors.AuthInfo, error) {
	return connectors.AuthInfo{OK: true, Identity: "uid=svc", Mode: "simple_bind"}, p.rec("authenticate")
}
func (p *stubProber) RootInfo(context.Context) (connectors.RootInfo, error) {
	return connectors.RootInfo{Domains: []string{"dc=corp,dc=example"}, Capabilities: []string{"paged"}}, p.rec("root_info")
}
func (p *stubProber) ObjectExists(_ context.Context, ref string) (bool, error) {
	return ref == "ou=people,dc=corp,dc=example", p.rec("object_exists")
}
func (p *stubProber) Sample(_ context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	return connectors.SampleStats{Objects: q.Limit, AttrFill: map[string]int{"mail": 3}}, p.rec("sample")
}
func (p *stubProber) EffectiveRights(context.Context, string) (connectors.Rights, error) {
	return connectors.Rights{Unsupported: true}, p.rec("effective_rights")
}
func (p *stubProber) ChangeFeed(context.Context) (connectors.FeedInfo, error) {
	return connectors.FeedInfo{Supported: true, Mechanism: "syncrepl"}, p.rec("change_feed")
}
func (p *stubProber) RateLimits(context.Context) (connectors.RateInfo, error) {
	return connectors.RateInfo{Limit: 10}, p.rec("rate_limits")
}
func (p *stubProber) Time(context.Context) (time.Time, error) { return stubNow, p.rec("time") }

// factory counts how many probers the executor built.
type factory struct {
	mu    sync.Mutex
	built int
	last  agent.ProberSpec
	p     *stubProber
}

func (f *factory) New(s agent.ProberSpec) (connectors.Prober, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.built++
	f.last = s
	return f.p, nil
}

func mustAllow(t *testing.T, s string) []safedial.AllowEntry {
	t.Helper()
	a, err := safedial.ParseAllow(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func job(op agent.Op, host string, port int) agent.Job {
	j := agent.Job{ID: "job-1", Op: op, Target: agent.Target{Host: host, Port: port},
		Config: agent.ProbeConfig{BindDN: "uid=svc,dc=corp,dc=example", CredName: "svc"}}
	switch op {
	case agent.OpSample:
		j.Sample = &connectors.SampleQuery{Op: "search", Filter: "(objectClass=person)", Limit: 50}
	case agent.OpObjectExists, agent.OpEffectiveRights:
		j.Arg = "ou=people,dc=corp,dc=example"
	}
	return j
}

// ---------------------------------------------------------------- allowlist

// TestAgent_RejectsNonAllowlisted: the agent refuses every target that is not
// on its local allowlist, before it reads a credential, builds a prober or
// dials anything. A listed target runs; a listed target that safedial's
// address policy forbids (cloud metadata) is still refused.
func TestAgent_RejectsNonAllowlisted(t *testing.T) {
	allow := "ldap.corp.example:636, 10.20.0.5:389, 10.30.0.0/24:636, 169.254.169.254:636"
	cases := []struct {
		name string
		host string
		port int
	}{
		{"other host", "other.corp.example", 636},
		{"listed host, other port", "ldap.corp.example", 389},
		{"public ip literal", "93.184.216.34", 636},
		{"adjacent private ip", "10.20.0.6", 389},
		{"listed ip, other port", "10.20.0.5", 636},
		{"name for a cidr entry", "dc1.corp.example", 636},
		{"outside the cidr", "10.30.1.9", 636},
		{"localhost", "127.0.0.1", 636},
		{"loopback name", "localhost", 636},
		{"host with a path", "ldap.corp.example/x", 636},
		{"suffix of a listed name", "evil-ldap.corp.example", 636},
		{"prefix of a listed name", "ldap.corp.example.evil.test", 636},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			creds, f := &memCreds{m: map[string]string{"svc": "pw"}}, &factory{p: &stubProber{}}
			ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: creds, New: f.New}
			res := ex.Execute(context.Background(), job(agent.OpConnect, c.host, c.port))
			if res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed && res.Error.Code != agent.CodeBadRequest {
				t.Fatalf("result: %+v", res)
			}
			if f.built != 0 || creds.reads != 0 || len(f.p.ops) != 0 {
				t.Errorf("work done for a refused target: built %d, credential reads %d, ops %v", f.built, creds.reads, f.p.ops)
			}
		})
	}

	t.Run("empty allowlist refuses everything", func(t *testing.T) {
		f := &factory{p: &stubProber{}}
		ex := &agent.Executor{Creds: &memCreds{m: map[string]string{"svc": "pw"}}, New: f.New}
		res := ex.Execute(context.Background(), job(agent.OpConnect, "ldap.corp.example", 636))
		if res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed || f.built != 0 {
			t.Errorf("%+v built %d", res, f.built)
		}
	})

	t.Run("listed target runs", func(t *testing.T) {
		creds, f := &memCreds{m: map[string]string{"svc": "the-secret"}}, &factory{p: &stubProber{}}
		ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: creds, New: f.New}
		for _, tgt := range []struct {
			host string
			port int
		}{{"ldap.corp.example", 636}, {"LDAP.corp.example", 636}, {"10.20.0.5", 389}, {"10.30.0.77", 636}} {
			res := ex.Execute(context.Background(), job(agent.OpConnect, tgt.host, tgt.port))
			if res.Error != nil {
				t.Errorf("%s:%d: %+v", tgt.host, tgt.port, res.Error)
			}
		}
		if f.last.Password != "the-secret" || f.last.Config.CredName != "svc" {
			t.Errorf("spec: %+v", f.last.Config)
		}
	})

	t.Run("listed but forbidden address stays refused", func(t *testing.T) {
		creds := &memCreds{m: map[string]string{"svc": "pw"}}
		ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: creds, New: func(s agent.ProberSpec) (connectors.Prober, error) {
			return &dialProber{spec: s}, nil
		}}
		res := ex.Execute(context.Background(), job(agent.OpConnect, "169.254.169.254", 636))
		if res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed {
			t.Errorf("metadata address dialed: %+v", res)
		}
	})

	t.Run("missing credential", func(t *testing.T) {
		f := &factory{p: &stubProber{}}
		ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: &memCreds{m: map[string]string{}}, New: f.New}
		res := ex.Execute(context.Background(), job(agent.OpConnect, "ldap.corp.example", 636))
		if res.Error == nil || res.Error.Code != agent.CodeNoCredential || f.built != 0 {
			t.Errorf("%+v", res)
		}
	})
}

// dialProber's only operation is to dial through the executor's dialer, as the
// real LDAP prober does.
type dialProber struct {
	stubProber
	spec agent.ProberSpec
}

func (p *dialProber) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	c, err := p.spec.Dialer.Dial(ctx, p.spec.Target.Host, p.spec.Target.Port, false)
	if err != nil {
		return connectors.ConnInfo{}, err
	}
	_ = c.Close()
	return connectors.ConnInfo{Reachable: true}, nil
}

// ---------------------------------------------------------------- typed operations

type recordDispatcher struct {
	mu   sync.Mutex
	jobs []agent.Job
}

func (d *recordDispatcher) Do(_ context.Context, _ tenancy.ID, _ string, j agent.Job) (agent.Result, error) {
	d.mu.Lock()
	d.jobs = append(d.jobs, j)
	d.mu.Unlock()
	// The payloads are all "zero" values of the right type.
	var payload any
	switch j.Op {
	case agent.OpObjectExists:
		payload = true
	case agent.OpTime:
		payload = stubNow
	default:
		payload = map[string]any{}
	}
	b, _ := json.Marshal(payload)
	return agent.Result{JobID: j.ID, Payload: b}, nil
}

// TestAgent_OnlyTypedOps: the set of operations is exactly the Prober's nine;
// the server's RemoteProber emits only those; the agent refuses any other
// operation name, any argument an operation does not take, unbounded
// arguments, and a job with a field it does not know; and the package has no
// way to run a command, send raw bytes or speak LDAP write operations.
func TestAgent_OnlyTypedOps(t *testing.T) {
	t.Run("the operation set is connectors.ProberOps", func(t *testing.T) {
		var got []string
		for _, o := range agent.Ops {
			got = append(got, string(o))
		}
		want := append([]string(nil), connectors.ProberOps...)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("agent ops %v, prober ops %v", got, want)
		}
		if n := reflect.TypeOf((*connectors.Prober)(nil)).Elem().NumMethod(); n != len(agent.Ops) {
			t.Errorf("Prober has %d methods, the agent %d operations", n, len(agent.Ops))
		}
	})

	t.Run("RemoteProber emits exactly one typed job per Prober method", func(t *testing.T) {
		d := &recordDispatcher{}
		p, err := agent.NewRemoteProber(d, storetest.AID, "agent-1", agent.Target{Host: "ldap.corp.example", Port: 636},
			agent.ProbeConfig{BindDN: "uid=svc", CredName: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		_, _ = p.Connect(ctx)
		_, _ = p.Authenticate(ctx)
		_, _ = p.RootInfo(ctx)
		_, _ = p.ObjectExists(ctx, "ou=x")
		_, _ = p.Sample(ctx, connectors.SampleQuery{Op: "search", Limit: 100000})
		_, _ = p.EffectiveRights(ctx, "ou=x")
		_, _ = p.ChangeFeed(ctx)
		_, _ = p.RateLimits(ctx)
		_, _ = p.Time(ctx)
		var ops []string
		for _, j := range d.jobs {
			ops = append(ops, string(j.Op))
			if err := agent.ValidateJob(withID(j)); err != nil {
				t.Errorf("%s: %v", j.Op, err)
			}
			if j.Target.Host != "ldap.corp.example" || j.Config.CredName != "svc" {
				t.Errorf("%s: %+v", j.Op, j)
			}
		}
		if !reflect.DeepEqual(ops, connectors.ProberOps) {
			t.Errorf("emitted %v, want %v", ops, connectors.ProberOps)
		}
		if s := d.jobs[4].Sample; s == nil || s.Limit != connectors.MaxSample {
			t.Errorf("sample limit not capped: %+v", s)
		}
		if _, err := agent.NewRemoteProber(d, storetest.AID, "a", agent.Target{}, agent.ProbeConfig{CredName: "../etc/passwd"}); err == nil {
			t.Error("a path as a credential name was accepted")
		}
	})

	t.Run("the agent refuses anything else", func(t *testing.T) {
		f := &factory{p: &stubProber{}}
		creds := &memCreds{m: map[string]string{"svc": "pw"}}
		ex := &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds, New: f.New}
		for _, op := range []agent.Op{"", "exec", "shell", "ldap_modify", "ldap_add", "ldap_delete", "bind", "search", "dial", "proxy",
			"raw", "tunnel", "CONNECT", "Connect", "connect ", "connect;rm"} {
			res := ex.Execute(context.Background(), job(op, "ldap.corp.example", 636))
			if res.Error == nil || res.Error.Code != agent.CodeUnknownOp {
				t.Errorf("op %q: %+v", op, res)
			}
		}
		bad := map[string]func(*agent.Job){
			"arg on connect":       func(j *agent.Job) { j.Arg = "x" },
			"sample on connect":    func(j *agent.Job) { j.Sample = &connectors.SampleQuery{Limit: 1} },
			"huge arg":             func(j *agent.Job) { j.Op, j.Arg = agent.OpObjectExists, strings.Repeat("a", 5000) },
			"sample without query": func(j *agent.Job) { j.Op, j.Sample = agent.OpSample, nil },
			"sample over the bound": func(j *agent.Job) {
				j.Op, j.Sample = agent.OpSample, &connectors.SampleQuery{Limit: connectors.MaxSample + 1}
			},
			"sample negative":   func(j *agent.Job) { j.Op, j.Sample = agent.OpSample, &connectors.SampleQuery{Limit: -1} },
			"port 3268":         func(j *agent.Job) { j.Target.Port = 3268 },
			"port 80":           func(j *agent.Job) { j.Target.Port = 80 },
			"cred path":         func(j *agent.Job) { j.Config.CredName = "../../etc/shadow" },
			"cred empty":        func(j *agent.Job) { j.Config.CredName = "" },
			"huge filter":       func(j *agent.Job) { j.Config.UserFilter = strings.Repeat("(", 3000) },
			"too many base dns": func(j *agent.Job) { j.Config.BaseDNs = make([]string, 100) },
			"no job id":         func(j *agent.Job) { j.ID = "" },
		}
		for name, mut := range bad {
			j := job(agent.OpConnect, "ldap.corp.example", 636)
			mut(&j)
			res := ex.Execute(context.Background(), j)
			if res.Error == nil || res.Error.Code != agent.CodeBadRequest {
				t.Errorf("%s: %+v", name, res)
			}
		}
		if f.built != 0 || creds.reads != 0 {
			t.Errorf("a refused job built %d probers and read %d credentials", f.built, creds.reads)
		}
	})

	t.Run("every operation runs through the matching Prober method", func(t *testing.T) {
		f := &factory{p: &stubProber{}}
		ex := &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: &memCreds{m: map[string]string{"svc": "pw"}}, New: f.New}
		for _, op := range agent.Ops {
			if res := ex.Execute(context.Background(), job(op, "ldap.corp.example", 636)); res.Error != nil {
				t.Errorf("%s: %+v", op, res.Error)
			}
		}
		if !reflect.DeepEqual(f.p.ops, connectors.ProberOps) {
			t.Errorf("ran %v", f.p.ops)
		}
	})

	t.Run("errors keep their meaning and never carry the credential", func(t *testing.T) {
		for _, tc := range []struct {
			err  error
			code string
		}{{connectors.ErrUnsupported, agent.CodeUnsupported}, {connectors.ErrRateLimited, agent.CodeRateLimited},
			{safedial.ErrBlockedAddress, agent.CodeTargetNotAllowed}, {errors.New("bind failed for pw-123"), agent.CodeFailed}} {
			f := &factory{p: &stubProber{err: tc.err}}
			ex := &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: &memCreds{m: map[string]string{"svc": "pw-123"}}, New: f.New}
			res := ex.Execute(context.Background(), job(agent.OpConnect, "ldap.corp.example", 636))
			if res.Error == nil || res.Error.Code != tc.code || strings.Contains(res.Error.Message, "pw-123") {
				t.Errorf("%v: %+v", tc.err, res.Error)
			}
			if tc.code != agent.CodeFailed && !errors.Is(res.Err(), map[string]error{agent.CodeUnsupported: connectors.ErrUnsupported,
				agent.CodeRateLimited: connectors.ErrRateLimited, agent.CodeTargetNotAllowed: connectors.ErrAgentRefused}[tc.code]) {
				t.Errorf("Result.Err() for %s: %v", tc.code, res.Err())
			}
		}
	})

	t.Run("the package cannot run commands, send raw bytes or write to a directory", func(t *testing.T) {
		banned := []string{`"os/exec"`, `exec.Command`, `syscall.Exec`, `os.StartProcess`, `go-ldap`, `NewModifyRequest`,
			`NewAddRequest`, `NewDelRequest`, `ModifyDN`, `net.Dial(`, `net.DialTimeout(`, `net.Dialer`, `http.DefaultClient`,
			`database/sql`, `"unsafe"`}
		files, err := filepath.Glob("*.go")
		if err != nil || len(files) < 8 {
			t.Fatalf("files %v %v", files, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range banned {
				// the Windows DPAPI file is the one place allowed to import unsafe
				if b == `"unsafe"` && f == "dpapi_windows.go" {
					continue
				}
				if strings.Contains(string(raw), b) {
					t.Errorf("%s contains %s", f, b)
				}
			}
		}
	})
}

func withID(j agent.Job) agent.Job { j.ID = "x"; return j }

// ---------------------------------------------------------------- enrolment

// stack is a database with two tenants, the agent service and the mTLS
// listener, as cmd/tessera wires them.
type stack struct {
	f     *storetest.Fixture
	svc   *agent.Service
	srv   *httptest.Server
	pki   *agenttest.PKI
	clock *clock
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStack(t *testing.T) *stack {
	t.Helper()
	f := storetest.TwoTenants(t)
	ck := &clock{t: storetest.Now}
	s := &stack{f: f, pki: agenttest.NewPKI(t), clock: ck}
	s.svc = &agent.Service{DB: f.DB, Hub: agent.NewHub(nil), Clock: ck.Now}
	tlsCfg, err := agent.ServerTLSConfig(s.pki.CertFile, s.pki.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	s.srv = httptest.NewUnstartedServer(s.svc.Handler(150 * time.Millisecond))
	s.srv.TLS = tlsCfg
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stack) issue(t *testing.T, tn storetest.Tenant, name string) *agent.Enrolment {
	t.Helper()
	var e *agent.Enrolment
	if err := s.f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
		e, err = s.svc.Create(c, name, "admin@"+tn.Slug, s.clock.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (s *stack) client(t *testing.T, dir string) *agent.Client {
	t.Helper()
	cert, err := agent.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := agent.NewClient(s.srv.URL, s.pki.CAPEM, cert)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var tel = agent.Telemetry{Hostname: "dc-agent-01", OS: "linux", Version: agent.Version, AllowlistHash: strings.Repeat("a", 64)}

func auditActions(t *testing.T, s *stack, tn storetest.Tenant, action string) []*store.AuditEvent {
	t.Helper()
	var out []*store.AuditEvent
	if err := s.f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) (err error) {
		out, err = c.AuditEvents(store.AuditFilter{Action: action})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEnrolment_SingleUseHashed: the code is random, shown once, stored only
// as a hash, valid for 15 minutes and for one enrolment; enrolment and
// issuing are audited without the code; the agent's key is pinned.
func TestEnrolment_SingleUseHashed(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	a, b := s.issue(t, s.f.A, "dc-agent"), s.issue(t, s.f.A, "dc-agent-2")
	if a.Code == b.Code || !strings.HasPrefix(a.Code, "tdae_") || len(a.Code) < 40 {
		t.Fatalf("codes: %q %q", a.Code, b.Code)
	}
	if a.ExpiresAt != storetest.Now.Add(agent.EnrolmentTTL) || agent.EnrolmentTTL != 15*time.Minute {
		t.Errorf("expiry %v", a.ExpiresAt)
	}
	if a.Agent.Status != store.AgentPending || a.Agent.Online {
		t.Errorf("agent: %+v", a.Agent)
	}

	// Only the hash is stored: the code does not resolve, its hash does.
	if err := s.f.DB.ReadSystem(ctx, "test", func(sx *store.SystemTx) error {
		if _, _, err := sx.LookupAgentEnrolmentByTokenHash(a.Code); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the plain code resolves: %v", err)
		}
		tid, _, err := sx.LookupAgentEnrolmentByTokenHash(agent.HashCode(a.Code))
		if err != nil || tid != s.f.A.ID {
			t.Errorf("the hash does not resolve: %v %v", tid, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	c1 := s.client(t, filepath.Join(t.TempDir(), "id"))
	resp, err := c1.Enrol(ctx, a.Code, tel)
	if err != nil || resp.AgentID != a.Agent.ID || resp.ProtocolVersion != agent.ProtocolVersion {
		t.Fatalf("enrol: %+v %v", resp, err)
	}
	// Second use of the same code, from the same or another key: refused alike.
	for i, c := range []*agent.Client{c1, s.client(t, filepath.Join(t.TempDir(), "id"))} {
		_, err := c.Enrol(ctx, a.Code, tel)
		var se *agent.StatusError
		if !errors.As(err, &se) || se.Status != http.StatusForbidden || se.Code != "invalid_code" {
			t.Errorf("second use #%d: %v", i, err)
		}
	}
	// The agent is active, its key pinned, telemetry recorded.
	var v *agent.View
	if err := s.f.DB.ReadTenant(ctx, s.f.A.ID, func(c *store.TenantTx) (err error) { v, err = s.svc.Get(c, a.Agent.ID); return err }); err != nil {
		t.Fatal(err)
	}
	if v.Status != store.AgentActive || v.Hostname != "dc-agent-01" || v.Version != agent.Version || v.EnrolledAt == nil {
		t.Errorf("view: %+v", v)
	}
	// Audit: issued and enrolled, never the code.
	for _, act := range []string{"agent.enrolment_issued", "agent.enrolled"} {
		evs := auditActions(t, s, s.f.A, act)
		if len(evs) == 0 {
			t.Errorf("no %s event", act)
		}
		for _, e := range evs {
			if strings.Contains(string(e.Detail), a.Code) || strings.Contains(string(e.Detail), b.Code) ||
				strings.Contains(string(e.Detail), agent.HashCode(a.Code)) {
				t.Errorf("%s carries the code or its hash: %s", act, e.Detail)
			}
		}
	}
	if evs := auditActions(t, s, s.f.A, "agent.enrolled"); len(evs) != 1 || evs[0].TargetID == nil || *evs[0].TargetID != a.Agent.ID {
		t.Errorf("enrolled events: %+v", evs)
	}
	// The other tenant has no such events.
	if len(auditActions(t, s, s.f.B, "agent.enrolled")) != 0 {
		t.Error("tenant B sees tenant A's enrolment")
	}

	t.Run("expired", func(t *testing.T) {
		e := s.issue(t, s.f.A, "slow-agent")
		s.clock.Advance(agent.EnrolmentTTL)
		_, err := s.client(t, filepath.Join(t.TempDir(), "id")).Enrol(ctx, e.Code, tel)
		var se *agent.StatusError
		if !errors.As(err, &se) || se.Code != "invalid_code" {
			t.Errorf("expired code: %v", err)
		}
	})
	t.Run("malformed, unknown and foreign codes", func(t *testing.T) {
		for _, code := range []string{"", "x", "tdae_", "tdae_" + strings.Repeat("A", 43), b.Code[:len(b.Code)-1] + "A",
			strings.Repeat("tdae_", 40)} {
			_, err := s.client(t, filepath.Join(t.TempDir(), "id")).Enrol(ctx, code, tel)
			var se *agent.StatusError
			if !errors.As(err, &se) || se.Status != http.StatusForbidden {
				t.Errorf("code %q: %v", code, err)
			}
		}
	})
	t.Run("revoked before enrolment", func(t *testing.T) {
		e := s.issue(t, s.f.A, "revoked-early")
		if err := s.f.DB.InTenant(ctx, s.f.A.ID, func(c *store.TenantTx) error {
			return s.svc.Revoke(c, e.Agent.ID, "admin", s.clock.Now())
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.client(t, filepath.Join(t.TempDir(), "id")).Enrol(ctx, e.Code, tel); err == nil {
			t.Error("a revoked agent's code enrolled")
		}
	})
	t.Run("one winner among concurrent enrolments", func(t *testing.T) {
		e := s.issue(t, s.f.A, "racing-agent")
		const n = 6
		clients := make([]*agent.Client, n)
		for i := range clients {
			clients[i] = s.client(t, filepath.Join(t.TempDir(), "id"))
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for _, c := range clients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.Enrol(ctx, e.Code, tel); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("%d enrolments succeeded with one code", wins)
		}
	})
	t.Run("names", func(t *testing.T) {
		for _, name := range []string{"", " ", "-x", "a/b", strings.Repeat("a", 65), "x\ny"} {
			err := s.f.DB.InTenant(ctx, s.f.A.ID, func(c *store.TenantTx) error {
				_, err := s.svc.Create(c, name, "admin", s.clock.Now())
				return err
			})
			if !errors.Is(err, agent.ErrName) {
				t.Errorf("name %q: %v", name, err)
			}
		}
		err := s.f.DB.InTenant(ctx, s.f.A.ID, func(c *store.TenantTx) error {
			_, err := s.svc.Create(c, "dc-agent", "admin", s.clock.Now())
			return err
		})
		if !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("duplicate name: %v", err)
		}
	})
}

// ---------------------------------------------------------------- mutual TLS

// TestAgent_MutualTLS: the agent pins Tessera's CA, Tessera pins the agent's
// key; a client with no certificate, an unenrolled key or a revoked agent is
// refused, and an agent that pins another CA does not talk to this server.
func TestAgent_MutualTLS(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	e := s.issue(t, s.f.A, "dc-agent")
	dir := filepath.Join(t.TempDir(), "id")
	c := s.client(t, dir)
	if _, err := c.Enrol(ctx, e.Code, tel); err != nil {
		t.Fatal(err)
	}
	// The pinned agent can heartbeat and poll.
	if err := c.Heartbeat(ctx, tel); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if j, err := c.Poll(ctx); err != nil || j != nil {
		t.Fatalf("poll: %v %v", j, err)
	}

	t.Run("no client certificate", func(t *testing.T) {
		cert := tls.Certificate{}
		nc, err := agent.NewClient(s.srv.URL, s.pki.CAPEM, cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := nc.Heartbeat(ctx, tel); err == nil {
			t.Error("a request without a client certificate was served")
		}
	})
	t.Run("a well-formed key that was never enrolled", func(t *testing.T) {
		other := s.client(t, filepath.Join(t.TempDir(), "id"))
		for name, fn := range map[string]func() error{
			"heartbeat": func() error { return other.Heartbeat(ctx, tel) },
			"poll":      func() error { _, err := other.Poll(ctx); return err },
			"result":    func() error { return other.SendResult(ctx, agent.Result{JobID: "x", Payload: json.RawMessage(`{}`)}) },
		} {
			if err := fn(); !agent.IsUnauthorized(err) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("the agent pins Tessera's CA", func(t *testing.T) {
		cert, err := agent.LoadOrCreateIdentity(dir)
		if err != nil {
			t.Fatal(err)
		}
		wrong, err := agent.NewClient(s.srv.URL, agenttest.NewPKI(t).CAPEM, cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := wrong.Heartbeat(ctx, tel); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("an agent pinning another CA connected: %v", err)
		}
		// plain http and junk CA files are refused up front
		if _, err := agent.NewClient("http://tessera.example", s.pki.CAPEM, cert); err == nil {
			t.Error("http URL accepted")
		}
		if _, err := agent.NewClient("https://tessera.example/x?y", s.pki.CAPEM, cert); err == nil {
			t.Error("URL with a path accepted")
		}
		if _, err := agent.NewClient(s.srv.URL, []byte("not a pem"), cert); err == nil {
			t.Error("junk CA accepted")
		}
	})
	t.Run("only the agent protocol is served", func(t *testing.T) {
		cert, _ := agent.LoadOrCreateIdentity(dir)
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert},
			RootCAs: mustPool(t, s.pki.CAPEM)}}}
		for _, p := range []string{"/", "/api/health", "/api/connections", "/agent/v1/exec", "/agent/v1/poll/../enrol"} {
			for _, m := range []string{http.MethodGet, http.MethodPost} {
				req, _ := http.NewRequest(m, s.srv.URL+p, strings.NewReader("{}"))
				resp, err := hc.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					t.Errorf("%s %s answered 200", m, p)
				}
			}
		}
		req, _ := http.NewRequest(http.MethodGet, s.srv.URL+agent.PathPoll, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET poll: %d", resp.StatusCode)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		if err := s.f.DB.InTenant(ctx, s.f.A.ID, func(cx *store.TenantTx) error {
			return s.svc.Revoke(cx, e.Agent.ID, "admin", s.clock.Now())
		}); err != nil {
			t.Fatal(err)
		}
		if err := c.Heartbeat(ctx, tel); !agent.IsUnauthorized(err) {
			t.Errorf("revoked agent heartbeat: %v", err)
		}
		if _, err := c.Poll(ctx); !agent.IsUnauthorized(err) {
			t.Errorf("revoked agent poll: %v", err)
		}
		if evs := auditActions(t, s, s.f.A, "agent.revoked"); len(evs) != 1 {
			t.Errorf("revoked events: %d", len(evs))
		}
	})
}

func mustPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificate in the PEM")
	}
	return p
}

func pemOf(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }

// TestAgent_StrictJobDecoding: a job carrying a field the agent does not know
// is refused by the client, so Tessera cannot smuggle a new capability in.
func TestAgent_StrictJobDecoding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"1","op":"connect","target":{"host":"h","port":636},"config":{"bind_dn":"x","cred_name":"svc"},`+
			`"deadline":"2026-10-08T12:00:00Z","command":"rm -rf /"}`)
	}))
	defer srv.Close()
	cert, err := agent.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := agent.NewClient(srv.URL, pemOf(srv.Certificate().Raw), cert)
	if err != nil {
		t.Fatal(err)
	}
	if j, err := c.Poll(context.Background()); err == nil || j != nil {
		t.Errorf("a job with an unknown field was accepted: %+v %v", j, err)
	}
}

// ---------------------------------------------------------------- the whole path

// TestAgent_EndToEnd: an enrolled agent running the Runner answers typed jobs
// that Tessera sends through the Hub, with the executor's allowlist in
// between; results come back typed. A job for another tenant's agent id is
// never delivered, and a result for someone else's job is refused.
func TestAgent_EndToEnd(t *testing.T) {
	s := newStack(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := s.issue(t, s.f.A, "dc-agent")
	c := s.client(t, filepath.Join(t.TempDir(), "id"))
	if _, err := c.Enrol(ctx, e.Code, tel); err != nil {
		t.Fatal(err)
	}
	f := &factory{p: &stubProber{}}
	creds := &memCreds{m: map[string]string{"svc": "pw"}}
	r := &agent.Runner{Client: c, Telemetry: tel, HeartbeatEvery: time.Hour,
		Exec: &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds, New: f.New}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for !s.svc.Hub.Online(s.f.A.ID, e.Agent.ID) {
		if time.Now().After(deadline) {
			t.Fatal("the agent never started polling")
		}
		time.Sleep(10 * time.Millisecond)
	}
	prober, err := agent.NewRemoteProber(s.svc, s.f.A.ID, e.Agent.ID, agent.Target{Host: "ldap.corp.example", Port: 636},
		agent.ProbeConfig{BindDN: "uid=svc,dc=corp,dc=example", CredName: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	ci, err := prober.Connect(ctx)
	if err != nil || !ci.Reachable || ci.TLSVersion != "1.3" || ci.Issuer != "Lab CA" {
		t.Errorf("Connect: %+v %v", ci, err)
	}
	if ok, err := prober.ObjectExists(ctx, "ou=people,dc=corp,dc=example"); err != nil || !ok {
		t.Errorf("ObjectExists: %v %v", ok, err)
	}
	if ok, err := prober.ObjectExists(ctx, "ou=nope"); err != nil || ok {
		t.Errorf("ObjectExists(nope): %v %v", ok, err)
	}
	if st, err := prober.Sample(ctx, connectors.SampleQuery{Op: "search", Limit: 7}); err != nil || st.Objects != 7 || st.AttrFill["mail"] != 3 {
		t.Errorf("Sample: %+v %v", st, err)
	}
	if tm, err := prober.Time(ctx); err != nil || !tm.Equal(stubNow) {
		t.Errorf("Time: %v %v", tm, err)
	}
	if _, err := prober.EffectiveRights(ctx, "x"); err != nil {
		t.Errorf("EffectiveRights: %v", err)
	}

	// A target that is not on the agent's allowlist: the agent refuses it, and
	// the answer maps to ErrAgentRefused.
	off, _ := agent.NewRemoteProber(s.svc, s.f.A.ID, e.Agent.ID, agent.Target{Host: "hr-db.corp.example", Port: 636},
		agent.ProbeConfig{BindDN: "uid=svc", CredName: "svc"})
	if _, err := off.Connect(ctx); !errors.Is(err, connectors.ErrAgentRefused) {
		t.Errorf("non-allowlisted target: %v", err)
	}
	// An agent id of another tenant is offline, whoever asks.
	foreign, _ := agent.NewRemoteProber(s.svc, s.f.B.ID, e.Agent.ID, agent.Target{Host: "ldap.corp.example", Port: 636},
		agent.ProbeConfig{BindDN: "uid=svc", CredName: "svc"})
	if _, err := foreign.Connect(ctx); !errors.Is(err, agent.ErrOffline) || !errors.Is(err, connectors.ErrAgentUnavailable) {
		t.Errorf("another tenant's use of the agent id: %v", err)
	}

	// Revoking fails what is pending and stops the agent.
	if err := s.f.DB.InTenant(ctx, s.f.A.ID, func(cx *store.TenantTx) error {
		return s.svc.Revoke(cx, e.Agent.ID, "admin", s.clock.Now())
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrAgentRefused) {
			t.Errorf("Run ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the revoked agent kept running")
	}
	if _, err := prober.Connect(ctx); err == nil {
		t.Error("a revoked agent answered")
	}
}

// ---------------------------------------------------------------- hub

func TestHub(t *testing.T) {
	h := agent.NewHub(nil)
	a, b := storetest.AID, storetest.BID
	ctx := context.Background()
	j := job(agent.OpConnect, "ldap.corp.example", 636)

	if _, err := h.Do(ctx, a, "ag1", j); !errors.Is(err, agent.ErrOffline) {
		t.Fatalf("offline: %v", err)
	}
	// ag1 polls; a job for it is delivered to it only.
	got := make(chan *agent.Job, 1)
	go func() { jb, _ := h.Poll(ctx, a, "ag1", 3*time.Second); got <- jb }()
	deadline := time.Now().Add(2 * time.Second)
	for !h.Online(a, "ag1") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// the same agent id under another tenant is a different agent
	if h.Online(b, "ag1") {
		t.Fatal("another tenant's agent id is online")
	}
	res := make(chan agent.Result, 1)
	go func() {
		r, err := h.Do(ctx, a, "ag1", j)
		if err != nil {
			t.Errorf("Do: %v", err)
		}
		res <- r
	}()
	var jb *agent.Job
	select {
	case jb = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("no job delivered")
	}
	if jb == nil || jb.Op != agent.OpConnect || jb.ID == "" || jb.ID == "job-1" {
		t.Fatalf("job: %+v", jb)
	}
	// a result from another agent or another tenant is refused; the right one is taken
	for _, w := range []struct {
		t  tenancy.ID
		ag string
	}{{a, "ag2"}, {b, "ag1"}} {
		if err := h.Complete(w.t, w.ag, agent.Result{JobID: jb.ID}); !errors.Is(err, agent.ErrUnknownJob) {
			t.Errorf("foreign result accepted: %v", err)
		}
	}
	if err := h.Complete(a, "ag1", agent.Result{JobID: "nope"}); !errors.Is(err, agent.ErrUnknownJob) {
		t.Errorf("unknown job: %v", err)
	}
	if err := h.Complete(a, "ag1", agent.Result{JobID: jb.ID, Payload: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if r := <-res; r.JobID != jb.ID {
		t.Errorf("result: %+v", r)
	}
	// a second result for the same job is refused (it is no longer pending)
	if err := h.Complete(a, "ag1", agent.Result{JobID: jb.ID}); !errors.Is(err, agent.ErrUnknownJob) {
		t.Errorf("duplicate result: %v", err)
	}
	// an invalid job never reaches the queue
	bad := j
	bad.Target.Port = 22
	if _, err := h.Do(ctx, a, "ag1", bad); err == nil || errors.Is(err, agent.ErrOffline) {
		t.Errorf("invalid job: %v", err)
	}
	// revocation fails a pending job and bars the agent
	pend := make(chan error, 1)
	go func() { _, err := h.Do(ctx, a, "ag1", j); pend <- err }()
	time.Sleep(50 * time.Millisecond)
	h.Revoke(a, "ag1")
	select {
	case err := <-pend:
		if !errors.Is(err, agent.ErrRevoked) && !errors.Is(err, agent.ErrOffline) {
			t.Errorf("pending job after revoke: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending job survived revocation")
	}
	if _, err := h.Poll(ctx, a, "ag1", time.Millisecond); !errors.Is(err, agent.ErrRevoked) {
		t.Errorf("poll after revoke: %v", err)
	}
	if h.Online(a, "ag1") {
		t.Error("revoked agent online")
	}
}

// ---------------------------------------------------------------- credential store, config

func TestFileStore(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "creds")
	st, err := agent.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", fi.Mode().Perm())
	}
	if err := st.Set("svc-ldap", "s3cret"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "svc-ldap.cred"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}
	if v, err := st.Get("svc-ldap"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
	if err := st.Set("svc-ldap", "rotated"); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.Get("svc-ldap"); v != "rotated" {
		t.Errorf("replace: %q", v)
	}
	if _, err := st.Get("absent"); !errors.Is(err, agent.ErrNoCredential) {
		t.Errorf("absent: %v", err)
	}
	if names, _ := st.List(); !reflect.DeepEqual(names, []string{"svc-ldap"}) {
		t.Errorf("list: %v", names)
	}
	// names are tokens, never paths
	for _, n := range []string{"", "..", ".", "a/b", `a\b`, "../x", "x y", strings.Repeat("a", 65), "a\x00b"} {
		if err := st.Set(n, "x"); err == nil {
			t.Errorf("Set(%q) accepted", n)
		}
		if _, err := st.Get(n); err == nil {
			t.Errorf("Get(%q) found something", n)
		}
	}
	if err := st.Set("empty", ""); err == nil {
		t.Error("empty secret accepted")
	}
	// loose permissions: refuse to read, and refuse to open the store
	if err := os.Chmod(filepath.Join(dir, "svc-ldap.cred"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("svc-ldap"); err == nil || errors.Is(err, agent.ErrNoCredential) {
		t.Errorf("group-readable secret read: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "svc-ldap.cred"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a symlink is not a credential
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.cred")); err == nil {
		if _, err := st.Get("link"); err == nil {
			t.Error("a symlink was read as a credential")
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.NewFileStore(dir); err == nil {
		t.Error("a world-readable credential directory was opened")
	}
	if err := st.Delete("svc-ldap"); err != nil {
		t.Error(err)
	}
	if err := st.Delete("svc-ldap"); err != nil {
		t.Errorf("delete twice: %v", err)
	}
}

func TestIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")
	c1, err := agent.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := agent.LoadOrCreateIdentity(dir)
	if err != nil || string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Errorf("the identity changed between loads: %v", err)
	}
	if os.PathSeparator != '\\' {
		if fi, err := os.Stat(filepath.Join(dir, "client.key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi, err)
		}
	}
	other, _ := agent.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "id"))
	if string(other.Certificate[0]) == string(c1.Certificate[0]) {
		t.Error("two agents share a key")
	}
}

func TestConfig(t *testing.T) {
	good := `{"server_url":"https://t.example:8443","server_ca_file":"/ca.pem","state_dir":"/var/lib/a",
		"allowed_targets":["ldap.corp.example:636","10.20.0.0/24:389"]}`
	c, err := agent.ParseConfig([]byte(good))
	if err != nil || len(c.Allow()) != 2 || len(c.AllowlistHash()) != 64 {
		t.Fatalf("%v %v", c, err)
	}
	reordered := `{"server_url":"https://t.example:8443","server_ca_file":"/ca.pem","state_dir":"/var/lib/a",
		"allowed_targets":["10.20.0.0/24:389","LDAP.corp.example:636"]}`
	c2, _ := agent.ParseConfig([]byte(reordered))
	if c.AllowlistHash() != c2.AllowlistHash() {
		t.Error("the allowlist hash depends on order or case")
	}
	changed, _ := agent.ParseConfig([]byte(strings.Replace(good, "ldap.corp.example", "ldap2.corp.example", 1)))
	if changed.AllowlistHash() == c.AllowlistHash() {
		t.Error("the allowlist hash ignores the list")
	}
	for name, raw := range map[string]string{
		"unknown field":  `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":[],"extra":1}`,
		"missing url":    `{"server_ca_file":"c","state_dir":"s"}`,
		"wildcard":       `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["*.corp:636"]}`,
		"broad cidr":     `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["10.0.0.0/8:636"]}`,
		"other port":     `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["ldap.corp:3268"]}`,
		"joined entries": `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["a.corp:636,b.corp:636"]}`,
		"trailing data":  good + `{}`,
		"not json":       `allowed_targets: []`,
		"no port":        `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["ldap.corp"]}`,
		"second no port": `{"server_url":"u","server_ca_file":"c","state_dir":"s","allowed_targets":["ldap.corp:636", "x"]}`,
	} {
		if _, err := agent.ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if os.PathSeparator == '\\' {
		return
	}
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadConfig(p); err != nil {
		t.Errorf("0644 config: %v", err)
	}
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadConfig(p); err == nil {
		t.Error("a group-writable config was loaded")
	}
	if err := os.Chmod(p, 0o646); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LoadConfig(p); err == nil {
		t.Error("a world-writable config was loaded")
	}
}

// TestVersion: an agent older than MinVersion is shown as outdated.
func TestVersionOutdated(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	e := s.issue(t, s.f.A, "old-agent")
	c := s.client(t, filepath.Join(t.TempDir(), "id"))
	old := tel
	old.Version = "0.0.9"
	if _, err := c.Enrol(ctx, e.Code, old); err != nil {
		t.Fatal(err)
	}
	view := func() *agent.View {
		var v *agent.View
		_ = s.f.DB.ReadTenant(ctx, s.f.A.ID, func(cx *store.TenantTx) (err error) { v, err = s.svc.Get(cx, e.Agent.ID); return err })
		return v
	}
	if !view().Outdated {
		t.Error("0.0.9 is not outdated")
	}
	// a heartbeat with a newer version and allowlist is audited as an update
	if err := c.Heartbeat(ctx, tel); err != nil {
		t.Fatal(err)
	}
	if view().Outdated || view().Version != agent.Version {
		t.Errorf("after update: %+v", view())
	}
	if evs := auditActions(t, s, s.f.A, "agent.updated"); len(evs) != 1 {
		t.Errorf("updated events: %d", len(evs))
	}
	// an unchanged heartbeat only touches last-seen: no event
	if err := c.Heartbeat(ctx, tel); err != nil {
		t.Fatal(err)
	}
	if evs := auditActions(t, s, s.f.A, "agent.updated"); len(evs) != 1 {
		t.Errorf("an unchanged heartbeat was audited: %d", len(evs))
	}
	// protocol mismatch is refused
	badHB := agent.HeartbeatRequest{ProtocolVersion: 99, Telemetry: tel}
	if err := s.svc.Heartbeat(ctx, &agent.Principal{Tenant: s.f.A.ID, AgentID: e.Agent.ID}, badHB); !errors.Is(err, agent.ErrProtocol) {
		t.Errorf("protocol 99: %v", err)
	}
}

func TestParseRef(t *testing.T) {
	for ref, ok := range map[string]bool{
		"agent:3f2b9c1e-0000-4000-8000-000000000001/svc-ldap": true, "agent:a/b.c_d-e": true,
		"agent:/svc": false, "agent:a/": false, "agent:a/b/c": false, "agent:a/..": false, "vault:kv/x": false,
		"agent:a:b/svc": false, "agent:a/b c": false, "": false,
	} {
		if _, _, got := agent.ParseRef(ref); got != ok {
			t.Errorf("ParseRef(%q) = %t, want %t", ref, got, ok)
		}
	}
}
