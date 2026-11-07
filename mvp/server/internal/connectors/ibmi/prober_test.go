package ibmi_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ibmi"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

func proberFor(t *testing.T, f *fakeMapepire, s agent.ProberSpec) connectors.Prober {
	t.Helper()
	f.start()
	p, err := ibmi.NewProber(ibmi.OpenMapepire)(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProber_Operations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("connect reports the handshake", func(t *testing.T) {
		f := newFake(t)
		ci, err := proberFor(t, f, f.spec(t)).Connect(ctx)
		if err != nil || !ci.Reachable || !ci.ChainValid || !ci.HostnameMatch || ci.TLSVersion == "" || ci.NotAfter.IsZero() {
			t.Fatalf("%+v %v", ci, err)
		}
		// Connect sends nothing: the fake saw no request.
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.reqs) != 0 {
			t.Errorf("connect sent %v", f.reqs)
		}
	})
	t.Run("connect to an untrusted certificate is a failed chain, not an error", func(t *testing.T) {
		f := newFake(t)
		s := f.spec(t)
		d, _ := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: mustAllow(t, f.addr)})
		s.Dialer, s.RootCAs = d, nil
		ci, err := proberFor(t, f, s).Connect(ctx)
		if err != nil || !ci.Reachable || ci.ChainValid {
			t.Fatalf("%+v %v", ci, err)
		}
	})
	t.Run("connect to a closed port", func(t *testing.T) {
		f := newFake(t)
		s := f.spec(t)
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		_ = ln.Close()
		s.Target.Port = atoi(port)
		d, _ := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: mustAllow(t, "127.0.0.1:"+port), RootCAs: f.pool})
		s.Dialer = d
		if _, err := proberFor(t, f, s).Connect(ctx); !errors.Is(err, ibmi.ErrConnect) {
			t.Errorf("%v", err)
		}
	})
	t.Run("connect to an address not on the allowlist", func(t *testing.T) {
		f := newFake(t)
		s := f.spec(t)
		d, _ := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, RootCAs: f.pool})
		s.Dialer = d
		if _, err := proberFor(t, f, s).Connect(ctx); !errors.Is(err, ibmi.ErrRefused) {
			t.Errorf("%v", err)
		}
	})
	t.Run("authenticate", func(t *testing.T) {
		f := newFake(t)
		a, err := proberFor(t, f, f.spec(t)).Authenticate(ctx)
		if err != nil || !a.OK || a.Identity != "TESSERA" || a.Mode == "" {
			t.Fatalf("%+v %v", a, err)
		}
	})
	t.Run("a refused sign-in is an answer", func(t *testing.T) {
		f := newFake(t)
		s := f.spec(t)
		s.Password = "nope"
		a, err := proberFor(t, f, s).Authenticate(ctx)
		if err != nil || a.OK {
			t.Fatalf("%+v %v", a, err)
		}
	})
	t.Run("sample reads USER_INFO through the fixed read-only query", func(t *testing.T) {
		f := newFake(t)
		st, err := proberFor(t, f, f.spec(t)).Sample(ctx, connectors.SampleQuery{Op: "search", Limit: 50})
		if err != nil || st.Objects != 5 || !st.Available {
			t.Fatalf("%+v %v", st, err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		sql, _ := f.reqs[1]["sql"].(string)
		if f.reqs[0]["props"] != "access=read only" || !strings.Contains(sql, "FROM QSYS2.USER_INFO") {
			t.Errorf("requests %v", f.reqs)
		}
	})
	t.Run("sample is capped by the query limit", func(t *testing.T) {
		f := newFake(t)
		st, err := proberFor(t, f, f.spec(t)).Sample(ctx, connectors.SampleQuery{Op: "search", Limit: 2})
		if err != nil || st.Objects != 2 {
			t.Fatalf("%+v %v", st, err)
		}
	})
	t.Run("an unsupported sample, and the other operations", func(t *testing.T) {
		f := newFake(t)
		p := proberFor(t, f, f.spec(t))
		if _, err := p.Sample(ctx, connectors.SampleQuery{Op: "classes"}); !errors.Is(err, connectors.ErrUnsupported) {
			t.Errorf("sample classes: %v", err)
		}
		_, e1 := p.RootInfo(ctx)
		_, e2 := p.ObjectExists(ctx, "x")
		_, e3 := p.EffectiveRights(ctx, "x")
		_, e4 := p.ChangeFeed(ctx)
		_, e5 := p.RateLimits(ctx)
		_, e6 := p.Time(ctx)
		for i, e := range []error{e1, e2, e3, e4, e5, e6} {
			if !errors.Is(e, connectors.ErrUnsupported) {
				t.Errorf("op %d: %v", i, e)
			}
		}
	})
	t.Run("errors keep fixed text", func(t *testing.T) {
		f := newFake(t)
		f.reply["sql"] = func(r map[string]any) []byte { return text(`{"id":"zzz","success":true,"is_done":true}`) }
		_, err := proberFor(t, f, f.spec(t)).Sample(ctx, connectors.SampleQuery{Op: "search"})
		if !errors.Is(err, ibmi.ErrProtocol) || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%v", err)
		}
	})
	t.Run("no transport", func(t *testing.T) {
		if _, err := ibmi.NewProber(nil)(agent.ProberSpec{}); !errors.Is(err, ibmi.ErrNoDriver) {
			t.Errorf("%v", err)
		}
	})
}

// TestProber_ThroughExecutor: a probe job naming the ibmi module runs the live
// Mapepire prober inside the agent's Executor, with the agent's own allowlist,
// credential store and dialer, for each operation the readiness checks use.
func TestProber_ThroughExecutor(t *testing.T) {
	f := newFake(t)
	f.start()
	host, port, _ := net.SplitHostPort(f.addr)
	ex := &agent.Executor{Allow: mustAllow(t, f.addr), Creds: credMap{"svc": "s3cret"}, New: func(agent.ProberSpec) (connectors.Prober, error) {
		return nil, errors.New("the LDAP prober must not run an ibmi job")
	}}
	if err := ex.Register(ibmi.Module(ibmi.OpenMapepire)); err != nil {
		t.Fatal(err)
	}
	job := func(op agent.Op, module string) agent.Job {
		j := agent.Job{ID: "j1", Op: op, Module: module, Target: agent.Target{Host: host, Port: atoi(port)},
			Config: agent.ProbeConfig{BindDN: "TESSERA", CredName: "svc", CABundle: f.pem}}
		if op == agent.OpSample {
			j.Sample = &connectors.SampleQuery{Op: "search", Limit: 50}
		}
		return j
	}
	for _, op := range []agent.Op{agent.OpConnect, agent.OpAuthenticate, agent.OpSample} {
		if res := ex.Execute(context.Background(), job(op, agent.ModuleIBMi)); res.Error != nil || len(res.Payload) == 0 {
			t.Errorf("%s: %+v", op, res.Error)
		}
	}
	// Without a module the job is an LDAP job and gets the LDAP factory.
	if res := ex.Execute(context.Background(), job(agent.OpConnect, "")); res.Error == nil || !strings.Contains(res.Error.Message, "LDAP prober") {
		t.Errorf("no module: %+v", res.Error)
	}
	// An operation IBM i lacks is "unsupported", and the credential is not echoed.
	if res := ex.Execute(context.Background(), job(agent.OpTime, agent.ModuleIBMi)); res.Error == nil || res.Error.Code != agent.CodeUnsupported {
		t.Errorf("time: %+v", res.Error)
	}
	// A wrong password is a failed sign-in, with no credential in the result.
	bad := ex
	bad.Creds = credMap{"svc": "wrong"}
	res := bad.Execute(context.Background(), job(agent.OpAuthenticate, agent.ModuleIBMi))
	if res.Error != nil || strings.Contains(string(res.Payload), "wrong") || !strings.Contains(string(res.Payload), `"OK":false`) {
		t.Errorf("wrong password: %+v %s", res.Error, res.Payload)
	}
}

type credMap map[string]string

func (c credMap) Get(n string) (string, error) {
	if v, ok := c[n]; ok {
		return v, nil
	}
	return "", agent.ErrNoCredential
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
