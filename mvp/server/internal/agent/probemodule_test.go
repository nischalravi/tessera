package agent_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestProbeJob_Module: a probe job that names a module runs that module's
// prober; a job without one runs the LDAP prober exactly as before; a module
// the build lacks, or an unknown name, fails closed with fixed text before the
// credential is read or anything is dialed.
func TestProbeJob_Module(t *testing.T) {
	const allow = "ldap.corp.example:636"
	newExec := func() (*agent.Executor, *memCreds, *factory, *factory) {
		creds := &memCreds{m: map[string]string{"svc": "pw"}}
		ldap, mod := &factory{p: &stubProber{}}, &factory{p: &stubProber{}}
		ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: creds, New: ldap.New}
		if err := ex.Register(agent.Module{Name: agent.ModuleIBMi, NewProber: mod.New,
			New: func(agent.ProberSpec) (agent.Syncer, error) { return nil, nil }}); err != nil {
			t.Fatal(err)
		}
		return ex, creds, ldap, mod
	}
	run := func(ex *agent.Executor, module string) agent.Result {
		j := job(agent.OpConnect, "ldap.corp.example", 636)
		j.Module = module
		return ex.Execute(context.Background(), j)
	}

	t.Run("module job runs the module prober only", func(t *testing.T) {
		ex, _, ldap, mod := newExec()
		if res := run(ex, agent.ModuleIBMi); res.Error != nil {
			t.Fatalf("%+v", res.Error)
		}
		if mod.built != 1 || ldap.built != 0 || mod.last.Dialer == nil || mod.last.Password != "pw" {
			t.Errorf("module built %d, ldap built %d, spec %+v", mod.built, ldap.built, mod.last)
		}
	})
	t.Run("a job without a module still runs LDAP", func(t *testing.T) {
		ex, _, ldap, mod := newExec()
		if res := run(ex, ""); res.Error != nil {
			t.Fatalf("%+v", res.Error)
		}
		if ldap.built != 1 || mod.built != 0 {
			t.Errorf("ldap built %d, module built %d", ldap.built, mod.built)
		}
	})
	t.Run("an old-format job (no module key) decodes and runs LDAP", func(t *testing.T) {
		const old = `{"id":"j1","op":"connect","target":{"host":"ldap.corp.example","port":636},"config":{"bind_dn":"cn=svc","cred_name":"svc"},"deadline":"0001-01-01T00:00:00Z"}`
		var j agent.Job
		if err := json.Unmarshal([]byte(old), &j); err != nil || j.Module != "" {
			t.Fatalf("%v module %q", err, j.Module)
		}
		ex, _, ldap, mod := newExec()
		if res := ex.Execute(context.Background(), j); res.Error != nil || ldap.built != 1 || mod.built != 0 {
			t.Errorf("%+v ldap %d module %d", res.Error, ldap.built, mod.built)
		}
	})
	t.Run("the wire form omits an empty module", func(t *testing.T) {
		b, _ := json.Marshal(job(agent.OpConnect, "ldap.corp.example", 636))
		if strings.Contains(string(b), "module") {
			t.Errorf("job without a module carries one: %s", b)
		}
		j := job(agent.OpConnect, "ldap.corp.example", 636)
		j.Module = agent.ModuleIBMi
		if b, _ = json.Marshal(j); !strings.Contains(string(b), `"module":"ibmi"`) {
			t.Errorf("module missing: %s", b)
		}
	})
	t.Run("fail closed", func(t *testing.T) {
		for name, tc := range map[string]struct{ module, code string }{
			"racf is known but has no prober here": {agent.ModuleRACF, agent.CodeUnsupported},
			"unknown name":                         {"acf2x", agent.CodeBadRequest},
			"path":                                 {"../ibmi", agent.CodeBadRequest},
		} {
			ex, creds, ldap, mod := newExec()
			res := run(ex, tc.module)
			if res.Error == nil || res.Error.Code != tc.code {
				t.Errorf("%s: %+v", name, res.Error)
				continue
			}
			if ldap.built != 0 || mod.built != 0 || creds.reads != 0 {
				t.Errorf("%s: work done: ldap %d module %d reads %d", name, ldap.built, mod.built, creds.reads)
			}
			if tc.code == agent.CodeUnsupported && res.Error.Message != "this agent build cannot run that module" {
				t.Errorf("%s: message %q", name, res.Error.Message)
			}
		}
	})
	t.Run("a module without a prober is unsupported", func(t *testing.T) {
		ex := &agent.Executor{Allow: mustAllow(t, allow), Creds: &memCreds{m: map[string]string{"svc": "pw"}}}
		_ = ex.Register(agent.Module{Name: agent.ModuleRACF, New: func(agent.ProberSpec) (agent.Syncer, error) { return nil, nil }})
		if res := run(ex, agent.ModuleRACF); res.Error == nil || res.Error.Code != agent.CodeUnsupported {
			t.Errorf("%+v", res.Error)
		}
	})
	t.Run("local allowlist still applies to a module job", func(t *testing.T) {
		ex, creds, _, mod := newExec()
		j := job(agent.OpConnect, "other.corp.example", 636)
		j.Module = agent.ModuleIBMi
		if res := ex.Execute(context.Background(), j); res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed || mod.built != 0 || creds.reads != 0 {
			t.Errorf("%+v", res.Error)
		}
	})
}

var _ connectors.Prober = (*stubProber)(nil)

type recDispatcher struct{ jobs []agent.Job }

func (r *recDispatcher) Do(_ context.Context, _ tenancy.ID, _ string, j agent.Job) (agent.Result, error) {
	r.jobs = append(r.jobs, j)
	b, _ := json.Marshal(connectors.ConnInfo{Reachable: true})
	return agent.Result{JobID: j.ID, Payload: b}, nil
}

// TestRemoteProber_Module: the server-side prober stamps its module on every
// job it builds; a prober for LDAP stamps none, so its jobs are unchanged.
func TestRemoteProber_Module(t *testing.T) {
	for module, want := range map[string]string{"": "", agent.ModuleIBMi: "ibmi"} {
		d := &recDispatcher{}
		p, err := agent.NewRemoteModuleProber(d, tenancy.New(), "a1", module, agent.Target{Host: "h.example", Port: 8076}, agent.ProbeConfig{BindDN: "X", CredName: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Connect(context.Background()); err != nil || len(d.jobs) != 1 || d.jobs[0].Module != want {
			t.Errorf("module %q: %v %+v", module, err, d.jobs)
		}
	}
	if _, err := agent.NewRemoteModuleProber(&recDispatcher{}, tenancy.New(), "a1", "nope", agent.Target{}, agent.ProbeConfig{CredName: "svc"}); err == nil {
		t.Error("an unknown module was accepted")
	}
}
