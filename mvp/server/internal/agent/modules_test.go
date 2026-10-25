package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
)

// TestModules_Host: the plug-in host routes a pulled sync job to the module it
// names, refuses a module the build does not carry before the credential is
// read, and keeps the closed set of names.
func TestModules_Host(t *testing.T) {
	var asked []string
	module := func(name string) agent.Module {
		return agent.Module{Name: name, New: func(s agent.ProberSpec) (agent.Syncer, error) {
			asked = append(asked, name)
			return syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) { return pullResult, nil }), nil
		}}
	}
	builtin := func(agent.ProberSpec) (agent.Syncer, error) {
		asked = append(asked, "ldap")
		return syncerFunc(func(context.Context, agent.SyncLimits) (*agent.SyncResult, error) { return pullResult, nil }), nil
	}
	newExec := func(creds *memCreds) *agent.Executor {
		e := &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds, NewSyncer: builtin}
		if err := e.Register(module(agent.ModuleRACF)); err != nil {
			t.Fatal(err)
		}
		return e
	}
	job := func(module string) agent.PulledJob {
		spec := pullSpec
		spec.Module = module
		return agent.PulledJob{ID: "j1", Kind: agent.KindSync, ConnectionID: "c1", Attempt: 1, Spec: spec, TimeoutSecs: 60}
	}
	creds := func() *memCreds { return &memCreds{m: map[string]string{"svc": "pw"}} }

	for name, tc := range map[string]struct {
		module string
		code   string // "" is success
		asked  string
	}{
		"no module is the built-in LDAP reader": {"", "", "ldap"},
		"a registered module":                   {agent.ModuleRACF, "", agent.ModuleRACF},
		"a known module this build lacks":       {agent.ModuleIBMi, agent.CodeUnsupported, ""},
		"an unknown module name":                {"acf2x", agent.CodeBadRequest, ""},
		"a module name with a path":             {"../racf", agent.CodeBadRequest, ""},
	} {
		asked = nil
		c := creds()
		res := newExec(c).ExecuteSync(context.Background(), job(tc.module))
		got := ""
		if res.Error != nil {
			got = res.Error.Code
		}
		if got != tc.code {
			t.Errorf("%s: code %q, want %q (%+v)", name, got, tc.code, res.Error)
		}
		if tc.code != "" && c.reads != 0 {
			t.Errorf("%s: the credential was read for a refused job", name)
		}
		if tc.asked == "" && len(asked) != 0 || tc.asked != "" && (len(asked) != 1 || asked[0] != tc.asked) {
			t.Errorf("%s: built %v, want %q", name, asked, tc.asked)
		}
	}

	t.Run("an agent with no built-in reader still runs its modules", func(t *testing.T) {
		e := &agent.Executor{Allow: mustAllow(t, "ldap.corp.example:636"), Creds: creds()}
		_ = e.Register(module(agent.ModuleRACF))
		if res := e.ExecuteSync(context.Background(), job(agent.ModuleRACF)); res.Error != nil {
			t.Errorf("module: %+v", res.Error)
		}
		if res := e.ExecuteSync(context.Background(), job("")); res.Error == nil || res.Error.Code != agent.CodeUnsupported {
			t.Errorf("built-in: %+v", res.Error)
		}
	})

	t.Run("registration", func(t *testing.T) {
		e := &agent.Executor{}
		if err := e.Register(agent.Module{Name: "nope", New: builtin}); !errors.Is(err, agent.ErrBadModule) {
			t.Errorf("unknown name: %v", err)
		}
		if err := e.Register(agent.Module{Name: agent.ModuleRACF}); !errors.Is(err, agent.ErrBadModule) {
			t.Errorf("no factory: %v", err)
		}
		if err := e.Register(module(agent.ModuleIBMi)); err != nil {
			t.Fatal(err)
		}
		if err := e.Register(module(agent.ModuleIBMi)); !errors.Is(err, agent.ErrDuplicateModule) {
			t.Errorf("duplicate: %v", err)
		}
		_ = e.Register(module(agent.ModuleRACF))
		if got := e.ModuleList(); len(got) != 2 || got[0] != "ibmi" || got[1] != "racf" {
			t.Errorf("list: %v", got)
		}
	})

	t.Run("the target still has to be on the local allowlist", func(t *testing.T) {
		j := job(agent.ModuleRACF)
		j.Spec.Target.Host = "evil.example"
		res := newExec(creds()).ExecuteSync(context.Background(), j)
		if res.Error == nil || res.Error.Code != agent.CodeTargetNotAllowed {
			t.Errorf("%+v", res.Error)
		}
	})
}
