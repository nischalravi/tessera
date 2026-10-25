package ibmi_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ibmi"
)

// fakeSource is an in-process IBM i: a fixed list of profiles.
type fakeSource struct {
	profiles []ibmi.Profile
	err      error
	closed   bool
}

func (f *fakeSource) Profiles(_ context.Context, max int) ([]ibmi.Profile, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.profiles) > max {
		return nil, ibmi.ErrTooLarge
	}
	return f.profiles, nil
}
func (f *fakeSource) Close() { f.closed = true }

func profiles() []ibmi.Profile {
	return []ibmi.Profile{
		{Name: "QSECOFR", Status: "*ENABLED", UserClass: "*SECOFR", Text: "Security officer",
			SpecialAuthorities: []string{"*ALLOBJ", "*SECADM", "*JOBCTL", "*SAVSYS", "*SERVICE", "*SPLCTL", "*AUDIT", "*IOSYSCFG"}},
		{Name: "ALICE", Status: "*ENABLED", UserClass: "*USER", GroupProfile: "PAYGRP", SupplementalGroups: []string{"DEVGRP", "payg" + "rp"},
			SpecialAuthorities: []string{"*JOBCTL"}},
		{Name: "BOB", Status: "*DISABLED", UserClass: "*PGMR", GroupProfile: "*NONE"},
		{Name: "alice", Status: "*ENABLED"}, // same name in another case
		{Name: "PAYGRP", Status: "*DISABLED", UserClass: "*USER"},
	}
}

var lim = agent.SyncLimits{Accounts: 100, Groups: 100, Members: 1000}

func discover(t *testing.T, src ibmi.Source, open ibmi.Opener, l agent.SyncLimits) (*agent.SyncResult, error) {
	t.Helper()
	if open == nil {
		open = func(context.Context, agent.ProberSpec) (ibmi.Source, error) { return src, nil }
	}
	m := ibmi.Module(open)
	if m.Name != agent.ModuleIBMi {
		t.Fatalf("module name %q", m.Name)
	}
	sy, err := m.New(agent.ProberSpec{Target: agent.Target{Host: "as400.corp.example", Port: 636}})
	if err != nil {
		t.Fatal(err)
	}
	return sy.Discover(context.Background(), l)
}

func TestDiscover_ProfilesAuthoritiesAndGroups(t *testing.T) {
	src := &fakeSource{profiles: profiles()}
	res, err := discover(t, src, nil, lim)
	if err != nil {
		t.Fatal(err)
	}
	if !src.closed {
		t.Error("the source was not closed")
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("the result must pass the protocol's own validation: %v", err)
	}
	status := map[string]string{}
	for _, a := range res.Accounts {
		status[a.Username] = a.Status
	}
	if len(res.Accounts) != 4 || status["QSECOFR"] != "active" || status["BOB"] != "disabled" || status["PAYGRP"] != "disabled" {
		t.Errorf("accounts: %+v", res.Accounts)
	}
	if x := res.Accounts[0].Extra; len(x) != 2 || x[0].Target != "userClass" || x[0].Value != "*SECOFR" || x[1].Value != "Security officer" {
		t.Errorf("extra: %+v", x)
	}
	for _, a := range res.Accounts {
		for _, x := range a.Extra {
			if x.Scope != "account" || !agent.ModuleAttribute(agent.ModuleIBMi, x.Target) {
				t.Errorf("the module reports %s.%s, which the server would drop", x.Scope, x.Target)
			}
		}
	}
	groups := map[string]bool{}
	for _, g := range res.Groups {
		groups[g.ExternalID] = g.Privileged
	}
	wantPriv := map[string]bool{"authority:*ALLOBJ": true, "authority:*SECADM": true, "authority:*AUDIT": true, "authority:*IOSYSCFG": true,
		"authority:*SERVICE": true, "authority:*SAVSYS": true, "authority:*JOBCTL": true, "authority:*SPLCTL": true,
		"class:*SECOFR": true, "group:PAYGRP": false, "group:DEVGRP": false}
	if len(groups) != len(wantPriv) {
		t.Errorf("groups: %v", groups)
	}
	for id, p := range wantPriv {
		if got, ok := groups[id]; !ok || got != p {
			t.Errorf("group %s: present %v privileged %v, want %v", id, ok, got, p)
		}
	}
	has := map[string]bool{}
	for _, m := range res.Members {
		if has[m.Account+">"+m.Group] {
			t.Errorf("duplicate %v", m)
		}
		has[m.Account+">"+m.Group] = true
	}
	for _, k := range []string{"ALICE>group:PAYGRP", "ALICE>group:DEVGRP", "ALICE>authority:*JOBCTL", "QSECOFR>class:*SECOFR", "QSECOFR>authority:*ALLOBJ"} {
		if !has[k] {
			t.Errorf("missing %s", k)
		}
	}
	if has["BOB>group:*NONE"] || has["BOB>class:*PGMR"] {
		t.Error("*NONE and an ordinary class are not entitlements")
	}
}

func TestDiscover_Refusals(t *testing.T) {
	t.Run("limits", func(t *testing.T) {
		for name, l := range map[string]agent.SyncLimits{"accounts": {Accounts: 2, Groups: 100, Members: 100},
			"groups": {Accounts: 100, Groups: 2, Members: 100}, "members": {Accounts: 100, Groups: 100, Members: 2}} {
			if res, err := discover(t, &fakeSource{profiles: profiles()}, nil, l); !errors.Is(err, ibmi.ErrTooLarge) || res != nil {
				t.Errorf("%s: %v %v", name, res, err)
			}
		}
	})
	t.Run("a profile name that is not a profile name", func(t *testing.T) {
		for _, bad := range []ibmi.Profile{{Name: ""}, {Name: "TOOLONGNAME1"}, {Name: "A B"}, {Name: "A;DROP"},
			{Name: "OK", GroupProfile: "bad group"}, {Name: "OK", SpecialAuthorities: []string{"ALLOBJ"}}, {Name: "OK", SpecialAuthorities: []string{"*A B"}}} {
			if _, err := discover(t, &fakeSource{profiles: []ibmi.Profile{bad}}, nil, lim); !errors.Is(err, ibmi.ErrBadProfile) {
				t.Errorf("%+v: %v", bad, err)
			}
		}
	})
	t.Run("a transport error is replaced by fixed text", func(t *testing.T) {
		src := &fakeSource{err: errors.New("SQL0204 user QSECOFR password hunter2 rejected")}
		_, err := discover(t, src, nil, lim)
		if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "QSECOFR") {
			t.Errorf("%v", err)
		}
		if _, err := discover(t, &fakeSource{err: context.DeadlineExceeded}, nil, lim); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("deadline: %v", err)
		}
	})
	t.Run("no driver", func(t *testing.T) {
		if _, err := ibmi.Module(nil).New(agent.ProberSpec{}); !errors.Is(err, ibmi.ErrNoDriver) {
			t.Errorf("%v", err)
		}
	})
}

// TestNoTransport: this build answers "unsupported" for IBM i, with the code
// the agent protocol uses, and never dials.
func TestNoTransport(t *testing.T) {
	_, err := discover(t, nil, ibmi.NoTransport, lim)
	if !errors.Is(err, ibmi.ErrNoTransport) || !errors.Is(err, connectors.ErrUnsupported) {
		t.Fatalf("%v", err)
	}
	e := &agent.Executor{Allow: nil, Creds: nil}
	if err := e.Register(ibmi.Module(ibmi.NoTransport)); err != nil {
		t.Fatal(err)
	}
}

// TestMap_GroupProfileAuthoritiesMakeTheGroupPrivileged: IBM i gives a member
// the special authorities of its group profile, so a group profile holding
// *ALLOBJ (or the *SECOFR class) is a privileged group; one with none is not.
func TestMap_GroupProfileAuthoritiesMakeTheGroupPrivileged(t *testing.T) {
	res, err := ibmi.Map([]ibmi.Profile{
		{Name: "ALICE", GroupProfile: "ADMGRP", SupplementalGroups: []string{"OFFGRP", "USRGRP"}},
		{Name: "ADMGRP", SpecialAuthorities: []string{"*ALLOBJ"}},
		{Name: "OFFGRP", UserClass: "*SECOFR"},
		{Name: "USRGRP", UserClass: "*USER"},
	}, lim)
	if err != nil {
		t.Fatal(err)
	}
	priv := map[string]bool{}
	for _, g := range res.Groups {
		priv[g.ExternalID] = g.Privileged
	}
	if !priv["group:ADMGRP"] || !priv["group:OFFGRP"] || priv["group:USRGRP"] {
		t.Errorf("groups: %v", priv)
	}
}

// TestMap_ProfileNames: a period is not valid in a user profile name, nor a
// leading digit or underscore.
func TestMap_ProfileNames(t *testing.T) {
	for _, n := range []string{"A.B", "1ABC", "_ABC", "TOOLONGNAME"} {
		if _, err := ibmi.Map([]ibmi.Profile{{Name: n}}, lim); !errors.Is(err, ibmi.ErrBadProfile) {
			t.Errorf("%q: %v", n, err)
		}
		if _, err := ibmi.Map([]ibmi.Profile{{Name: "OK", GroupProfile: n}}, lim); !errors.Is(err, ibmi.ErrBadProfile) {
			t.Errorf("group %q: %v", n, err)
		}
	}
	if _, err := ibmi.Map([]ibmi.Profile{{Name: "#T$@_9"}}, lim); err != nil {
		t.Errorf("valid name: %v", err)
	}
}
