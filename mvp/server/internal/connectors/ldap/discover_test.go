package ldap

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestDiscover (issue #302): the typed listing a remote agent returns for a
// sync: people, groups and memberships, read-only, bounded.
func TestDiscover(t *testing.T) {
	e := newEnv(t, lldapLab)
	ls, err := e.p.Discover(context.Background(), 100, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range ls.Accounts {
		names = append(names, a.Username)
		if a.Username == "alice" && (a.Email != "alice@tessera.test" || a.Disabled || a.ExternalID != "uid=alice,ou=people,dc=tessera,dc=test") {
			t.Errorf("alice = %+v", a)
		}
	}
	slices.Sort(names)
	if want := []string{"admin", "alice", "bob", "carol", "svc-tessera"}; !slices.Equal(names, want) {
		t.Errorf("accounts = %v, want %v", names, want)
	}
	var groups []string
	for _, g := range ls.Groups {
		groups = append(groups, g.Name)
	}
	slices.Sort(groups)
	for _, g := range []string{"devs", "ops"} {
		if !slices.Contains(groups, g) {
			t.Errorf("groups = %v, missing %s", groups, g)
		}
	}
	// devs = alice, bob; ops = bob, carol; each pair once although the group
	// lists it as member and uniqueMember
	pairs := map[[2]string]int{}
	for _, m := range ls.Members {
		pairs[[2]string{m.Account, m.Group}]++
	}
	for _, want := range [][2]string{
		{"uid=alice,ou=people,dc=tessera,dc=test", "cn=devs,ou=groups,dc=tessera,dc=test"},
		{"uid=bob,ou=people,dc=tessera,dc=test", "cn=devs,ou=groups,dc=tessera,dc=test"},
		{"uid=bob,ou=people,dc=tessera,dc=test", "cn=ops,ou=groups,dc=tessera,dc=test"},
		{"uid=carol,ou=people,dc=tessera,dc=test", "cn=ops,ou=groups,dc=tessera,dc=test"},
	} {
		if pairs[want] != 1 {
			t.Errorf("membership %v seen %d times", want, pairs[want])
		}
	}
	if ops, writes := e.srv.snapshot(); len(writes) != 0 {
		t.Errorf("Discover sent write operations: %v (all: %v)", writes, ops)
	}
}

// TestDiscoverBounds: a directory larger than the limits is an error, never a
// partial listing, and a missing base DN is refused.
func TestDiscoverBounds(t *testing.T) {
	e := newEnv(t, lldapLab)
	for name, lim := range map[string][3]int{"accounts": {2, 100, 100}, "groups": {100, 1, 100}, "members": {100, 100, 2}} {
		if ls, err := e.p.Discover(context.Background(), lim[0], lim[1], lim[2]); !errors.Is(err, ErrTooLarge) || ls != nil {
			t.Errorf("limit on %s: %v %v", name, ls, err)
		}
	}
	e2 := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.BaseDNs = nil })
	if _, err := e2.p.Discover(context.Background(), 10, 10, 10); err == nil {
		t.Error("a Discover without a base DN was accepted")
	}
	e3 := newEnv(t, lldapLab, func(_ *fakeDir, c *Config) { c.UserFilter = "(((" })
	if _, err := e3.p.Discover(context.Background(), 10, 10, 10); err == nil {
		t.Error("a bad user filter was accepted")
	}
	e4 := newEnv(t, lldapLab, withBind("uid=svc-tessera,ou=people,dc=tessera,dc=test", "wrong"))
	if _, err := e4.p.Discover(context.Background(), 10, 10, 10); err == nil {
		t.Error("a refused bind listed the directory")
	}
}
