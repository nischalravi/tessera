package racf_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldap"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/racf"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// fakeSDBM is an in-process stand-in for the z/OS LDAP SDBM backend: entries
// keyed by base DN, with every search recorded.
type fakeSDBM struct {
	entries  map[string][]ldap.Entry // base -> entries
	err      error
	searches []string
	closed   bool
	max      int
}

func (f *fakeSDBM) Search(_ context.Context, base string, scope ldap.Scope, filter string, attrs []string, page, max int) ([]ldap.Entry, error) {
	f.searches = append(f.searches, base+"|"+filter)
	f.max = max
	if f.err != nil {
		return nil, f.err
	}
	out := f.entries[base]
	if len(out) > max {
		return nil, ldap.ErrTooManyEntries
	}
	return out, nil
}

func (f *fakeSDBM) Close() { f.closed = true }

func ent(dn string, kv ...string) ldap.Entry {
	e := ldap.Entry{DN: dn, Attrs: map[string][]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		e.Attrs[kv[i]] = append(e.Attrs[kv[i]], kv[i+1])
	}
	return e
}

const suffix = "cn=RACFA"

func sdbm() *fakeSDBM {
	u := func(id string) string { return "racfid=" + id + ",profiletype=USER," + suffix }
	g := func(id string) string { return "racfid=" + id + ",profiletype=GROUP," + suffix }
	return &fakeSDBM{entries: map[string][]ldap.Entry{
		"profiletype=USER," + suffix: {
			ent(u("IBMUSER"), "racfid", "IBMUSER", "racfattributes", "SPECIAL", "racfattributes", "OPERATIONS", "racfattributes", "AUDITOR",
				"racfdefaultgroup", "SYS1", "racfowner", "SYS1", "racfprogrammername", "System Programmer",
				"racfconnectgroupname", "SYS1", "racfconnectgroupname", "PAYROLL", "racfemployee", "E100"),
			ent(u("ALICE"), "racfid", "ALICE", "racfdefaultgroup", "PAYROLL", "racfconnectgroupname", "PAYROLL"),
			ent(u("BOB"), "racfid", "BOB", "racfattributes", "REVOKE", "racfattributes", "OPERATIONS"),
			ent(u("alice"), "racfid", "alice"), // the same id in another case: one account
			ent("racfid=,profiletype=USER,"+suffix, "racfid", ""),
		},
		"profiletype=GROUP," + suffix: {
			ent(g("SYS1"), "racfid", "SYS1", "racfgroupuserids", "IBMUSER"),
			ent(g("PAYROLL"), "racfid", "PAYROLL", "racfgroupuserids", "ALICE", "racfgroupuserids", "BOB", "racfgroupuserids", "GHOST"),
			ent(g("EMPTY"), "racfid", "EMPTY"),
		},
	}}
}

func spec() agent.ProberSpec {
	return agent.ProberSpec{
		Target: agent.Target{Host: "zos.corp.example", Port: 636},
		Config: agent.ProbeConfig{BindDN: "racfid=TESSERA,profiletype=USER," + suffix, CredName: "racf", BaseDNs: []string{suffix},
			AttrMap: []agent.AttrMap{{LDAP: "racfEmployee", Target: "employeeNumber", Scope: "identity"}}},
		Password: "pw",
	}
}

var lim = agent.SyncLimits{Accounts: 100, Groups: 100, Members: 1000}

func discover(t *testing.T, f *fakeSDBM, s agent.ProberSpec, l agent.SyncLimits) (*agent.SyncResult, error) {
	t.Helper()
	m := racf.Module(func(context.Context, agent.ProberSpec) (racf.Searcher, error) { return f, nil })
	if m.Name != agent.ModuleRACF {
		t.Fatalf("module name %q", m.Name)
	}
	sy, err := m.New(s)
	if err != nil {
		return nil, err
	}
	return sy.Discover(context.Background(), l)
}

func TestDiscover_UsersGroupsConnectsAndAuthorities(t *testing.T) {
	f := sdbm()
	res, err := discover(t, f, spec(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if !f.closed {
		t.Error("the connection was not closed")
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("the result must pass the protocol's own validation: %v", err)
	}
	// SDBM is searched below profiletype=USER, GROUP and CONNECT, by object class, and nothing else.
	want := []string{"profiletype=USER,cn=RACFA|(objectclass=racfUser)", "profiletype=GROUP,cn=RACFA|(objectclass=racfGroup)",
		"profiletype=CONNECT,cn=RACFA|(objectclass=racfConnect)"}
	if strings.Join(f.searches, ";") != strings.Join(want, ";") {
		t.Errorf("searches %v", f.searches)
	}

	accts := map[string]agent.SyncAccount{}
	for _, a := range res.Accounts {
		accts[a.Username] = a
	}
	if len(res.Accounts) != 3 {
		t.Fatalf("accounts: %+v", res.Accounts)
	}
	if accts["IBMUSER"].Status != "active" || accts["BOB"].Status != "disabled" || accts["ALICE"].Status != "active" {
		t.Errorf("status: %+v", accts)
	}
	extra := map[string]string{}
	for _, x := range accts["IBMUSER"].Extra {
		extra[x.Scope+"."+x.Target] = x.Value
	}
	for k, v := range map[string]string{"account.racfDefaultGroup": "SYS1", "account.racfOwner": "SYS1",
		"account.racfProgrammerName": "System Programmer", "identity.employeeNumber": "E100"} {
		if extra[k] != v {
			t.Errorf("extra %s = %q, want %q (%v)", k, extra[k], v, extra)
		}
	}

	for _, a := range res.Accounts {
		for _, x := range a.Extra {
			if x.Target != "employeeNumber" && !(x.Scope == "account" && agent.ModuleAttribute(agent.ModuleRACF, x.Target)) {
				t.Errorf("the module reports %s.%s, which the server would drop", x.Scope, x.Target)
			}
		}
	}
	groups := map[string]agent.SyncGroup{}
	for _, g := range res.Groups {
		groups[g.Name] = g
	}
	for _, n := range []string{"SYS1", "PAYROLL", "EMPTY"} {
		if g, ok := groups[n]; !ok || g.Privileged {
			t.Errorf("group %s: %+v", n, g)
		}
	}
	for _, a := range []string{"SPECIAL", "OPERATIONS", "AUDITOR"} { // ROAUDIT: no holder in this fixture
		if g, ok := groups["RACF "+a+" attribute"]; !ok || !g.Privileged || g.ExternalID != "racf-attr:"+a {
			t.Errorf("authority %s: %+v", a, g)
		}
	}

	members := map[string]bool{}
	for _, m := range res.Members {
		k := m.Account + " -> " + m.Group
		if members[k] {
			t.Errorf("duplicate membership %s", k)
		}
		members[k] = true
	}
	u := func(id string) string { return "racfid=" + id + ",profiletype=USER," + suffix }
	g := func(id string) string { return "racfid=" + id + ",profiletype=GROUP," + suffix }
	for _, k := range []string{
		u("IBMUSER") + " -> " + g("SYS1"),      // named by the user and by the group: once
		u("IBMUSER") + " -> " + g("PAYROLL"),   // named by the user only
		u("ALICE") + " -> " + g("PAYROLL"),     // by both
		u("BOB") + " -> " + g("PAYROLL"),       // by the group only
		u("IBMUSER") + " -> racf-attr:SPECIAL", // authorities
		u("IBMUSER") + " -> racf-attr:AUDITOR",
		u("BOB") + " -> racf-attr:OPERATIONS",
		u("IBMUSER") + " -> racf-attr:OPERATIONS",
	} {
		if !members[k] {
			t.Errorf("missing membership %s", k)
		}
	}
	if len(res.Members) != 8 {
		t.Errorf("%d memberships: %v", len(res.Members), members) // GHOST is not a user and drops out
	}

	again, _ := discover(t, sdbm(), spec(), lim)
	for i := range res.Members {
		if res.Members[i] != again.Members[i] {
			t.Fatal("the result is not deterministic")
		}
	}
}

func TestDiscover_Limits(t *testing.T) {
	for name, l := range map[string]agent.SyncLimits{
		"accounts": {Accounts: 2, Groups: 100, Members: 100},
		"groups":   {Accounts: 100, Groups: 3, Members: 100}, // three groups plus room for the synthetic ones
		"members":  {Accounts: 100, Groups: 100, Members: 3},
	} {
		if res, err := discover(t, sdbm(), spec(), l); !errors.Is(err, racf.ErrTooLarge) || res != nil {
			t.Errorf("%s: %v %v", name, res, err)
		}
	}
}

func TestDiscover_FixedErrors(t *testing.T) {
	// A directory's own message can echo a DN or a filter: the module reports fixed text.
	f := sdbm()
	f.err = errors.New("LDAP Result Code 32: no such object racfid=ALICE,profiletype=USER,cn=RACFA secret-pw")
	_, err := discover(t, f, spec(), lim)
	if !errors.Is(err, racf.ErrRead) || strings.Contains(err.Error(), "ALICE") || strings.Contains(err.Error(), "secret") {
		t.Errorf("read error: %v", err)
	}
	f.err = ldap.ErrTooManyEntries
	if _, err := discover(t, f, spec(), lim); !errors.Is(err, racf.ErrTooLarge) {
		t.Errorf("too many: %v", err)
	}
	f.err = context.Canceled
	if _, err := discover(t, f, spec(), lim); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	// an open (dial or bind) failure passes through for the agent's error codes
	open := func(context.Context, agent.ProberSpec) (racf.Searcher, error) { return nil, safedial.ErrBlockedAddress }
	sy, _ := racf.Module(open).New(spec())
	if _, err := sy.Discover(context.Background(), lim); !errors.Is(err, safedial.ErrBlockedAddress) {
		t.Errorf("open: %v", err)
	}
}

func TestModule_RefusesBadSettings(t *testing.T) {
	open := func(context.Context, agent.ProberSpec) (racf.Searcher, error) { return sdbm(), nil }
	s := spec()
	s.Config.BaseDNs = nil
	if _, err := racf.Module(open).New(s); !errors.Is(err, racf.ErrNoBase) {
		t.Errorf("no base: %v", err)
	}
	s.Config.BaseDNs = []string{"not a dn"}
	if _, err := racf.Module(open).New(s); !errors.Is(err, racf.ErrBadBase) {
		t.Errorf("bad base: %v", err)
	}
	if _, err := racf.Module(nil).New(spec()); !errors.Is(err, racf.ErrNoDriver) {
		t.Errorf("no driver: %v", err)
	}
	s = spec()
	s.Config.AttrMap = []agent.AttrMap{{LDAP: "bad attr)(", Target: "x", Scope: "account"}}
	if _, err := discover(t, sdbm(), s, lim); !errors.Is(err, racf.ErrRead) {
		t.Errorf("bad attribute name: %v", err)
	}
}

// TestOpenLDAP_GoesThroughSafedial: the production opener dials only through
// the agent's Dialer, so an address the policy refuses is never reached, and a
// bind without a password never leaves the agent.
func TestOpenLDAP_GoesThroughSafedial(t *testing.T) {
	d, err := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	s := spec()
	s.Target.Host = "169.254.169.254"
	s.Dialer = d
	if _, err := racf.OpenLDAP(context.Background(), s); err == nil {
		t.Fatal("a blocked address was dialed")
	} else if strings.Contains(err.Error(), "pw") {
		t.Errorf("the error carries the password: %v", err)
	}
	s.Password = ""
	if _, err := racf.OpenLDAP(context.Background(), s); !errors.Is(err, ldap.ErrBindRefused) {
		t.Errorf("empty password: %v", err)
	}
}

// TestDiscover_PrivilegedAttributesAlwaysFlagged: ROAUDIT is a system-wide
// authority too, and a server that packs several keywords into one value
// cannot hide a SPECIAL.
func TestDiscover_PrivilegedAttributesAlwaysFlagged(t *testing.T) {
	u := "racfid=AUD1,profiletype=USER," + suffix
	f := &fakeSDBM{entries: map[string][]ldap.Entry{
		"profiletype=USER," + suffix: {ent(u, "racfid", "AUD1", "racfattributes", "ROAUDIT", "racfattributes", "special, revoked")},
	}}
	res, err := discover(t, f, spec(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accounts[0].Status != "disabled" {
		t.Errorf("a packed REVOKED was missed: %+v", res.Accounts[0])
	}
	priv := map[string]bool{}
	for _, g := range res.Groups {
		priv[g.ExternalID] = g.Privileged
	}
	members := map[string]bool{}
	for _, m := range res.Members {
		members[m.Group] = m.Account == u
	}
	for _, id := range []string{"racf-attr:ROAUDIT", "racf-attr:SPECIAL"} {
		if !priv[id] || !members[id] {
			t.Errorf("%s: privileged %v, member %v (%+v)", id, priv[id], members[id], res)
		}
	}
}

// TestDiscover_OpenErrorsAreFixedText: a dial or bind failure that carries the
// server's diagnostic (a DN, an address) is reported as fixed text; the policy
// sentinels survive for the agent's error codes.
func TestDiscover_OpenErrorsAreFixedText(t *testing.T) {
	for in, want := range map[error]error{
		errors.New("LDAP Result Code 49 \"\": ICH408I USER(TESSERA) racfid=TESSERA,profiletype=USER,cn=RACFA pw"): racf.ErrConnect,
		fmt.Errorf("%w: StartTLS: server said racfid=X", safedial.ErrNoTLS):                                       safedial.ErrNoTLS,
		fmt.Errorf("dial 10.1.2.3: %w", safedial.ErrBlockedAddress):                                               safedial.ErrBlockedAddress,
		ldap.ErrBindRefused: ldap.ErrBindRefused,
	} {
		open := func(context.Context, agent.ProberSpec) (racf.Searcher, error) { return nil, in }
		sy, _ := racf.Module(open).New(spec())
		_, err := sy.Discover(context.Background(), lim)
		if err != want || strings.Contains(err.Error(), "racfid") || strings.Contains(err.Error(), "10.1.2.3") {
			t.Errorf("%v: got %v, want %v", in, err, want)
		}
	}
}

func connect(user, group string, attrs ...string) ldap.Entry {
	e := ent("racfuserid="+user+"+racfgroupid="+group+",profiletype=CONNECT,"+suffix, "racfuserid", user, "racfgroupid", group)
	for _, a := range attrs {
		e.Attrs["racfconnectattributes"] = append(e.Attrs["racfconnectattributes"], a)
	}
	return e
}

// TestDiscover_ConnectProfiles: a connect's group-level SPECIAL, OPERATIONS
// and AUDITOR are privileged groups of their own (kept when the connect is
// revoked: a dormant authority stays visible), and a revoked connect is not a
// live membership whichever side names it.
func TestDiscover_ConnectProfiles(t *testing.T) {
	f := sdbm()
	f.entries["profiletype=CONNECT,"+suffix] = []ldap.Entry{
		connect("ALICE", "PAYROLL", "SPECIAL"),
		connect("BOB", "PAYROLL", "REVOKED", "AUDITOR"),
		connect("IBMUSER", "PAYROLL", "REVOKED"),
		connect("GHOST", "PAYROLL", "SPECIAL"), // not a user: dropped
	}
	res, err := discover(t, f, spec(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Validate(); err != nil {
		t.Fatal(err)
	}
	u := func(id string) string { return "racfid=" + id + ",profiletype=USER," + suffix }
	pay := "racfid=PAYROLL,profiletype=GROUP," + suffix
	members := map[string]bool{}
	for _, m := range res.Members {
		members[m.Account+" -> "+m.Group] = true
	}
	priv := map[string]bool{}
	for _, g := range res.Groups {
		priv[g.ExternalID] = g.Privileged
	}
	for id, want := range map[string]bool{"racf-group-attr:SPECIAL:" + pay: true, "racf-group-attr:AUDITOR:" + pay: true, pay: false} {
		if got, ok := priv[id]; !ok || got != want {
			t.Errorf("group %s: present %v privileged %v", id, ok, got)
		}
	}
	for k, want := range map[string]bool{
		u("ALICE") + " -> racf-group-attr:SPECIAL:" + pay: true,
		u("BOB") + " -> racf-group-attr:AUDITOR:" + pay:   true,  // revoked, still visible
		u("ALICE") + " -> " + pay:                         true,  // a live connect
		u("BOB") + " -> " + pay:                           false, // revoked: named by the group only
		u("IBMUSER") + " -> " + pay:                       false, // revoked: named by the user only
	} {
		if members[k] != want {
			t.Errorf("membership %s: %v, want %v", k, members[k], want)
		}
	}
}

// TestDiscover_SuffixesAreSeparateDatabases: the same racfid under two
// suffixes is two accounts, each keeping its own SPECIAL, and connects match
// within their suffix only.
func TestDiscover_SuffixesAreSeparateDatabases(t *testing.T) {
	f := &fakeSDBM{entries: map[string][]ldap.Entry{
		"profiletype=USER,cn=A":  {ent("racfid=ADM,profiletype=USER,cn=A", "racfid", "ADM", "racfconnectgroupname", "SYS1", "racfattributes", "AUDITOR")},
		"profiletype=USER,cn=B":  {ent("racfid=ADM,profiletype=USER,cn=B", "racfid", "ADM", "racfattributes", "SPECIAL")},
		"profiletype=GROUP,cn=B": {ent("racfid=SYS1,profiletype=GROUP,cn=B", "racfid", "SYS1")},
	}}
	s := spec()
	s.Config.BaseDNs = []string{"cn=A", "cn=B"}
	res, err := discover(t, f, s, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 {
		t.Fatalf("accounts: %+v", res.Accounts)
	}
	members := map[string]bool{}
	for _, m := range res.Members {
		members[m.Account+" -> "+m.Group] = true
	}
	if !members["racfid=ADM,profiletype=USER,cn=B -> racf-attr:SPECIAL"] || !members["racfid=ADM,profiletype=USER,cn=A -> racf-attr:AUDITOR"] {
		t.Errorf("privileges: %v", members)
	}
	if members["racfid=ADM,profiletype=USER,cn=A -> racfid=SYS1,profiletype=GROUP,cn=B"] {
		t.Error("a connect crossed suffixes")
	}
}

// TestDiscover_NoReadableAttributesFails: users without any racfAttributes
// mean the bind user cannot read them; the sync fails rather than report no
// privileged holder.
func TestDiscover_NoReadableAttributesFails(t *testing.T) {
	f := &fakeSDBM{entries: map[string][]ldap.Entry{
		"profiletype=USER," + suffix: {ent("racfid=A,profiletype=USER,"+suffix, "racfid", "A"), ent("racfid=B,profiletype=USER,"+suffix, "racfid", "B")},
	}}
	if res, err := discover(t, f, spec(), lim); !errors.Is(err, racf.ErrNoAttributes) || res != nil {
		t.Errorf("%v %v", res, err)
	}
	// an empty database is not an error
	if _, err := discover(t, &fakeSDBM{entries: map[string][]ldap.Entry{}}, spec(), lim); err != nil {
		t.Errorf("empty: %v", err)
	}
}

// TestDiscover_GroupLimitBoundary: the synthetic groups count only when
// emitted. The fixture has three groups and three synthetic ones.
func TestDiscover_GroupLimitBoundary(t *testing.T) {
	if _, err := discover(t, sdbm(), spec(), agent.SyncLimits{Accounts: 100, Groups: 6, Members: 100}); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	if _, err := discover(t, sdbm(), spec(), agent.SyncLimits{Accounts: 100, Groups: 5, Members: 100}); !errors.Is(err, racf.ErrTooLarge) {
		t.Errorf("over the limit: %v", err)
	}
	// no privileged holder: every slot is for real groups
	f := sdbm()
	for i, e := range f.entries["profiletype=USER,"+suffix] {
		e.Attrs["racfattributes"] = []string{"PROTECTED"}
		f.entries["profiletype=USER,"+suffix][i] = e
	}
	if _, err := discover(t, f, spec(), agent.SyncLimits{Accounts: 100, Groups: 3, Members: 100}); err != nil {
		t.Errorf("three groups, no synthetic: %v", err)
	}
}
