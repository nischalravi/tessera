package graph_test

import (
	"fmt"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

func TestMain(m *testing.M) { testkit.Main(m) }

type ar struct{ action, resource string }

func byAction(eff *graph.Eff) map[ar]*graph.EffectivePermission {
	out := map[ar]*graph.EffectivePermission{}
	for _, ep := range eff.Values() {
		out[ar{ep.Action, ep.ResourceName}] = ep
	}
	return out
}

func load(t *testing.T, st *testkit.DB, now time.Time) *graph.Snapshot {
	t.Helper()
	return testkit.Get(t, st, func(c *store.TenantTx) (*graph.Snapshot, error) { return graph.Build(c, now) })
}

func acctKey(ids testkit.IDs, k string) string  { return graph.Key("account", ids["acct:"+k]) }
func groupKey(ids testkit.IDs, k string) string { return graph.Key("group", ids["group:"+k]) }

func TestEffectivePermissionPathThroughGroupsAndRoles(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	eff := byAction(g.EffectivePermissions(ids["alice"]))
	ep := eff[ar{"s3:GetObject", "s3://customer-pii"}]
	if ep == nil {
		t.Fatal("alice should reach s3://customer-pii")
	}
	want := "Alice → okta:alice@t.example → okta:eng → aws:DevAdmin → s3:GetObject on s3://customer-pii"
	if got := g.PathText(ep.Paths[0]); got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if !ep.Standing || ep.Privileged {
		t.Errorf("standing=%v privileged=%v, want standing non-privileged", ep.Standing, ep.Privileged)
	}
	if len(eff) != 2 || eff[ar{"s3:PutObject", "s3://ml-artifacts"}] == nil {
		t.Errorf("alice permissions = %v, want GetObject+PutObject", eff)
	}
}

func TestMultiplePathsAreAllReported(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	carol := byAction(g.EffectivePermissions(ids["carol"]))
	if carol[ar{"iam:*", "aws/prod"}] == nil || carol[ar{"s3:GetObject", "s3://customer-pii"}] == nil {
		t.Fatalf("carol permissions = %v", carol)
	}
	if err := g.AddEdge(acctKey(ids, "okta:carol"), groupKey(ids, "aws:DevAdmin"), "member_of", "simulated", nil); err != nil {
		t.Fatal(err)
	}
	ep := byAction(g.EffectivePermissions(ids["carol"]))[ar{"s3:GetObject", "s3://customer-pii"}]
	if len(ep.Paths) != 2 {
		t.Errorf("paths = %d, want 2", len(ep.Paths))
	}
	if len(ep.Paths[0]) > len(ep.Paths[1]) {
		t.Error("paths should be shortest first")
	}
}

func TestRoleInheritanceIsFollowed(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	ep := byAction(g.EffectivePermissions(ids["helper-bot"]))[ar{"snowflake:SELECT", "snowflake/CUSTOMERS"}]
	if ep == nil {
		t.Fatal("helper-bot should reach CUSTOMERS")
	}
	got := []string{g.Label(ep.Paths[0][2]), g.Label(ep.Paths[0][3])}
	if !slices.Equal(got, []string{"snowflake:ANALYST", "snowflake:PII_READER"}) {
		t.Errorf("hops = %v", got)
	}
}

func TestDisabledAccountsGrantNothing(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	dave := g.EffectivePermissions(ids["dave"])
	// okta account disabled -> no eng/DevAdmin perms; the AWS IAM user is still active
	if dave.Len() != 1 || dave.Values()[0].Action != "s3:GetObject" {
		t.Fatalf("dave = %v", dave.Keys)
	}
	for _, p := range dave.Values()[0].Paths {
		if g.Label(p[1]) != "aws:dave" {
			t.Errorf("path via %s, want aws:dave", g.Label(p[1]))
		}
	}
}

func TestExpiredJITEdgesAreIgnored(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	testkit.Write(t, st, func(c *store.TenantTx) error {
		exp := now.Add(time.Hour)
		_, err := c.InsertEdge(&store.GrantEdge{Src: acctKey(ids, "okta:alice"), Dst: groupKey(ids, "aws:ProdAdmin"),
			Relation: "member_of", Source: "jit", ExpiresAt: &exp, CreatedAt: now})
		return err
	})
	tests := []struct {
		name    string
		at      time.Time
		present bool
	}{
		{"before expiry", now, true},
		{"exactly at expiry", now.Add(time.Hour), false},
		{"after expiry", now.Add(2 * time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ep := byAction(load(t, st, tc.at).EffectivePermissions(ids["alice"]))[ar{"iam:*", "aws/prod"}]
			if (ep != nil) != tc.present {
				t.Fatalf("iam:* present = %v, want %v", ep != nil, tc.present)
			}
			if ep != nil && !ep.JITOnly() {
				t.Error("permission reachable only via JIT should be JIT-only")
			}
		})
	}
}

func TestCyclesDoNotLoopForever(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	if err := g.AddEdge(groupKey(ids, "aws:DevAdmin"), groupKey(ids, "okta:eng"), "maps_to", "simulated", nil); err != nil {
		t.Fatal(err)
	}
	if n := g.EffectivePermissions(ids["alice"]).Len(); n != 2 {
		t.Errorf("len = %d, want 2", n)
	}
}

func TestPermsLostIfEdgeRemoved(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	eff := g.EffectivePermissions(ids["carol"])
	lost := graph.PermsLostIfRemoved(eff, [2]string{acctKey(ids, "okta:carol"), groupKey(ids, "okta:platform")})
	if len(lost) != 1 || lost[0].Action != "iam:*" {
		t.Errorf("lost = %v, want [iam:*]", lost)
	}
	via := graph.PermsViaEdge(eff, [2]string{acctKey(ids, "okta:carol"), groupKey(ids, "okta:eng")})
	if len(via) != 2 {
		t.Errorf("via okta:eng = %d, want 2", len(via))
	}
}

func TestSnapshotCopyIsIsolated(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	g2 := g.Copy()
	if !g2.RemoveEdge(acctKey(ids, "okta:alice"), groupKey(ids, "okta:eng")) {
		t.Fatal("edge should exist")
	}
	if n := g.EffectivePermissions(ids["alice"]).Len(); n != 2 {
		t.Errorf("original = %d, want 2", n)
	}
	if n := g2.EffectivePermissions(ids["alice"]).Len(); n != 0 {
		t.Errorf("copy = %d, want 0", n)
	}
}

func TestDemoCompanyAliceReachesCustomerPII(t *testing.T) {
	st := testkit.Demo(t)
	idents := testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Identity, error) { return c.Identities() })
	var alice []*store.Identity
	for _, i := range idents {
		if i.Name == "Alice Okafor" {
			alice = append(alice, i)
		}
	}
	if len(alice) != 1 {
		t.Fatalf("alice: %v", alice)
	}
	g := load(t, st, testkit.Now)
	var texts []string
	for _, ep := range g.EffectivePermissions(alice[0].ID).Values() {
		if ep.Action == "s3:GetObject" && ep.ResourceName == "s3://customer-pii" {
			for _, p := range ep.Paths {
				texts = append(texts, g.PathText(p))
			}
		}
	}
	want := "Alice Okafor → okta:alice.okafor@larkspur.example → okta:engineering → aws:DevAdmin → s3:GetObject on s3://customer-pii"
	if !slices.Contains(texts, want) {
		t.Errorf("paths %v do not include %q", texts, want)
	}
	counts := map[string]int{}
	for _, i := range idents {
		counts[i.Type]++
	}
	if counts["human"] < 60 || counts["service"] < 25 || counts["ai_agent"] != 6 {
		t.Errorf("identity counts = %v", counts)
	}
	if n := testkit.Get(t, st, func(c *store.TenantTx) (int, error) { return c.CountAccounts() }); n <= 150 {
		t.Errorf("accounts = %d, want > 150", n)
	}
}

// --- focused graph / effective-permission tests on a hand-built snapshot ---

// chain builds identity:1 -> account:1 -> group:1..n (chained) -> perm:1 -> resource:1.
func chain(t *testing.T, groups int, jitHop int) *graph.Snapshot {
	t.Helper()
	g := graph.New()
	g.AddNode(&graph.Node{Key: "identity:1", Kind: "identity", Label: "Ida", ID: 1, Type: "human", Status: "active"})
	g.AddNode(&graph.Node{Key: "resource:1", Kind: "resource", Label: "db", ID: 1, System: "x"})
	g.AddNode(&graph.Node{Key: "account:1", Kind: "account", Label: "x:ida", ID: 1, System: "x", Status: "active"})
	for i := 1; i <= groups; i++ {
		g.AddNode(&graph.Node{Key: graph.Key("group", int64(i)), Kind: "group", Label: fmt.Sprintf("x:g%d", i), ID: int64(i), System: "x"})
	}
	g.AddNode(&graph.Node{Key: "perm:1", Kind: "perm", Label: "read on db", ID: 1, System: "x", Action: "read", ResourceID: 1, ResourceName: "db"})
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(g.AddEdge("identity:1", "account:1", "has_account", "connector", nil))
	must(g.AddEdge("perm:1", "resource:1", "on", "connector", nil))
	prev := "account:1"
	for i := 1; i <= groups; i++ {
		src := "connector"
		if i == jitHop {
			src = "jit"
		}
		k := graph.Key("group", int64(i))
		must(g.AddEdge(prev, k, "member_of", src, nil))
		prev = k
	}
	must(g.AddEdge(prev, "perm:1", "grants", "connector", nil))
	return g
}

func TestEffectivePermissionsStandingVsJIT(t *testing.T) {
	tests := []struct {
		name     string
		groups   int
		jitHop   int
		standing bool
	}{
		{"direct chain is standing", 1, 0, true},
		{"deep chain is standing", 5, 0, true},
		{"jit first hop", 3, 1, false},
		{"jit deep hop", 3, 3, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := chain(t, tc.groups, tc.jitHop)
			eff := g.EffectivePermissions(1)
			if eff.Len() != 1 {
				t.Fatalf("len = %d", eff.Len())
			}
			ep := eff.M["perm:1"]
			if ep.Standing != tc.standing {
				t.Errorf("standing = %v, want %v", ep.Standing, tc.standing)
			}
			if got := len(ep.Paths[0]); got != tc.groups+3 {
				t.Errorf("path length = %d, want %d", got, tc.groups+3)
			}
		})
	}
}

func TestEffectivePermissionsCapsPaths(t *testing.T) {
	// 12 parallel groups between the account and the permission: 12 paths, capped at 8.
	g := chain(t, 0, 0)
	for i := 1; i <= 12; i++ {
		k := graph.Key("group", int64(100+i))
		g.AddNode(&graph.Node{Key: k, Kind: "group", Label: k, ID: int64(100 + i), System: "x"})
		if err := g.AddEdge("account:1", k, "member_of", "connector", nil); err != nil {
			t.Fatal(err)
		}
		if err := g.AddEdge(k, "perm:1", "grants", "connector", nil); err != nil {
			t.Fatal(err)
		}
	}
	ep := g.EffectivePermissions(1).M["perm:1"]
	if len(ep.Paths) != graph.MaxPathsPerPermission {
		t.Errorf("paths = %d, want %d", len(ep.Paths), graph.MaxPathsPerPermission)
	}
	if len(ep.Paths[0]) != 3 {
		t.Errorf("shortest path first: got length %d", len(ep.Paths[0]))
	}
}

func TestEffectivePermissionsCacheInvalidation(t *testing.T) {
	g := chain(t, 2, 0)
	if g.EffectivePermissions(1).Len() != 1 {
		t.Fatal("want 1")
	}
	g.RemoveEdge("group:1", "group:2")
	if n := g.EffectivePermissions(1).Len(); n != 0 {
		t.Errorf("after RemoveEdge = %d, want 0 (cache must be cleared)", n)
	}
	g2 := chain(t, 1, 0)
	if err := g2.SetAccountStatus(1, "disabled"); err != nil {
		t.Fatal(err)
	}
	if n := g2.EffectivePermissions(1).Len(); n != 0 {
		t.Errorf("after disabling the account = %d, want 0", n)
	}
	if err := g2.SetAccountStatus(99, "disabled"); err == nil || err.Error() != "'account:99'" {
		t.Errorf("unknown account error = %v", err)
	}
	if err := g2.AddEdge("account:1", "group:99", "member_of", "simulated", nil); err == nil {
		t.Error("AddEdge to an unknown node should fail")
	}
}

func TestUnknownIdentityHasNoPermissions(t *testing.T) {
	if n := chain(t, 1, 0).EffectivePermissions(42).Len(); n != 0 {
		t.Errorf("len = %d", n)
	}
}

func TestRemoveEdgeID(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	e := testkit.Get(t, st, func(c *store.TenantTx) (*store.GrantEdge, error) {
		return c.EdgeBetween(acctKey(ids, "okta:bob"), groupKey(ids, "okta:payments-approvers"))
	})
	src, dst, ok := g.RemoveEdgeID(e.ID)
	if !ok || src != e.Src || dst != e.Dst {
		t.Fatalf("RemoveEdgeID = %s %s %v", src, dst, ok)
	}
	if _, _, ok := g.RemoveEdgeID(e.ID); ok {
		t.Error("second removal should report not found")
	}
	if byAction(g.EffectivePermissions(ids["bob"]))[ar{"payments:approve", "Supplier Payments"}] != nil {
		t.Error("bob should lose payments:approve")
	}
}

func TestDiffEffective(t *testing.T) {
	st, ids := testkit.Tiny(t)
	before := load(t, st, testkit.Now)
	after := before.Copy()
	after.RemoveEdge(acctKey(ids, "okta:carol"), groupKey(ids, "okta:platform"))
	if err := after.AddEdge(acctKey(ids, "okta:alice"), groupKey(ids, "okta:payments-clerks"), "member_of", "simulated", nil); err != nil {
		t.Fatal(err)
	}
	changes := graph.DiffEffective(before.AllEffective(), after.AllEffective())
	if len(changes) != 2 {
		t.Fatalf("changes = %v", changes)
	}
	if c := changes[ids["carol"]]; len(c.Removed) != 1 || len(c.Added) != 0 {
		t.Errorf("carol = %+v", c)
	}
	if c := changes[ids["alice"]]; len(c.Added) != 1 || len(c.Removed) != 0 {
		t.Errorf("alice = %+v", c)
	}
}

func TestDescribePathAndWhoCanAccess(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g := load(t, st, testkit.Now)
	ep := byAction(g.EffectivePermissions(ids["alice"]))[ar{"s3:GetObject", "s3://customer-pii"}]
	steps := g.DescribePath(ep.Paths[0], timeutil.ISOPtr)
	if steps[0].Via != nil || steps[0].System != nil {
		t.Errorf("identity step = %+v, want no via and no system", steps[0])
	}
	if steps[1].Via.Relation != "has_account" || steps[1].Via.EdgeID != nil {
		t.Errorf("account step via = %+v", steps[1].Via)
	}
	if steps[2].Via.EdgeID == nil || steps[2].Via.Source != "connector" {
		t.Errorf("grant step via = %+v", steps[2].Via)
	}
	who, perms := g.WhoCanAccess(ep.ResourceID)
	names := []string{}
	for _, iid := range who {
		names = append(names, g.Label(graph.Key("identity", iid)))
		if len(perms[iid]) == 0 {
			t.Errorf("%d listed without permissions", iid)
		}
	}
	sort.Strings(names)
	// alice and carol via okta:eng, dave via the forgotten IAM user, svc-etl directly
	if want := []string{"Alice", "Carol", "Dave", "svc-etl"}; !slices.Equal(names, want) {
		t.Errorf("who can access customer-pii = %v, want %v", names, want)
	}
}

func TestParseKey(t *testing.T) {
	tests := []struct {
		in   string
		kind string
		id   int64
		ok   bool
	}{
		{"group:7", "group", 7, true},
		{"account:12", "account", 12, true},
		{"group:x", "group", 0, false},
		{"nocolon", "nocolon", 0, false},
	}
	for _, tc := range tests {
		kind, id, err := graph.ParseKey(tc.in)
		if kind != tc.kind || (err == nil) != tc.ok || (tc.ok && id != tc.id) {
			t.Errorf("ParseKey(%q) = %q %d %v", tc.in, kind, id, err)
		}
	}
}
