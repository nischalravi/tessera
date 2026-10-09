package leastpriv_test

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func load(t *testing.T, st *store.Store) (*graph.Snapshot, *usage.Index) {
	t.Helper()
	c := testkit.Conn(st)
	g, err := graph.FromDB(c, testkit.Now)
	if err != nil {
		t.Fatal(err)
	}
	u, err := usage.Build(c, testkit.Now)
	if err != nil {
		t.Fatal(err)
	}
	return g, u
}

func actions(g *graph.Snapshot, keys []string) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, g.Node(k).Action)
	}
	return out
}

func TestUsageIndexLastUsed(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g, u := load(t, st)
	eff := map[string]*graph.EffectivePermission{}
	for _, ep := range g.EffectivePermissions(ids["alice"]).Values() {
		eff[ep.Action] = ep
	}
	if d := u.Get(ids["alice"], eff["s3:PutObject"].PermID).DaysSince(u.Now); d == nil || *d != 0 {
		t.Errorf("PutObject days since = %v, want 0", d)
	}
	st2 := u.Get(ids["alice"], eff["s3:GetObject"].PermID)
	if st2.LastUsed != nil || st2.Events90d != 0 {
		t.Errorf("GetObject stat = %+v, want never used", st2)
	}
	if got := u.Get(ids["alice"], eff["s3:PutObject"].PermID); got.Events90d != 150 || got.ActiveDays90 != 30 {
		t.Errorf("PutObject stat = %+v, want 150 events over 30 days", got)
	}
}

func TestUnusedPermissionsDetected(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g, u := load(t, st)
	tests := []struct {
		identity string
		days     int
		want     []string
	}{
		{"alice", 60, []string{"s3:GetObject"}},
		// carol used prod admin 75 days ago: unused at 60d and 75d, used at 76d and 90d
		{"carol", 60, []string{"s3:GetObject", "s3:PutObject", "iam:*"}},
		{"carol", 75, []string{"s3:GetObject", "s3:PutObject", "iam:*"}},
		{"carol", 76, []string{"s3:GetObject", "s3:PutObject"}},
		{"carol", 90, []string{"s3:GetObject", "s3:PutObject"}},
		{"bob", 1, []string{"payments:approve", "payments:create"}},
		{"bob", 2, []string{"payments:approve"}},
	}
	for _, tc := range tests {
		got := actions(g, leastpriv.UnusedPermissions(g, u, ids[tc.identity], tc.days))
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s @%dd: unused = %v, want %v", tc.identity, tc.days, got, want)
		}
	}
}

func TestRecommendationsRemoveVsRightSize(t *testing.T) {
	st, ids := testkit.Tiny(t)
	g, u := load(t, st)
	type key struct {
		iid    int64
		target string
	}
	recs := map[key]leastpriv.Recommendation{}
	for _, r := range leastpriv.GrantRecommendations(g, u, 60, nil) {
		recs[key{*r.IdentityID, r.Target}] = r
	}
	tests := []struct {
		identity, target string
		kind             string // "" = no recommendation
		check            func(leastpriv.Recommendation) bool
	}{
		{"carol", "okta:platform", "remove", func(r leastpriv.Recommendation) bool { return r.PrivilegedUnused == 1 }},
		{"alice", "okta:eng", "right_size", func(r leastpriv.Recommendation) bool { // 1 of 2 perms unused
			return slices.Equal(r.UnusedExamples, []string{"s3:GetObject on s3://customer-pii"})
		}},
		{"bob", "okta:payments-clerks", "", nil}, // in active use
		{"bob", "okta:payments-approvers", "remove", nil},
	}
	for _, tc := range tests {
		r, ok := recs[key{ids[tc.identity], tc.target}]
		if tc.kind == "" {
			if ok {
				t.Errorf("%s/%s: unexpected %s recommendation", tc.identity, tc.target, r.Kind)
			}
			continue
		}
		if !ok || r.Kind != tc.kind {
			t.Errorf("%s/%s: kind = %q (present %v), want %q", tc.identity, tc.target, r.Kind, ok, tc.kind)
			continue
		}
		if tc.check != nil && !tc.check(r) {
			t.Errorf("%s/%s: unexpected %+v", tc.identity, tc.target, r)
		}
	}
	all := leastpriv.GrantRecommendations(g, u, 60, nil)
	for i := 1; i < len(all); i++ {
		if all[i-1].Score < all[i].Score {
			t.Fatal("recommendations must be sorted by descending score")
		}
	}
	one := leastpriv.GrantRecommendations(g, u, 60, func() *int64 { v := ids["alice"]; return &v }())
	for _, r := range one {
		if *r.IdentityID != ids["alice"] {
			t.Errorf("identity filter leaked %s", r.IdentityName)
		}
	}
}

func TestRedundantGrant(t *testing.T) {
	st, ids := testkit.Tiny(t)
	// a second, parallel route to ProdAdmin makes carol's okta:platform grant redundant
	testkit.Write(t, st, func(c *store.Conn) error {
		_, err := c.Exec(`INSERT INTO grant_edges (src, dst, relation, source, created_at) VALUES (?, ?, 'member_of', 'manual', ?)`,
			graph.Key("account", ids["acct:okta:carol"]), graph.Key("group", ids["group:aws:ProdAdmin"]), store.T(testkit.Now))
		return err
	})
	g, u := load(t, st)
	for _, r := range leastpriv.GrantRecommendations(g, u, 60, nil) {
		if *r.IdentityID == ids["carol"] && r.Target == "okta:platform" {
			if r.Kind != "redundant" || r.Score != 1 || r.PermissionsLost != 0 {
				t.Errorf("rec = %+v", r)
			}
			return
		}
	}
	t.Error("no recommendation for carol's okta:platform grant")
}

func TestRoleTrimFlagsPermissionNoHolderUses(t *testing.T) {
	st, _ := testkit.Tiny(t)
	g, u := load(t, st)
	recs := leastpriv.RoleTrimRecommendations(g, u, 60, 2)
	// alice and carol both hold DevAdmin's s3:GetObject on customer-pii via okta:eng; nobody uses it
	if len(recs) != 1 || recs[0].Grant != "aws:DevAdmin → s3:GetObject on s3://customer-pii" {
		t.Fatalf("recs = %+v", recs)
	}
	if recs[0].IdentityName != "2 holders" { // dave is terminated, so not counted
		t.Errorf("identity_name = %q", recs[0].IdentityName)
	}
	if recs[0].IdentityID != nil || !slices.Equal(recs[0].Holders, []string{"Alice", "Carol"}) {
		t.Errorf("rec = %+v", recs[0])
	}
	if n := len(leastpriv.RoleTrimRecommendations(g, u, 60, 3)); n != 0 {
		t.Errorf("min_holders=3: %d recs, want 0", n)
	}
}

func TestDemoUnusedAccessAndRecommendations(t *testing.T) {
	st := testkit.Demo(t)
	g, u := load(t, st)
	alice, err := testkit.Conn(st).Identities("WHERE name = 'Alice Okafor'")
	if err != nil || len(alice) != 1 {
		t.Fatal(err)
	}
	var labels []string
	for _, k := range leastpriv.UnusedPermissions(g, u, alice[0].ID, 60) {
		labels = append(labels, g.Label(k))
	}
	if !slices.Contains(labels, "s3:GetObject on s3://customer-pii") {
		t.Errorf("alice unused = %v", labels)
	}
	recs := leastpriv.GrantRecommendations(g, u, 60, nil)
	hasRemove := slices.ContainsFunc(recs, func(r leastpriv.Recommendation) bool { return r.Kind == "remove" })
	hasService := slices.ContainsFunc(recs, func(r leastpriv.Recommendation) bool { return r.IdentityType == "service" })
	if !hasRemove || !hasService {
		t.Errorf("remove=%v service=%v", hasRemove, hasService)
	}
	trims := leastpriv.RoleTrimRecommendations(g, u, 60, 2)
	if !slices.ContainsFunc(trims, func(r leastpriv.Recommendation) bool {
		return r.Grant == "aws:DevAdmin → s3:GetObject on s3://customer-pii"
	}) {
		t.Error("demo role trim should flag DevAdmin's customer-pii read")
	}
}
