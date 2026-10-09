package simulate_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestSimulation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	c := testkit.Conn(st)
	acct := func(k string) string { return graph.Key("account", ids["acct:"+k]) }
	grp := func(k string) string { return graph.Key("group", ids["group:"+k]) }
	bobAppr, err := c.EdgeBetween(acct("okta:bob"), grp("okta:payments-approvers"))
	if err != nil {
		t.Fatal(err)
	}
	pols := testkit.Policies(t)
	run := func(req simulate.Request) (*simulate.Result, error) {
		return simulate.Run(c, req, simulate.Inputs{Now: testkit.Now, Policies: pols})
	}

	t.Run("remove grant resolves SoD", func(t *testing.T) {
		out, err := run(simulate.Request{RemoveEdgeIDs: []int64{bobAppr.ID}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Violations.Resolved) != 1 || out.Violations.Resolved[0].PolicyID != "sod-payments" {
			t.Errorf("resolved = %+v", out.Violations.Resolved)
		}
		if len(out.Violations.Introduced) != 0 {
			t.Errorf("introduced = %+v", out.Violations.Introduced)
		}
		if len(out.Identities) != 1 || len(out.Identities[0].Removed) != 1 || out.Identities[0].Removed[0].Action != "payments:approve" {
			t.Errorf("identities = %+v", out.Identities)
		}
		// the database is untouched by a simulation
		if _, err := c.Edge(bobAppr.ID); err != nil {
			t.Errorf("edge was deleted: %v", err)
		}
	})

	t.Run("add grant introduces violation", func(t *testing.T) {
		out, err := run(simulate.Request{AddEdges: []simulate.AddEdge{{Src: acct("okta:alice"), Dst: grp("okta:platform")}}})
		if err != nil {
			t.Fatal(err)
		}
		in := out.Violations.Introduced
		if len(in) != 1 || in[0].PolicyID != "no-standing-prod-admin" || *in[0].IdentityID != ids["alice"] {
			t.Errorf("introduced = %+v", in)
		}
		if out.Summary.PermissionsAdded != 1 {
			t.Errorf("permissions_added = %d", out.Summary.PermissionsAdded)
		}
	})

	t.Run("disable account removes iam:* and both DevAdmin permissions", func(t *testing.T) {
		out, err := run(simulate.Request{DisableAccountIDs: []int64{ids["acct:okta:carol"]}})
		if err != nil {
			t.Fatal(err)
		}
		if out.Summary.PermissionsRemoved != 3 || out.Summary.RemovedPrivileged != 1 || out.Summary.ViolationsResolved != 1 {
			t.Errorf("summary = %+v", out.Summary)
		}
	})

	t.Run("unknown edge id is reported, not fatal", func(t *testing.T) {
		out, err := run(simulate.Request{RemoveEdgeIDs: []int64{999999}})
		if err != nil {
			t.Fatal(err)
		}
		if lbl, _ := out.Changes[0].Get("label"); lbl != "not found" {
			t.Errorf("label = %v", lbl)
		}
	})

	t.Run("unknown nodes fail", func(t *testing.T) {
		var une *graph.UnknownNodeError
		if _, err := run(simulate.Request{DisableAccountIDs: []int64{999999}}); !errors.As(err, &une) {
			t.Errorf("disable unknown account: %v", err)
		}
		if _, err := run(simulate.Request{AddEdges: []simulate.AddEdge{{Src: "account:999999", Dst: grp("okta:eng")}}}); !errors.As(err, &une) {
			t.Errorf("add unknown edge: %v", err)
		}
	})
}
