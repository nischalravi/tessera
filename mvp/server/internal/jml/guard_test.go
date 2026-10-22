package jml_test

import (
	"fmt"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func identityStatus(t *testing.T, c *store.TenantTx, id int64) string {
	t.Helper()
	i, err := c.Identity(id)
	if err != nil {
		t.Fatal(err)
	}
	return i.Status
}

// Ending more people than the identities threshold allows is held: the HRIS events that go over
// are executed without ending anyone, the identity keeps its accounts and grants, and a second
// admin's release runs the leaver plan and ends them.
func TestLeaversOverTheThresholdAreHeldAndReleased(t *testing.T) {
	st, ids := testkit.Tiny(t)
	limit := 1
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatIdentities, MaxCount: &limit, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, testkit.Now)
	})
	events := map[string]int64{}
	for _, who := range []string{"alice", "bob", "carol"} {
		var ev int64
		testkit.Write(t, st, func(c *store.TenantTx) (err error) {
			identity := ids[who]
			ev, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "guard-" + who, Type: "leaver", IdentityID: &identity,
				EffectiveAt: testkit.Now, Status: "pending"})
			return
		})
		events[who] = ev
		execute(t, st, ev)
	}
	var ended, kept []string
	testkit.Read(t, st, func(c *store.TenantTx) error {
		for _, who := range []string{"alice", "bob", "carol"} {
			if identityStatus(t, c, ids[who]) == "terminated" {
				ended = append(ended, who)
			} else {
				kept = append(kept, who)
			}
		}
		return nil
	})
	if fmt.Sprint(ended) != "[alice]" || fmt.Sprint(kept) != "[bob carol]" {
		t.Fatalf("ended %v, kept %v: the first is let through, the rest held", ended, kept)
	}
	// the held ones keep their accounts
	testkit.Read(t, st, func(c *store.TenantTx) error {
		for _, who := range kept {
			accts, err := c.IdentityAccounts(ids[who])
			if err != nil {
				return err
			}
			for _, a := range accts {
				if a.Status != "active" {
					t.Errorf("%s's account %s is %s although the leaver is held", who, a.System, a.Status)
				}
			}
		}
		return nil
	})
	var hold string
	testkit.Read(t, st, func(c *store.TenantTx) error {
		hs, err := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 2 || hs[0].Source != "lifecycle" {
			t.Fatalf("holds %+v %v", hs, err)
		}
		hold = hs[0].ID
		return nil
	})
	// the release re-checks: one of them was ended by hand meanwhile
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if err := c.TerminateIdentity(ids["bob"], testkit.Now); err != nil {
			return err
		}
		res, err := deleteguard.Release(c, testkit.Now, hold, "approver", nil, deleteguard.Appliers{jml.ItemLeaver: jml.ReleaseLeaver, jml.ItemAccountDisable: jml.ReleaseAccountDisable})
		if err != nil || res.Released != 1 || res.Gone != 1 {
			t.Fatalf("release = %+v, %v", res, err)
		}
		return nil
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		if s := identityStatus(t, c, ids["carol"]); s != "terminated" {
			t.Errorf("carol is %s after the release", s)
		}
		return nil
	})
}

// ExecuteLeaver (the end-date leaver of the lifecycle) is guarded the same way: held, it returns
// a plan that says so and leaves the identity as it is.
func TestExecuteLeaverReturnsAHeldPlan(t *testing.T) {
	st, ids := testkit.Tiny(t)
	zero := 0
	testkit.Write(t, st, func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatIdentities, MaxCount: &zero, WindowMinutes: 60, Mode: deleteguard.ModeHoldAll}, nil, testkit.Now)
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		plan, err := jml.ExecuteLeaver(c, testkit.Now, ids["bob"])
		if err != nil {
			return err
		}
		if v, ok := plan.Get("held"); !ok || v != true {
			t.Errorf("plan %v", plan)
		}
		if s := identityStatus(t, c, ids["bob"]); s != "active" {
			t.Errorf("bob is %s", s)
		}
		return nil
	})
}
