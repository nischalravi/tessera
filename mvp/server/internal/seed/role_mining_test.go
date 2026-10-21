package seed_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/roles/mining"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// TestSeedRoleMining: a default run over the demo company finds at least two
// sensible roles, each with a department or title rule that predicts its
// members, and the run is repeatable.
func TestSeedRoleMining(t *testing.T) {
	db := testkit.Demo(t)
	testkit.Read(t, db, func(c *store.TenantTx) error {
		in, err := mining.Load(c)
		if err != nil {
			return err
		}
		out, err := mining.Mine(context.Background(), mining.Params{}, in)
		if err != nil {
			return err
		}
		if len(out.Candidates) < 2 {
			t.Fatalf("%d candidates", len(out.Candidates))
		}
		withRule := 0
		for _, cd := range out.Candidates {
			if cd.Rule != nil && cd.Rule.Precision >= 90 && cd.Rule.Recall >= 90 && len(cd.Members) >= 3 && len(cd.Entitlements) >= 2 {
				withRule++
			}
		}
		if withRule < 2 {
			t.Errorf("only %d candidates have a strong rule: %+v", withRule, out.Candidates)
		}
		again, err := mining.Mine(context.Background(), mining.Params{}, in)
		if err != nil || again.SnapshotHash != out.SnapshotHash || len(again.Candidates) != len(out.Candidates) {
			t.Errorf("not repeatable: %v", err)
		}
		return nil
	})
}

// TestSeedRoleMiningSkipsReferenceGroups: Tessera's internal reference groups
// (ref:ial:*, ref:sponsor:*) never reach the mining input, so no candidate or
// accepted role carries them (#405).
func TestSeedRoleMiningSkipsReferenceGroups(t *testing.T) {
	db := testkit.Demo(t)
	ref := map[int64]bool{}
	// the sweeper maintains reference groups; hold two of them on every active account
	testkit.Write(t, db, func(c *store.TenantTx) error {
		refs, _, err := access.EnsureRefGroups(c)
		if err != nil {
			return err
		}
		accounts, err := c.Accounts()
		if err != nil {
			return err
		}
		for _, key := range []string{access.RefIAL2, access.RefSponsorEligible} {
			ref[refs[key].ID] = true
			for _, a := range accounts {
				if a.Status != "active" || a.IdentityID == nil {
					continue
				}
				if _, err := c.InsertEdge(&store.GrantEdge{Src: fmt.Sprintf("account:%d", a.ID), Dst: fmt.Sprintf("group:%d", refs[key].ID),
					Relation: "member_of", Source: "manual", CreatedAt: time.Now()}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	testkit.Read(t, db, func(c *store.TenantTx) error {
		in, err := mining.Load(c)
		if err != nil {
			return err
		}
		for _, p := range in.People {
			for _, g := range p.Entitlements {
				if ref[g] {
					t.Fatalf("person %d carries reference group %d into mining", p.ID, g)
				}
			}
		}
		for _, r := range in.Roles {
			for _, g := range r.Entitlements {
				if ref[g] {
					t.Fatalf("role %s carries reference group %d into mining", r.ID, g)
				}
			}
		}
		out, err := mining.Mine(context.Background(), mining.Params{}, in)
		if err != nil {
			return err
		}
		for _, cd := range out.Candidates {
			for _, g := range cd.Entitlements {
				if ref[g] {
					t.Errorf("candidate %q includes reference group %d", cd.Name, g)
				}
			}
		}
		return nil
	})
}
