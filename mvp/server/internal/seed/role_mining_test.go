package seed_test

import (
	"context"
	"testing"

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
