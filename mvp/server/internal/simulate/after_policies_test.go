package simulate_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// AfterPolicies are the policies the simulated graph is evaluated against, for a change that alters the policies
// themselves (a proposed SoD rule or agent scope). Left nil, Policies serve both sides.
func TestAfterPolicies(t *testing.T) {
	st, _ := testkit.Tiny(t)
	pols := testkit.Policies(t)
	testkit.Read(t, st, func(c *store.TenantTx) error {
		same, err := simulate.Run(c, simulate.Request{}, simulate.Inputs{Now: testkit.Now, Policies: pols})
		if err != nil {
			t.Fatal(err)
		}
		if same.Summary.ViolationsBefore == 0 || same.Summary.ViolationsAfter != same.Summary.ViolationsBefore || len(same.Violations.Introduced) != 0 {
			t.Fatalf("no change: %+v", same.Summary)
		}
		// the same graph under no policy at all: every finding is resolved, and the before side is untouched
		none, err := simulate.Run(c, simulate.Request{}, simulate.Inputs{Now: testkit.Now, Policies: pols, AfterPolicies: []*policy.Policy{}})
		if err != nil {
			t.Fatal(err)
		}
		if none.Summary.ViolationsBefore != same.Summary.ViolationsBefore || none.Summary.ViolationsAfter != 0 ||
			len(none.Violations.Resolved) != same.Summary.ViolationsBefore || len(none.Violations.Introduced) != 0 {
			t.Errorf("under no policy: %+v", none.Summary)
		}
		return nil
	})
}
