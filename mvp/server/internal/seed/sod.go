package seed

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// seedSoD imports the separation_of_duties policy files into the tenant as
// the "Legacy SoD policies" ruleset (issue #298): functions for each side of
// a conflict, a risk per policy keyed by the policy id, so violation keys and
// results are unchanged. It writes no audit event, like the other seeds.
func seedSoD(c *store.TenantTx, now time.Time, policies []*policy.Policy) error {
	b, err := policy.LegacyBundle(policies, true)
	if err != nil || b == nil {
		return err
	}
	w := &sod.Writer{Tx: c, By: sod.Actor{Display: "seed"}, Now: now, Quiet: true}
	_, err = w.Import(b, sod.ImportOptions{})
	return err
}
