package simulate_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// budgetCtx is done once Err has been asked budget times: a run is cancelled at its n-th check, deterministically.
type budgetCtx struct {
	context.Context
	budget int64
	calls  atomic.Int64
}

func (b *budgetCtx) Err() error {
	if b.calls.Add(1) > b.budget {
		return context.Canceled
	}
	return nil
}

// TestRunContext_Cancelled (#766): a context cancelled at any of the run's checks ends it with the context's error
// and no partial result, and the checks reach into the long phases (more than one per phase), not only between them.
func TestRunContext_Cancelled(t *testing.T) {
	st, _ := testkit.Tiny(t)
	pols := testkit.Policies(t)
	testkit.Read(t, st, func(c *store.TenantTx) error {
		in := simulate.Inputs{Now: testkit.Now, Policies: pols}
		done := int64(-1)
		for budget := int64(0); budget < 500 && done < 0; budget++ {
			ctx := &budgetCtx{Context: context.Background(), budget: budget}
			res, err := simulate.RunContext(ctx, c, simulate.Request{}, in)
			switch {
			case err == nil:
				if res == nil {
					t.Fatalf("budget %d: no error and no result", budget)
				}
				done = budget
			case !errors.Is(err, context.Canceled) || res != nil:
				t.Fatalf("budget %d: res %v err %v, want nil and context.Canceled", budget, res, err)
			}
		}
		if done < 0 {
			t.Fatal("the run never completed within 500 checks")
		}
		// each identity and each policy is a check of its own, so the budget a run needs exceeds its phases
		if done < 6 {
			t.Errorf("the run completes with %d checks: the long phases do not check the context", done)
		}
		// a context that is already done never starts
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if res, err := simulate.RunContext(ctx, c, simulate.Request{}, in); !errors.Is(err, context.Canceled) || res != nil {
			t.Errorf("cancelled context: res %v err %v", res, err)
		}
		return nil
	})
}
