package jit_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestIsolation_SweeperPerTenant: tenants A and B each have one approved JIT
// grant past its deadline. One sweeper pass expires both, each in its own
// tenant transaction, and each tenant's jit.expire event is in its own audit
// log only, naming its own request.
func TestIsolation_SweeperPerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	got, err := jit.SweepAll(ctx, f.DB, storetest.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got[f.A.ID] != 1 || got[f.B.ID] != 1 || len(got) != 2 {
		t.Errorf("SweepAll expired %v, want one request in each tenant", got)
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		other := f.A
		if tn.ID == f.A.ID {
			other = f.B
		}
		err := f.DB.ReadTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			r, err := c.Request(tn.IDs["request:expired"])
			if err != nil {
				return err
			}
			if r.Status != "expired" {
				t.Errorf("tenant %s: expired request has status %q", tn.Slug, r.Status)
			}
			if active, err := c.Request(tn.IDs["request:approved"]); err != nil || active.Status != "approved" {
				t.Errorf("tenant %s: the active grant was touched: %v %v", tn.Slug, active, err)
			}
			if _, err := c.Edge(tn.IDs["edge:jit-expired"]); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("tenant %s: expired JIT edge still present (err %v)", tn.Slug, err)
			}
			log, err := c.AuditLog(-1)
			if err != nil {
				return err
			}
			var ids []int64
			for _, e := range log {
				if e.Action != "jit.expire" {
					continue
				}
				var d struct {
					RequestID int64 `json:"request_id"`
				}
				if err := json.Unmarshal(e.Detail, &d); err != nil {
					return err
				}
				ids = append(ids, d.RequestID)
			}
			if !slices.Equal(ids, []int64{tn.IDs["request:expired"]}) {
				t.Errorf("tenant %s: jit.expire events for requests %v, want only its own %d (the other tenant's is %d)",
					tn.Slug, ids, tn.IDs["request:expired"], other.IDs["request:expired"])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A second pass finds nothing to do anywhere.
	if got, err := jit.SweepAll(ctx, f.DB, storetest.Now); err != nil || len(got) != 0 {
		t.Errorf("second sweep: %v %v, want nothing", got, err)
	}
}
