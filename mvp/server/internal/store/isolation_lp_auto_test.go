package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The automatic policy (schema/0953, issue #664): one row per tenant, A's policy is not B's, and the count of
// what an actor announced is a tenant's own.
func TestIsolation_LPAutoPolicy(t *testing.T) {
	f := storetest.TwoTenants(t)
	digest := func(c string) string { return strings.Repeat(c, 64) }
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: `{"a":1}`, PolicySHA256: digest("a"), Commit: "c1", AppliedBy: "u"}, storetest.Now); err != nil {
			return err
		}
		// a second apply replaces the first
		if err := c.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: `{"a":2}`, PolicySHA256: digest("d"), Commit: "c2", AppliedBy: "u", ApprovedBy: "v"}, storetest.Now); err != nil {
			return err
		}
		r := lpRev("rev-1", "arn:aws:iam::111122223333:role/shared")
		if err := c.InsertLPRevocation(r); err != nil {
			return err
		}
		r.State, r.ApprovedBy, r.ApprovedAt = store.LPAnnounced, "lp.auto", &storetest.Now
		return c.UpdateLPRevocation(r, store.LPCandidate, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.LPAutoPolicy(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B sees A's policy: %v", err)
		}
		if n, err := c.LPApprovedBySince("lp.auto", storetest.Now.Add(-time.Hour)); err != nil || n != 0 {
			t.Errorf("B counts A's announcements: %d, %v", n, err)
		}
		if err := c.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: `{"b":1}`, PolicySHA256: digest("b"), Commit: "c3", AppliedBy: "u"}, storetest.Now); err != nil {
			t.Errorf("B's own policy = %v", err)
		}
		if err := c.PutLPAutoPolicy(&store.LPAutoPolicy{Policy: `{}`, PolicySHA256: "short", Commit: "c", AppliedBy: "u"}, storetest.Now); err == nil {
			t.Error("a policy with a short digest was accepted")
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		p, err := c.LPAutoPolicy()
		if err != nil || p.Policy != `{"a":2}` || p.ApprovedBy != "v" || p.Commit != "c2" {
			t.Errorf("A's policy = %+v, %v", p, err)
		}
		if n, err := c.LPApprovedBySince("lp.auto", storetest.Now.Add(-time.Hour)); err != nil || n != 1 {
			t.Errorf("A's announcements = %d, %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
