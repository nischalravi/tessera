package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// lpRecPRsCovered lists the repository methods the test below exercises (TestIsolation_EveryTenantTxMethodCovered).
func lpRecPRsCovered() map[string]bool {
	return map[string]bool{"LPRecPR": true, "PutLPRecPR": true, "LPRecPRAttemptsSince": true, "ReserveLPRecPRAttempt": true}
}

// The pull request of a recommendation (schema/0958, issue #665) is a tenant's own: the same recommendation id and
// repository in two tenants are two rows, the hourly cap counts only the tenant's own, and a write keeps the creator.
func TestIsolation_LPRecPRs(t *testing.T) {
	f := storetest.TwoTenants(t)
	at := storetest.Now.Add(time.Hour)
	for i, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.PutLPRecPR(&store.LPRecPR{RecID: "grant-7", Repo: "o/policy", Branch: "tessera/" + tn.Slug, PullNumber: 10 + i,
				HeadSHA: "a", State: store.LPRecPROpen, CreatedBy: tn.Slug}, at)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A reserves one attempt; B reserves up to its cap of three: a tenant's cap never counts the other's attempts, and the
	// fourth is refused
	inA := func(fn func(c *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.A.ID, fn); err != nil {
			t.Fatal(err)
		}
	}
	inA(func(c *store.TenantTx) error {
		ok, err := c.ReserveLPRecPRAttempt("grant-7", "o/policy", "a", at, at.Add(-time.Hour), 3)
		if !ok || err != nil {
			t.Errorf("A reserve = %v, %v", ok, err)
		}
		return err
	})
	inB(t, f, func(c *store.TenantTx) error {
		for i := 0; i < 4; i++ {
			ok, err := c.ReserveLPRecPRAttempt("grant-7", "o/policy", "b", at, at.Add(-time.Hour), 3)
			if err != nil || ok != (i < 3) {
				t.Errorf("B reserve %d = %v, %v; want %v", i, ok, err, i < 3)
			}
		}
		return nil
	})
	// B updates its row; a second row for B only counts for B
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.PutLPRecPR(&store.LPRecPR{RecID: "grant-7", Repo: "o/policy", Branch: "tessera/b2", PullNumber: 99, HeadSHA: "b",
			State: store.LPRecPRClosed, CreatedBy: "someone else"}, at.Add(time.Minute)); err != nil {
			return err
		}
		return c.PutLPRecPR(&store.LPRecPR{RecID: "grant-8", Repo: "o/policy", Branch: "x", PullNumber: 1, HeadSHA: "c",
			State: store.LPRecPROpen, CreatedBy: "b"}, at)
	})
	read := func(tn storetest.Tenant, fn func(*store.TenantTx)) {
		t.Helper()
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	read(f.A, func(c *store.TenantTx) {
		p, err := c.LPRecPR("grant-7", "o/policy")
		if err != nil || p == nil || p.Branch != "tessera/"+f.A.Slug || p.PullNumber != 10 || p.State != store.LPRecPROpen || p.CreatedBy != f.A.Slug {
			t.Errorf("A: LPRecPR = %+v, %v; want its own", p, err)
		}
		if p, err := c.LPRecPR("grant-8", "o/policy"); err != nil || p != nil {
			t.Errorf("A: LPRecPR of B's recommendation = %+v, %v; want nil", p, err)
		}
		if n, err := c.LPRecPRAttemptsSince(at.Add(-time.Minute)); err != nil || n != 1 {
			t.Errorf("A: LPRecPRAttemptsSince = %d, %v; want 1", n, err)
		}
	})
	read(f.B, func(c *store.TenantTx) {
		p, err := c.LPRecPR("grant-7", "o/policy")
		if err != nil || p == nil || p.PullNumber != 99 || p.State != store.LPRecPRClosed || p.CreatedBy != f.B.Slug {
			t.Errorf("B: LPRecPR = %+v, %v; want the update with the first creator", p, err)
		}
		if n, err := c.LPRecPRAttemptsSince(at.Add(-time.Minute)); err != nil || n != 3 {
			t.Errorf("B: LPRecPRAttemptsSince = %d, %v; want 3", n, err)
		}
	})
}
