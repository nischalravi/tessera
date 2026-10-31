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
	return map[string]bool{"LPRecPR": true, "PutLPRecPR": true, "LPRecPRsCreatedSince": true}
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
		if n, err := c.LPRecPRsCreatedSince(at.Add(-time.Minute)); err != nil || n != 1 {
			t.Errorf("A: LPRecPRsCreatedSince = %d, %v; want 1", n, err)
		}
	})
	read(f.B, func(c *store.TenantTx) {
		p, err := c.LPRecPR("grant-7", "o/policy")
		if err != nil || p == nil || p.PullNumber != 99 || p.State != store.LPRecPRClosed || p.CreatedBy != f.B.Slug {
			t.Errorf("B: LPRecPR = %+v, %v; want the update with the first creator", p, err)
		}
		if n, err := c.LPRecPRsCreatedSince(at.Add(-time.Minute)); err != nil || n != 2 {
			t.Errorf("B: LPRecPRsCreatedSince = %d, %v; want 2", n, err)
		}
	})
}
