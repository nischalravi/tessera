package abac_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/abac"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func setWorker(t *testing.T, c *store.TenantTx, id int64, wt string) {
	t.Helper()
	l := &store.Lifecycle{IdentityID: id, WorkerType: wt, Source: "manual", UpdatedAt: storetest.Now}
	if wt != "employee" {
		ends := storetest.Now.Add(30 * 24 * time.Hour)
		l.EndsAt = &ends
	}
	if err := c.PutLifecycle(l); err != nil {
		t.Fatal(err)
	}
}

// identity.worker_type comes from the lifecycle record: a person without one is
// an employee, a service or agent has none (so a test on it denies), an unknown
// value matches nothing, and another tenant's records are never seen.
func TestResolver_WorkerType(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	var humans, nonHumans []*store.Identity
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		people, err := c.Identities()
		if err != nil {
			return err
		}
		for _, p := range people {
			if p.Type == "human" {
				humans = append(humans, p)
			} else {
				nonHumans = append(nonHumans, p)
			}
		}
		if len(humans) < 3 || len(nonHumans) == 0 {
			t.Fatalf("fixture has %d humans and %d non-humans", len(humans), len(nonHumans))
		}
		setWorker(t, c, humans[0].ID, "contractor")
		setWorker(t, c, humans[1].ID, "vendor")
		setWorker(t, c, humans[2].ID, "employee")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// tenant B has its own, different records; none may show up in A
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		people, err := c.Identities()
		if err != nil {
			return err
		}
		for _, p := range people {
			if p.Type == "human" {
				setWorker(t, c, p.ID, "partner")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	count := func(c *store.TenantTx, cs string) int {
		t.Helper()
		res, err := abac.Simulate(c, cond(t, cs), nil, nil, storetest.Now)
		if err != nil {
			t.Fatal(err)
		}
		return res.Matching
	}
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		r, err := abac.NewResolver(c, storetest.Now)
		if err != nil {
			return err
		}
		for _, tc := range []struct {
			name string
			id   *store.Identity
			want string
		}{
			{"contractor", humans[0], "contractor"},
			{"vendor", humans[1], "vendor"},
			{"explicit employee", humans[2], "employee"},
		} {
			if got := r.Identity(tc.id)["identity.worker_type"]; got != tc.want {
				t.Errorf("%s: worker_type = %v, want %s", tc.name, got, tc.want)
			}
		}
		for _, p := range humans[3:] {
			if got := r.Identity(p)["identity.worker_type"]; got != "employee" {
				t.Errorf("%s without a lifecycle record: worker_type = %v, want employee", p.Name, got)
			}
		}
		for _, p := range nonHumans {
			if v, ok := r.Identity(p)["identity.worker_type"]; ok {
				t.Errorf("%s (%s) has worker_type %v", p.Name, p.Type, v)
			}
		}

		eq := func(v string) string { return `{"attr":"identity.worker_type","op":"eq","value":"` + v + `"}` }
		for name, tc := range map[string]struct {
			cond string
			want int
		}{
			"contractor matches one":        {eq("contractor"), 1},
			"vendor matches one":            {eq("vendor"), 1},
			"partner is only in tenant B":   {eq("partner"), 0},
			"unknown worker type":           {eq("freelancer"), 0},
			"in list":                       {`{"attr":"identity.worker_type","op":"in","value":["contractor","vendor"]}`, 2},
			"not contractor skips services": {`{"not":` + eq("contractor") + `}`, len(humans) - 1},
			"employees":                     {eq("employee"), len(humans) - 2},
			"exists is people only":         {`{"attr":"identity.worker_type","op":"exists"}`, len(humans)},
		} {
			if got := count(c, tc.cond); got != tc.want {
				t.Errorf("%s: %d matched, want %d", name, got, tc.want)
			}
		}
		// a service is outside a "not contractor" test, never granted by it
		res, err := abac.Simulate(c, cond(t, `{"attr":"identity.worker_type","op":"ne","value":"contractor"}`), nil, nil, storetest.Now)
		if err != nil || res.NoAttrs != len(nonHumans) {
			t.Errorf("ne contractor: %d identities lack the attribute, want %d (%v)", res.NoAttrs, len(nonHumans), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCatalog_ListsWorkerType(t *testing.T) {
	for _, a := range abac.Catalog {
		if a.Name == "identity.worker_type" {
			if a.Type != "string" {
				t.Errorf("type = %s", a.Type)
			}
			if err := cond(t, `{"attr":"identity.worker_type","op":"eq","value":"guest"}`).Validate(); err != nil {
				t.Error(err)
			}
			return
		}
	}
	t.Error("identity.worker_type is not in the catalog")
}
