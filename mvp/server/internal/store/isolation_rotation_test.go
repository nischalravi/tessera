package store_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Secret rotation isolation tests. storetest.TwoTenants gives both tenants an
// adapter pair, a policy, a bulk run and a pending job; tenant A's carry
// storetest.Sentinel, and every read here runs as tenant B.

var rotationLists = map[string]func(c *store.TenantTx) (any, error){
	"RotationAdapters": func(c *store.TenantTx) (any, error) { return c.RotationAdapters() },
	"RotationPolicies": func(c *store.TenantTx) (any, error) { return c.RotationPolicies() },
	"RotationBulks":    func(c *store.TenantTx) (any, error) { return c.RotationBulks() },
	"RotationJobs":     func(c *store.TenantTx) (any, error) { return c.RotationJobs(store.RotationJobFilter{}) },
	"RotationJobs/filtered": func(c *store.TenantTx) (any, error) {
		return c.RotationJobs(store.RotationJobFilter{State: store.RotPending})
	},
	"DueRotationJobs": func(c *store.TenantTx) (any, error) { return c.DueRotationJobs(storetest.Now.Add(48*time.Hour), 100) },
}

func TestIsolation_RotationListsReturnOnlyOwnRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, fn := range rotationLists {
		t.Run(name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error {
				got, err := fn(c)
				if err != nil {
					return err
				}
				if reflect.ValueOf(got).Len() == 0 {
					t.Fatalf("%s returned nothing for tenant B (the fixture should give it rows)", name)
				}
				if hasSentinel(got) {
					t.Errorf("%s in tenant B returned tenant A data", name)
				}
				return nil
			})
		})
	}
}

// Tenant A's ids, probed from tenant B, are indistinguishable from missing ones.
func TestIsolation_RotationGetsOtherTenantNotFound(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := f.A.Refs
	cases := map[string]func(c *store.TenantTx) error{
		"RotationAdapter": func(c *store.TenantTx) error { _, err := c.RotationAdapter(a["rot:adapter"]); return err },
		"RotationAdapterByName": func(c *store.TenantTx) error {
			_, err := c.RotationAdapterByName("adapter " + storetest.Sentinel)
			return err
		},
		"RotationPolicy": func(c *store.TenantTx) error { _, err := c.RotationPolicy(a["rot:policy"]); return err },
		"RotationBulk":   func(c *store.TenantTx) error { _, err := c.RotationBulk(a["rot:bulk"]); return err },
		"RotationJob":    func(c *store.TenantTx) error { _, err := c.RotationJob(a["rot:job"]); return err },
		"SecretByID":     func(c *store.TenantTx) error { _, err := c.SecretByID(f.A.IDs["secret"]); return err },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			inB(t, f, func(c *store.TenantTx) error {
				if err := fn(c); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("err = %v, want ErrNotFound", err)
				}
				return nil
			})
		})
	}
	inB(t, f, func(c *store.TenantTx) error {
		p, err := c.RotationPolicyByKey("access_key", "")
		if err != nil || p.ID != f.B.Refs["rot:policy"] {
			t.Errorf("RotationPolicyByKey = %v, %v; want tenant B's own policy", p, err)
		}
		n, err := c.RotationAdapterUses(a["rot:adapter"])
		if err != nil || n != 0 {
			t.Errorf("RotationAdapterUses(tenant A's adapter) = %d, %v; want 0", n, err)
		}
		n, err = c.RotationAdapterUses(f.B.Refs["rot:adapter"])
		if err != nil || n != 2 { // the policy and the pending job
			t.Errorf("RotationAdapterUses(own adapter) = %d, %v; want 2", n, err)
		}
		return nil
	})
}

// A mutation given tenant A's id, run as B, changes nothing in A.
func TestIsolation_RotationMutationsScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := f.A.Refs
	before := storetest.Dump(t, f.DB, f.A.ID)
	now := storetest.Now.Add(time.Hour)
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.UpdateRotationAdapter(a["rot:adapter"], `{"hijacked":true}`, []byte("x"), now); err != nil {
			return err
		}
		if err := c.UpdateRotationPolicy(&store.RotationPolicy{ID: a["rot:policy"], MaxAgeDays: 1, UpdatedAt: now}); err != nil {
			return err
		}
		for name, del := range map[string]func() (bool, error){
			"adapter": func() (bool, error) { return c.DeleteRotationAdapter(a["rot:adapter"]) },
			"policy":  func() (bool, error) { return c.DeleteRotationPolicy(a["rot:policy"]) },
		} {
			if ok, err := del(); err != nil || ok {
				t.Errorf("delete %s: %v, %v; want false", name, ok, err)
			}
		}
		if ok, err := c.ClaimRotationJob(a["rot:job"], store.RotPending, now.Add(48*time.Hour), now.Add(72*time.Hour)); err != nil || ok {
			t.Errorf("ClaimRotationJob: %v, %v; want false", ok, err)
		}
		j := &store.RotationJob{ID: a["rot:job"], State: store.RotFailed, NextStepAt: now}
		if err := c.UpdateRotationJob(j, store.RotPending, now); !errors.Is(err, store.ErrStateConflict) {
			t.Errorf("UpdateRotationJob: %v, want ErrStateConflict", err)
		}
		return c.ReplaceSecretCredential(f.A.IDs["secret"], "hijacked", now)
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("rotation mutations made as tenant B changed tenant A")
	}
}

func TestIsolation_RotationInsertWrongTenantRejected(t *testing.T) {
	f := storetest.TwoTenants(t)
	inserts := map[string]func(c *store.TenantTx) error{
		"adapter": func(c *store.TenantTx) error {
			return c.InsertRotationAdapter(&store.RotationAdapter{ID: store.NewID(), TenantID: f.A.ID, Name: "x", Type: "fake",
				Config: "{}", SecretEnc: []byte("x"), CreatedBy: "x", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
		"policy": func(c *store.TenantTx) error {
			return c.InsertRotationPolicy(&store.RotationPolicy{ID: store.NewID(), TenantID: f.A.ID, Kind: "k", MaxAgeDays: 1,
				CreatedBy: "x", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
		"bulk": func(c *store.TenantTx) error {
			return c.InsertRotationBulk(&store.RotationBulk{ID: store.NewID(), TenantID: f.A.ID, System: "s",
				Reason: "0123456789", Plan: "{}", PlanHash: "0", RequestedBy: "x", CreatedAt: storetest.Now})
		},
		"job": func(c *store.TenantTx) error {
			return c.InsertRotationJob(&store.RotationJob{ID: store.NewID(), TenantID: f.A.ID, SecretID: f.B.IDs["secret"],
				Origin: store.RotOriginManual, AdapterID: f.B.Refs["rot:adapter"], AdapterType: "fake", OldRef: "x",
				NextStepAt: storetest.Now, RequestedBy: "x", CreatedAt: storetest.Now})
		},
	}
	for name, fn := range inserts {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
}

// B cannot reference A's secret, adapters or bulk run from its own rows.
func TestIsolation_RotationCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := f.A.Refs, f.B.Refs
	job := func(secret int64, adapter string, dest, bulk *string) *store.RotationJob {
		return &store.RotationJob{ID: store.NewID(), TenantID: f.B.ID, SecretID: secret, BulkID: bulk, Origin: store.RotOriginManual,
			AdapterID: adapter, AdapterType: "fake", DestAdapterID: dest, OldRef: "x", NextStepAt: storetest.Now,
			RequestedBy: "x", CreatedAt: storetest.Now}
	}
	// B's own fixture job holds B's only secret, so use a finished job's slot:
	// move it out of flight first so the one-active index does not interfere.
	inB(t, f, func(c *store.TenantTx) error {
		j, err := c.RotationJob(b["rot:job"])
		if err != nil {
			return err
		}
		from := j.State
		j.State = store.RotCancelled
		return c.UpdateRotationJob(j, from, storetest.Now)
	})
	aAdapter, aBulk := a["rot:adapter"], a["rot:bulk"]
	cases := map[string]func(c *store.TenantTx) error{
		"job -> A's secret": func(c *store.TenantTx) error {
			return c.InsertRotationJob(job(f.A.IDs["secret"], b["rot:adapter"], nil, nil))
		},
		"job -> A's adapter": func(c *store.TenantTx) error {
			return c.InsertRotationJob(job(f.B.IDs["secret"], aAdapter, nil, nil))
		},
		"job -> A's destination": func(c *store.TenantTx) error {
			return c.InsertRotationJob(job(f.B.IDs["secret"], b["rot:adapter"], &aAdapter, nil))
		},
		"job -> A's bulk": func(c *store.TenantTx) error {
			return c.InsertRotationJob(job(f.B.IDs["secret"], b["rot:adapter"], nil, &aBulk))
		},
		"policy -> A's adapter": func(c *store.TenantTx) error {
			return c.InsertRotationPolicy(&store.RotationPolicy{ID: store.NewID(), TenantID: f.B.ID, Kind: "other", MaxAgeDays: 1,
				AdapterID: &aAdapter, CreatedBy: "x", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
		"policy update -> A's destination": func(c *store.TenantTx) error {
			p, err := c.RotationPolicy(b["rot:policy"])
			if err != nil {
				return err
			}
			p.DestAdapterID = &aAdapter
			return c.UpdateRotationPolicy(p)
		},
	}
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("a refused cross-tenant write changed tenant A")
	}
}

// The schema makes "verified by re-read" structural and keeps one job in
// flight per secret.
func TestRotationSchemaRules(t *testing.T) {
	f := storetest.TwoTenants(t)
	b := f.B.Refs
	inB(t, f, func(c *store.TenantTx) error {
		// a second job for the secret while the first is in flight
		dup := &store.RotationJob{ID: store.NewID(), TenantID: f.B.ID, SecretID: f.B.IDs["secret"], Origin: store.RotOriginManual,
			AdapterID: b["rot:adapter"], AdapterType: "fake", OldRef: "x", NextStepAt: storetest.Now, RequestedBy: "x",
			CreatedAt: storetest.Now}
		if err := c.InsertRotationJob(dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second in-flight job: %v, want ErrDuplicate", err)
		}
		return nil
	})
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		j, err := c.RotationJob(b["rot:job"])
		if err != nil {
			return err
		}
		j.State = store.RotVerified // no verification recorded
		return c.UpdateRotationJob(j, store.RotPending, storetest.Now)
	})
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint") {
		t.Errorf("verified without a recorded re-read: %v, want a CHECK failure", err)
	}
	// with the observation it is accepted, and the sealed bytes stay bytes
	inB(t, f, func(c *store.TenantTx) error {
		j, err := c.RotationJob(b["rot:job"])
		if err != nil {
			return err
		}
		v := `{"old_exists":true}`
		j.State, j.Verification = store.RotVerified, &v
		if err := c.UpdateRotationJob(j, store.RotPending, storetest.Now); err != nil {
			return err
		}
		got, err := c.RotationJob(b["rot:job"])
		if err != nil || got.State != store.RotVerified || got.LeaseUntil != nil {
			t.Errorf("job after update: %+v, %v", got, err)
		}
		return nil
	})
}

// rotationCovered lists every rotation repository method with a case above
// (TestIsolation_EveryRepoMethodClassified includes it).
func rotationCovered() map[string]bool {
	out := map[string]bool{}
	for _, m := range []map[string]bool{keys(rotationLists)} {
		for k := range m {
			out[strings.SplitN(k, "/", 2)[0]] = true
		}
	}
	for _, n := range []string{"RotationAdapter", "RotationAdapterByName", "RotationPolicy", "RotationPolicyByKey", "RotationBulk",
		"RotationJob", "SecretByID", "RotationAdapterUses", "UpdateRotationAdapter", "DeleteRotationAdapter",
		"UpdateRotationPolicy", "DeleteRotationPolicy", "ClaimRotationJob", "UpdateRotationJob", "ReplaceSecretCredential",
		"InsertRotationAdapter", "InsertRotationPolicy", "InsertRotationBulk", "InsertRotationJob"} {
		out[n] = true
	}
	return out
}
