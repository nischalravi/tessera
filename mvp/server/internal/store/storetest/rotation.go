package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Rotation keys in Tenant.Refs (every value is a UUID); every name, path and
// credential reference carries the tenant's sentinel (tenant A's graph
// sentinel; tenant B's rows are unmarked):
//
//	rot:adapter   a rotation adapter (type fake) with a sealed-looking credential blob
//	rot:dest      a second adapter, the hand-over destination
//	rot:policy    a policy for kind access_key naming both adapters
//	rot:bulk      a bulk "vendor compromised" run
//	rot:job       a pending job on the tenant's fixture secret, part of that bulk
//
// The blob is not a real sealed value: the store only keeps bytes.
func seedRotation(tb testing.TB, db *store.DB, t *Tenant, sentinel string) {
	tb.Helper()
	mark := func(s string) string {
		if sentinel == "" {
			return s
		}
		return s + " " + sentinel
	}
	// adapter names must be valid API names (no spaces)
	markName := func(s string) string {
		if sentinel == "" {
			return s
		}
		return s + "-" + sentinel
	}
	refs := t.Refs
	err := db.InTenant(context.Background(), t.ID, func(c *store.TenantTx) error {
		for _, a := range []struct{ key, name string }{{"rot:adapter", "adapter"}, {"rot:dest", "dest"}} {
			id := store.NewID()
			if err := c.InsertRotationAdapter(&store.RotationAdapter{ID: id, TenantID: t.ID, Name: markName(a.name), Type: "fake",
				Config: `{"note":"` + mark("config") + `"}`, SecretEnc: []byte("blob-" + a.name), CreatedBy: mark("admin"),
				CreatedAt: Now, UpdatedAt: Now}); err != nil {
				return err
			}
			refs[a.key] = id
		}
		adapter, dest := refs["rot:adapter"], refs["rot:dest"]
		refs["rot:policy"] = store.NewID()
		if err := c.InsertRotationPolicy(&store.RotationPolicy{ID: refs["rot:policy"], TenantID: t.ID, Kind: "access_key",
			MaxAgeDays: 90, GraceHours: 24, AdapterID: &adapter, DestAdapterID: &dest, DestPath: mark("kv/rot"),
			CreatedBy: mark("admin"), CreatedAt: Now, UpdatedAt: Now}); err != nil {
			return err
		}
		refs["rot:bulk"] = store.NewID()
		if err := c.InsertRotationBulk(&store.RotationBulk{ID: refs["rot:bulk"], TenantID: t.ID, System: "aws",
			Reason: mark("vendor breach"), Plan: `{"items":[]}`, PlanHash: "00", RequestedBy: mark("admin"), CreatedAt: Now}); err != nil {
			return err
		}
		bulk := refs["rot:bulk"]
		refs["rot:job"] = store.NewID()
		return c.InsertRotationJob(&store.RotationJob{ID: refs["rot:job"], TenantID: t.ID, SecretID: t.IDs["secret"],
			BulkID: &bulk, Origin: store.RotOriginVendor, AdapterID: adapter, AdapterType: "fake", DestAdapterID: &dest,
			DestPath: mark("kv/rot"), OldRef: mark("old-key"), GraceHours: 24, NextStepAt: Now.Add(time.Hour),
			RequestedBy: mark("admin"), CreatedAt: Now})
	})
	if err != nil {
		tb.Fatalf("storetest: rotation rows in %s: %v", t.Slug, err)
	}
}
