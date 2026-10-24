package store_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Datasets (schema/0910, issue #588): a tenant reads and writes only its own lookup tables, and the same
// name in two tenants is two datasets.
func TestIsolation_Datasets(t *testing.T) {
	f := storetest.TwoTenants(t)
	const idA, idB = "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertDataset(idA, "cost-centers", "A's", "admin a", storetest.Now); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"cc-1", "cc-2"} {
			if ok, err := c.AddDatasetValue(idA, v); err != nil || !ok {
				t.Fatalf("add %s: %v %v", v, ok, err)
			}
		}
		if ok, err := c.AddDatasetValue(idA, "cc-1"); err != nil || ok {
			t.Errorf("duplicate value added: %v %v", ok, err)
		}
		if d, err := c.DatasetByName("cost-centers"); err != nil || d.Count != 2 || d.ID != idA {
			t.Errorf("A's dataset: %+v %v", d, err)
		}
		if ok, err := c.TouchDataset(idA, 1, "admin a", storetest.Now); err != nil || !ok {
			t.Errorf("touch: %v %v", ok, err)
		}
		if ok, err := c.TouchDataset(idA, 1, "admin a", storetest.Now); err != nil || ok {
			t.Errorf("a stale touch was accepted: %v %v", ok, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.Dataset(idA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's dataset: %v", err)
		}
		if _, err := c.DatasetByName("cost-centers"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B finds A's dataset by name: %v", err)
		}
		if l, err := c.Datasets(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's datasets: %v %v", l, err)
		}
		if vs, err := c.DatasetValues(idA, 10, 0); err != nil || len(vs) != 0 {
			t.Errorf("B reads A's values: %v %v", vs, err)
		}
		if has, err := c.DatasetHas(idA, "cc-1"); err != nil || has {
			t.Errorf("B tests A's values: %v %v", has, err)
		}
		if ok, err := c.RemoveDatasetValue(idA, "cc-1"); err != nil || ok {
			t.Errorf("B removed A's value: %v %v", ok, err)
		}
		if err := c.ClearDatasetValues(idA); err != nil {
			t.Errorf("B clear: %v", err)
		}
		if n, err := c.DatasetValueCount(idA); err != nil || n != 0 {
			t.Errorf("B counts A's values: %d %v", n, err)
		}
		if err := c.DeleteDataset(idA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B deleted A's dataset: %v", err)
		}
		if ok, err := c.UpdateDataset(idA, 2, "x", "", "b", storetest.Now); err != nil || ok {
			t.Errorf("B renamed A's dataset: %v %v", ok, err)
		}
		// the same name is free in B
		return c.InsertDataset(idB, "cost-centers", "B's", "admin b", storetest.Now)
	})
	inA(t, f, func(c *store.TenantTx) error {
		if has, err := c.DatasetHas(idA, "cc-2"); err != nil || !has {
			t.Errorf("A lost its value: %v %v", has, err)
		}
		if n, err := c.DatasetValueCount(idA); err != nil || n != 2 {
			t.Errorf("A's values after B cleared them: %d %v", n, err)
		}
		if n, err := c.DatasetCount(); err != nil || n != 1 {
			t.Errorf("A's count: %d %v", n, err)
		}
		return nil
	})
}

// datasetsCovered lists the methods TestIsolation_Datasets exercises.
func datasetsCovered() map[string]bool {
	return map[string]bool{"Datasets": true, "Dataset": true, "DatasetByName": true, "DatasetCount": true, "InsertDataset": true,
		"UpdateDataset": true, "TouchDataset": true, "DeleteDataset": true, "DatasetValues": true, "DatasetHas": true,
		"DatasetValueCount": true, "AddDatasetValue": true, "RemoveDatasetValue": true, "ClearDatasetValues": true}
}
