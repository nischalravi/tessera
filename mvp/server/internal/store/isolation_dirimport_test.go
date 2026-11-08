package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The snapshot a directory CSV import left (schema/0965_dirimport.sql, issue #915) is the tenant's
// own. Both tenants use the same manual source and person keys, so only the tenant filter tells them apart.

func seedDirimport(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			for _, key := range []string{"pat@x.example", "sam@x.example"} {
				if err := c.PutImportRecord(&store.ImportRecord{System: "hr-sheet", Kind: "people", Key: key, Data: `{"who":"` + tn.Slug + `"}`,
					Hash: "h", ImportedBy: "admin", ImportedAt: storetest.Now}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_DirimportReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedDirimport(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		rows, err := c.ImportRecords("hr-sheet", "people")
		if err != nil || len(rows) != 2 || rows[0].Data != `{"who":"`+f.B.Slug+`"}` {
			t.Errorf("ImportRecords = %v, %v", rows, err)
		}
		if src, err := c.ImportSources(); err != nil || len(src) != 1 || src[0].Rows != 2 {
			t.Errorf("ImportSources = %v, %v", src, err)
		}
		if s, err := c.ImportRecordSource("people", "pat@x.example"); err != nil || s != "hr-sheet" {
			t.Errorf("ImportRecordSource = %q, %v", s, err)
		}
		return nil
	})
	// who imported a person is read per tenant: B's row says "admin", A's later edit does not leak
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutImportRecord(&store.ImportRecord{System: "hr-sheet", Kind: "people", Key: "pat@x.example", Data: "{}", Hash: "h2",
			ImportedBy: "a-admin", ImportedAt: storetest.Now.Add(time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if by, err := c.ImportedByOf("people", "pat@x.example"); err != nil || by != "admin" {
			t.Errorf("ImportedByOf = %q, %v, want B's own admin", by, err)
		}
		if by, err := c.ImportedByOf("people", "nobody@x.example"); err != nil || by != "" {
			t.Errorf("ImportedByOf(unknown) = %q, %v", by, err)
		}
		return nil
	})
	// a key only A has is unknown to B
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutImportRecord(&store.ImportRecord{System: "a-only", Kind: "people", Key: "only-a", Data: "{}", Hash: "h", ImportedBy: "admin", ImportedAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.ImportRecordSource("people", "only-a"); err != nil || s != "" {
			t.Errorf("ImportRecordSource(A's key) = %q, %v", s, err)
		}
		if rows, err := c.ImportRecords("a-only", "people"); err != nil || len(rows) != 0 {
			t.Errorf("ImportRecords(A's source) = %v, %v", rows, err)
		}
		return nil
	})
}

func TestIsolation_DirimportWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedDirimport(t, f)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.DeleteImportRecord("hr-sheet", "people", "pat@x.example"); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// B's delete took B's row only
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if rows, err := c.ImportRecords("hr-sheet", "people"); err != nil || len(rows) != 2 {
			t.Errorf("A's ImportRecords after B's delete = %v, %v", rows, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if rows, err := c.ImportRecords("hr-sheet", "people"); err != nil || len(rows) != 1 {
			t.Errorf("B's ImportRecords = %v, %v", rows, err)
		}
		return nil
	})
}

func dirimportCovered() map[string]bool {
	return map[string]bool{"PutImportRecord": true, "ImportRecords": true, "DeleteImportRecord": true, "ImportSources": true, "ImportRecordSource": true, "ImportedByOf": true} // TestIsolation_Dirimport*
}
