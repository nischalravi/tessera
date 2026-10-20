package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestPersistLoadRoundTrip(t *testing.T) {
	col, _ := collectFixtures(t)
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	in := PersistInput{Source: store.AWSSourceConnector, ConnectorID: "", CatalogVersion: "2026-10-08-0123456789abcdef"}

	var created bool
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) {
		created, err = Persist(c, col, in)
		return err
	}); err != nil || !created {
		t.Fatalf("Persist = %v, %v", created, err)
	}

	var got *Collection
	var atts, ents int
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) {
		if got, err = Load(c, col.Snapshot.ID); err != nil {
			return err
		}
		as, _ := c.AWSAttachments(col.Snapshot.ID)
		atts = len(as)
		es, _ := c.AWSEntities(col.Snapshot.ID, store.AWSEntityPrincipal)
		ents = len(es)
		hdr, err := c.AWSSnapshot(col.Snapshot.ID)
		if err != nil {
			return err
		}
		if hdr.OrgID != "o-example12345" || hdr.Source != store.AWSSourceConnector || hdr.CatalogVersion != in.CatalogVersion ||
			!slices.Equal(hdr.AccountIDs, col.AccountIDs) || !hdr.TakenAt.Equal(testNow) {
			t.Errorf("header = %+v", hdr)
		}
		// policy documents hold the verbatim bytes
		for id, d := range col.Snapshot.Policies {
			row, err := c.AWSPolicyDocument(id)
			if err != nil || string(row.RawJSON) != string(d.RawJSON) || row.SourceARN != d.SourceARN || row.Kind != d.Kind.String() {
				t.Errorf("stored document %s = %+v, %v", d.SourceARN, row, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// the snapshot id is the content hash, and the loaded snapshot has the same content
	if id, err := ContentID(got); err != nil || id != col.Snapshot.ID {
		t.Fatalf("ContentID(loaded) = %s, %v; want %s", id, err, col.Snapshot.ID)
	}
	if got.Snapshot.ID != col.Snapshot.ID || !got.Snapshot.TakenAt.Equal(col.Snapshot.TakenAt) {
		t.Errorf("loaded id %s, taken %v", got.Snapshot.ID, got.Snapshot.TakenAt)
	}
	for id, want := range col.Snapshot.Policies {
		have := got.Snapshot.Policies[id]
		if have == nil {
			t.Errorf("policy %s lost", want.SourceARN)
			continue
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(have)
		if string(a) != string(b) {
			t.Errorf("policy %s changed:\n%s\n%s", want.SourceARN, a, b)
		}
	}
	if len(got.Snapshot.Policies) != len(col.Snapshot.Policies) {
		t.Errorf("%d policies loaded, %d stored", len(got.Snapshot.Policies), len(col.Snapshot.Policies))
	}
	a, _ := json.Marshal(col.Findings)
	b, _ := json.Marshal(got.Findings)
	if string(a) != string(b) {
		t.Errorf("findings changed:\n%s\n%s", a, b)
	}
	if len(got.Snapshot.Org.Nodes["ou-ab12-prod0001"].SCPIDs) != 1 || len(got.Snapshot.Org.Nodes["r-ab12"].RCPIDs) != 1 || !got.Snapshot.Org.RCPEnabled {
		t.Errorf("org = %+v", got.Snapshot.Org)
	}
	if len(got.IdentityCenter) != 1 || got.IdentityCenter[0].PermissionSetName != "Admin" {
		t.Errorf("identity center = %+v", got.IdentityCenter)
	}
	if atts == 0 || ents == 0 {
		t.Errorf("attachments %d, principals %d", atts, ents)
	}

	// persisting the same estate again writes nothing
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		created, err := Persist(c, col, in)
		if err != nil || created {
			t.Errorf("second Persist = %v, %v; want created=false", created, err)
		}
		as, _ := c.AWSAttachments(col.Snapshot.ID)
		if len(as) != atts {
			t.Errorf("%d attachments after the second Persist, %d before", len(as), atts)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// tenant B does not see A's snapshot, and storing the same estate gives B a snapshot of its own
	if err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		if _, err := Load(c, col.Snapshot.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B loaded A's snapshot: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		created, err := Persist(c, col, in)
		if err != nil || !created {
			t.Errorf("Persist in B = %v, %v", created, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistRefusesWithoutID(t *testing.T) {
	f := storetest.TwoTenants(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		_, err := Persist(c, &Collection{}, PersistInput{Source: store.AWSSourceConnector})
		return err
	})
	if err == nil {
		t.Error("persisted a collection with no snapshot")
	}
}
