package store_test

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// VMS sources (issue #304) are per tenant: another tenant cannot read, change,
// delete or record a sync on them, and the same name is free in each tenant.
func TestIsolation_VmsSources(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	src := func(id string) *store.VmsSource {
		return &store.VmsSource{ID: id, Vendor: store.VmsFieldglass, Name: "Fieldglass", BaseURL: "https://fg.example",
			Settings: "{}", CredentialEnc: []byte("sealed"), Status: store.VmsActive, CreatedBy: "alice"}
	}
	inA(t, f, func(c *store.TenantTx) error { return c.InsertVmsSource(src("vms-a"), now) })
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.VmsSource("vms-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("VmsSource(A's) = %v", err)
		}
		if l, err := c.VmsSources(); err != nil || len(l) != 0 {
			t.Errorf("VmsSources = %v, %v", l, err)
		}
		b := src("vms-a")
		b.Name = "x"
		if err := c.UpdateVmsSource(b, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateVmsSource(A's) = %v", err)
		}
		if err := c.SetVmsResult("vms-a", &now, now, "ok", nil, "{}"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetVmsResult(A's) = %v", err)
		}
		if err := c.DeleteVmsSource("vms-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteVmsSource(A's) = %v", err)
		}
		if ev, err := c.IntakeEventsByChannel(store.ChannelVMS, 10); err != nil || len(ev) != 0 {
			t.Errorf("IntakeEventsByChannel = %v, %v", ev, err)
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	// the same name in another tenant is a different source
	inB(t, f, func(c *store.TenantTx) error { return c.InsertVmsSource(src("vms-b"), now) })
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertVmsSource(src("vms-a2"), now); !errors.Is(err, store.ErrVmsNameTaken) {
			t.Errorf("duplicate name = %v, want ErrVmsNameTaken", err)
		}
		if err := c.SetVmsResult("vms-a", &now, now, "ok", nil, `{"created":1}`); err != nil {
			t.Fatal(err)
		}
		s, err := c.VmsSource("vms-a")
		if err != nil || s.Cursor == nil || s.LastResult == nil || *s.LastResult != "ok" || string(s.CredentialEnc) != "sealed" {
			t.Errorf("VmsSource = %+v, %v", s, err)
		}
		// a failed sync keeps the watermark
		msg := "boom"
		if err := c.SetVmsResult("vms-a", nil, now, "failed", &msg, "{}"); err != nil {
			t.Fatal(err)
		}
		if s, _ = c.VmsSource("vms-a"); s.Cursor == nil || !s.Cursor.Equal(now) {
			t.Errorf("cursor after a failed sync = %v", s.Cursor)
		}
		return c.DeleteVmsSource("vms-a")
	})
}
