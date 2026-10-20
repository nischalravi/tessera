package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Shared Signals (issue #114): a tenant sees and changes only its own
// transmitters and events. Another tenant's id looks nonexistent, a replayed
// jti is refused per transmitter, and rows naming another tenant's connection,
// identity, account or transmitter are refused by the guard triggers.

func ssfTransmitter(tn storetest.Tenant) *store.SSFTransmitter {
	conn := tn.Refs["connection"]
	return &store.SSFTransmitter{Name: "okta-" + tn.Slug, Issuer: "https://" + tn.Slug + ".okta.com", Audience: "tessera",
		JWKSInline: `{"keys":[]}`, Delivery: store.SSFPush, SecretEnc: []byte("sealed-" + tn.Slug), SubjectSystem: "okta",
		ConnectionID: &conn, Status: store.SSFEnabled, CreatedBy: "admin"}
}

// seedSSF gives each tenant a transmitter with one event; it returns the ids by slug.
func seedSSF(t *testing.T, f *storetest.Fixture) (tr, ev map[string]string) {
	t.Helper()
	tr, ev = map[string]string{}, map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		x := ssfTransmitter(tn)
		e := &store.SSFEvent{JTI: "jti-1", Via: store.SSFPush, EventType: "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			SubjectFormat: "iss_sub", Subject: "alice", ReceivedAt: storetest.Now, IATAt: storetest.Now}
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertSSFTransmitter(x, storetest.Now); err != nil {
				return err
			}
			e.TransmitterID = x.ID
			return c.InsertSSFEvent(e)
		}); err != nil {
			t.Fatal(err)
		}
		tr[tn.Slug], ev[tn.Slug] = x.ID, e.ID
	}
	return tr, ev
}

func TestIsolation_SSFReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	tr, ev := seedSSF(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		xs, err := c.SSFTransmitters()
		if err != nil || len(xs) != 1 || xs[0].ID != tr[f.B.Slug] || string(xs[0].SecretEnc) != "sealed-"+f.B.Slug {
			t.Errorf("SSFTransmitters = %v, %v", xs, err)
		}
		if _, err := c.SSFTransmitter(tr[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SSFTransmitter(A's) = %v", err)
		}
		if _, err := c.SSFEvent(ev[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SSFEvent(A's) = %v", err)
		}
		if _, err := c.SSFEventByJTI(tr[f.A.Slug], "jti-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SSFEventByJTI(A's transmitter) = %v", err)
		}
		evs, err := c.SSFEvents("", 100)
		if err != nil || len(evs) != 1 || evs[0].ID != ev[f.B.Slug] {
			t.Errorf("SSFEvents(all) = %v, %v", evs, err)
		}
		if evs, err := c.SSFEvents(tr[f.A.Slug], 100); err != nil || len(evs) != 0 {
			t.Errorf("SSFEvents(A's transmitter) = %v, %v", evs, err)
		}
		return nil
	})
}

func TestIsolation_SSFWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	tr, ev := seedSSF(t, f)
	now := storetest.Now.Add(time.Minute)
	inB(t, f, func(c *store.TenantTx) error {
		x := ssfTransmitter(f.B)
		x.ID, x.Name = tr[f.A.Slug], "hijack"
		for name, err := range map[string]error{
			"UpdateSSFTransmitter":        c.UpdateSSFTransmitter(x, now),
			"DeleteSSFTransmitter":        c.DeleteSSFTransmitter(tr[f.A.Slug]),
			"TouchSSFTransmitter":         c.TouchSSFTransmitter(tr[f.A.Slug], now),
			"SetSSFTransmitterError":      c.SetSSFTransmitterError(tr[f.A.Slug], "x", now),
			"SetSSFPollState":             c.SetSSFPollState(tr[f.A.Slug], `["x"]`, `{}`, now),
			"SetSSFVerificationRequested": c.SetSSFVerificationRequested(tr[f.A.Slug], "s", now),
			"SetSSFVerified":              c.SetSSFVerified(tr[f.A.Slug], now),
			"UpdateSSFEvent (A's event)":  c.UpdateSSFEvent(&store.SSFEvent{ID: ev[f.A.Slug], Status: store.SSFEventActioned}),
		} {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s on A's row from B = %v, want ErrNotFound", name, err)
			}
		}
		return nil
	})
	// A's rows are untouched
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		x, err := c.SSFTransmitter(tr[f.A.Slug])
		if err != nil || x.Name != "okta-"+f.A.Slug || x.LastError != "" || x.PendingAcks != "[]" || x.VerifiedAt != nil || x.LastEventAt != nil {
			t.Errorf("A's transmitter = %+v, %v", x, err)
		}
		e, err := c.SSFEvent(ev[f.A.Slug])
		if err != nil || e.Status != store.SSFEventReceived {
			t.Errorf("A's event = %+v, %v", e, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_SSFGuardTriggers(t *testing.T) {
	f := storetest.TwoTenants(t)
	tr, _ := seedSSF(t, f)
	ctx := context.Background()
	// B names A's connection
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		x := ssfTransmitter(f.B)
		aConn := f.A.Refs["connection"]
		x.Name, x.ConnectionID = "named-a-connection", &aConn
		return c.InsertSSFTransmitter(x, storetest.Now)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("transmitter naming A's connection = %v, want ErrCrossTenant", err)
	}
	// B updates its transmitter to name A's connection
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		x := ssfTransmitter(f.B)
		aConn := f.A.Refs["connection"]
		x.ID, x.ConnectionID = tr[f.B.Slug], &aConn
		return c.UpdateSSFTransmitter(x, storetest.Now)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("update naming A's connection = %v, want ErrCrossTenant", err)
	}
	// B records an event on A's transmitter, and one naming A's identity and account
	for name, e := range map[string]*store.SSFEvent{
		"A's transmitter": {TransmitterID: tr[f.A.Slug], JTI: "x"},
	} {
		e.Via, e.EventType, e.ReceivedAt, e.IATAt = store.SSFPush, "t", storetest.Now, storetest.Now
		err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error { return c.InsertSSFEvent(e) })
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("event on %s = %v, want ErrCrossTenant", name, err)
		}
	}
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		e := &store.SSFEvent{TransmitterID: tr[f.B.Slug], JTI: "ok", Via: store.SSFPoll, EventType: "t", ReceivedAt: storetest.Now, IATAt: storetest.Now}
		if err := c.InsertSSFEvent(e); err != nil {
			return err
		}
		e.IdentityID, e.AccountID, e.Status = ptrInt(f.A.IDs["alice"]), ptrInt(f.A.IDs["acct:okta:alice"]), store.SSFEventMatched
		return c.UpdateSSFEvent(e)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("event update naming A's identity = %v, want ErrCrossTenant", err)
	}
}

func ptrInt(i int64) *int64 { return &i }

// The replay table: a jti is accepted once per transmitter, and the same jti
// at another transmitter or tenant is a different event.
func TestIsolation_SSFReplayKey(t *testing.T) {
	f := storetest.TwoTenants(t)
	tr, ev := seedSSF(t, f)
	ctx := context.Background()
	dup := &store.SSFEvent{TransmitterID: tr[f.A.Slug], JTI: "jti-1", Via: store.SSFPush, EventType: "t",
		ReceivedAt: storetest.Now, IATAt: storetest.Now}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.InsertSSFEvent(dup) }); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("replayed jti = %v, want ErrDuplicate", err)
	}
	var second string
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		x := ssfTransmitter(f.A)
		x.Name = "second"
		if err := c.InsertSSFTransmitter(x, storetest.Now); err != nil {
			return err
		}
		second = x.ID
		return c.InsertSSFEvent(&store.SSFEvent{TransmitterID: x.ID, JTI: "jti-1", Via: store.SSFPush, EventType: "t",
			ReceivedAt: storetest.Now, IATAt: storetest.Now})
	})
	if err != nil {
		t.Errorf("same jti at another transmitter: %v", err)
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		x := ssfTransmitter(f.A) // same name as the seeded one
		return c.InsertSSFTransmitter(x, storetest.Now)
	}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate transmitter name = %v, want ErrDuplicate", err)
	}
	// a delete takes the transmitter's events with it, and only those
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.DeleteSSFTransmitter(second) }); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.SSFEvents("", 100)
		if err != nil || len(evs) != 1 || evs[0].ID != ev[f.A.Slug] {
			t.Errorf("events after delete = %v, %v", evs, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The subject lookups never reach another tenant's accounts.
func TestIsolation_SSFAccountLookups(t *testing.T) {
	f := storetest.TwoTenants(t)
	inB(t, f, func(c *store.TenantTx) error {
		got, err := c.AccountsByExternalID("okta", "alice")
		if err != nil || len(got) != 1 || got[0].ID != f.B.IDs["acct:okta:alice"] {
			t.Errorf("AccountsByExternalID = %v, %v", got, err)
		}
		got, err = c.AccountsByLogin("okta", "ALICE")
		for _, a := range got {
			if a.ID == f.A.IDs["acct:okta:alice"] || a.TenantID != f.B.ID {
				t.Errorf("AccountsByLogin returned %+v", a)
			}
		}
		if err != nil {
			t.Error(err)
		}
		if got, err := c.AccountsByExternalID("okta", "no-such"); err != nil || len(got) != 0 {
			t.Errorf("no such account: %v, %v", got, err)
		}
		return nil
	})
}

func ssfCovered() map[string]bool {
	return map[string]bool{"SSFTransmitter": true, "SSFTransmitters": true, "SSFEvent": true, "SSFEventByJTI": true, "SSFEvents": true, // TestIsolation_SSFReads
		"UpdateSSFTransmitter": true, "DeleteSSFTransmitter": true, "TouchSSFTransmitter": true, "SetSSFTransmitterError": true,
		"SetSSFPollState": true, "SetSSFVerificationRequested": true, "SetSSFVerified": true, "UpdateSSFEvent": true, // TestIsolation_SSFWritesScoped
		"InsertSSFTransmitter": true, "InsertSSFEvent": true, // TestIsolation_SSFGuardTriggers, TestIsolation_SSFReplayKey
		"AccountsByExternalID": true, "AccountsByLogin": true} // TestIsolation_SSFAccountLookups
}
