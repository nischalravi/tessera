package jit_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// Notifications from just-in-time access (issue #189): the requester and the
// person hear of a grant or a denial in the decision's own transaction; seed
// data, which has no signed-in decider, tells no one.
func TestJITDecisionsNotify(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	var requester, approver *store.PlatformUser
	var granted, denied *store.AccessRequest
	testkit.Write(t, st, func(c *store.TenantTx) error {
		requester = &store.PlatformUser{DisplayName: "Requester", CreatedAt: now}
		// an approver with no linked identity is refused (issue #443)
		person, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "approver", Name: "Approver", Type: "human", Status: "active", CreatedAt: now})
		if err != nil {
			return err
		}
		approver = &store.PlatformUser{DisplayName: "Approver", IdentityID: &person, CreatedAt: now}
		for _, u := range []*store.PlatformUser{requester, approver} {
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
		}

		if granted, err = jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 2}, "incident",
			store.UserRef{ID: requester.ID, Display: "Requester"}); err != nil {
			return err
		}
		denied, err = jit.CreateRequest(c, now, ids["bob"], ids["group:aws:ProdAdmin"], jit.Hours{N: 2}, "curiosity",
			store.UserRef{ID: requester.ID, Display: "Requester"})
		return err
	})
	inbox := func() []*store.Notification {
		return testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Notification, error) {
			return c.Notifications(requester.ID.String(), false, -1)
		})
	}
	if len(inbox()) != 0 {
		t.Fatal("filing a request notified someone")
	}
	by := store.UserRef{ID: approver.ID, Display: "Approver"}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		if _, err := jit.Approve(c, granted.ID, by, now, now); err != nil {
			return err
		}
		_, err := jit.Deny(c, denied.ID, by, now)
		return err
	})
	got := inbox()
	kinds := map[string]bool{}
	for _, n := range got {
		kinds[n.Kind] = true
		if n.Link != "/access/jit" || n.ReadAt != nil || !n.InApp {
			t.Errorf("notification = %+v", n)
		}
	}
	if len(got) != 2 || !kinds[notify.KindJITGranted] || !kinds[notify.KindJITDenied] {
		t.Fatalf("requester's notifications = %+v", got)
	}
	if n := testkit.Get(t, st, func(c *store.TenantTx) (int, error) {
		ns, err := c.Notifications(approver.ID.String(), false, -1)
		return len(ns), err
	}); n != 0 {
		t.Errorf("the approver was told of their own decision: %d", n)
	}
}

func TestJITSeedDataNotifiesNoOne(t *testing.T) {
	st, ids := testkit.Tiny(t)
	now := testkit.Now
	testkit.Write(t, st, func(c *store.TenantTx) error {
		r, err := jit.CreateRequest(c, now, ids["alice"], ids["group:aws:ProdAdmin"], jit.Hours{N: 2}, "seed", store.UserRef{})
		if err != nil {
			return err
		}
		_, err = jit.Approve(c, r.ID, store.UserRef{Display: "Ingrid"}, now, now)
		return err
	})
	testkit.Write(t, st, func(c *store.TenantTx) error {
		n, err := c.CountNotificationsDelivery(store.DeliveryPending)
		if err != nil || n != 0 {
			t.Errorf("pending email after seed-style approval = %d, %v", n, err)
		}
		return nil
	})
}
