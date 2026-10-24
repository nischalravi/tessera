package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Certification actions (schema/0912, issue #588): events on a review item and campaign lock and close
// states belong to the item's tenant.
func TestIsolation_ReviewActions(t *testing.T) {
	f := storetest.TwoTenants(t)
	itemA, itemB := f.A.IDs["item"], f.B.IDs["item"]
	campA := f.A.IDs["campaign"]
	var userA, userB string
	inA(t, f, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "reviewer a", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		userA = u.ID.String()
		target := f.A.IDs["bob"]
		id, err := c.InsertReviewItemEvent(&store.ReviewItemEvent{ItemID: itemA, Kind: store.ReviewEventConsult, ActorUserID: userA, Actor: "a",
			TargetIdentityID: &target, Note: "question", At: storetest.Now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.InsertReviewItemEvent(&store.ReviewItemEvent{ItemID: itemA, Kind: "bogus", ActorUserID: userA, Actor: "a", Note: "x", At: storetest.Now}); err == nil {
			t.Error("an unknown event kind was stored")
		}
		if e, err := c.ReviewItemEvent(id); err != nil || e.Note != "question" || e.TargetIdentityID == nil {
			t.Errorf("A's event: %+v %v", e, err)
		}
		if evs, err := c.ReviewItemEvents(itemA); err != nil || len(evs) != 1 {
			t.Errorf("A's events: %v %v", evs, err)
		}
		if open, err := c.OpenReviewConsultations(target); err != nil || len(open) != 1 {
			t.Errorf("A's open consultations: %v %v", open, err)
		}
		if ok, err := c.TransitionCampaign(campA, store.CampaignOpen, store.CampaignOpen, store.CampaignLocked); err != nil || !ok {
			t.Errorf("A locks: %v %v", ok, err)
		}
		if err := c.PutCampaignLock(&store.CampaignLock{CampaignID: campA, LockedBy: "a", Reason: "r", LockedAt: storetest.Now, ExpiresAt: storetest.Now.Add(time.Hour)}); err != nil {
			t.Errorf("A's lock record: %v", err)
		}
		if l, err := c.CampaignLock(campA); err != nil || l.Reason != "r" {
			t.Errorf("A's lock: %+v %v", l, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "reviewer b", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		userB = u.ID.String()
		if evs, err := c.ReviewItemEvents(itemA); err != nil || len(evs) != 0 {
			t.Errorf("B reads A's events: %v %v", evs, err)
		}
		if _, err := c.ReviewItemEvent(1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's event by id: %v", err)
		}
		if _, err := c.CampaignLock(campA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's lock: %v", err)
		}
		if err := c.PutCampaignLock(&store.CampaignLock{CampaignID: campA, LockedBy: "b", Reason: "x", LockedAt: storetest.Now, ExpiresAt: storetest.Now}); err == nil {
			t.Error("B locked A's campaign record")
		}
		if err := c.DeleteCampaignLock(campA); err != nil {
			t.Errorf("B's delete: %v", err)
		}
		if open, err := c.OpenReviewConsultations(f.A.IDs["bob"]); err != nil || len(open) != 0 {
			t.Errorf("B lists A's open consultations: %v %v", open, err)
		}
		if ok, err := c.TransitionCampaign(campA, store.CampaignLocked, store.CampaignLocked, store.CampaignClosed); err != nil || ok {
			t.Errorf("B closes A's campaign: %v %v", ok, err)
		}
		// B cannot attach an event to A's item, nor name A's user or person
		if _, err := c.InsertReviewItemEvent(&store.ReviewItemEvent{ItemID: itemA, Kind: store.ReviewEventConsult, ActorUserID: userB, Actor: "b",
			Note: "x", At: storetest.Now}); err == nil {
			t.Error("B added an event to A's item")
		}
		if _, err := c.InsertReviewItemEvent(&store.ReviewItemEvent{ItemID: itemB, Kind: store.ReviewEventConsult, ActorUserID: userA, Actor: "b",
			Note: "x", At: storetest.Now}); err == nil {
			t.Error("B's event names A's user")
		}
		other := f.A.IDs["bob"]
		if _, err := c.InsertReviewItemEvent(&store.ReviewItemEvent{ItemID: itemB, Kind: store.ReviewEventConsult, ActorUserID: userB, Actor: "b",
			TargetIdentityID: &other, Note: "x", At: storetest.Now}); err == nil {
			t.Error("B's event names A's identity")
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if _, err := c.CampaignLock(campA); err != nil {
			t.Errorf("A's lock after B's attempts: %v", err)
		}
		if cmp, err := c.Campaign(campA); err != nil || cmp.Status != store.CampaignLocked {
			t.Errorf("A's campaign after B's attempt: %+v %v", cmp, err)
		}
		return nil
	})
}

// reviewActionsCovered lists the methods TestIsolation_ReviewActions exercises.
func reviewActionsCovered() map[string]bool {
	return map[string]bool{"InsertReviewItemEvent": true, "ReviewItemEvents": true, "ReviewItemEvent": true,
		"OpenReviewConsultations": true, "TransitionCampaign": true, "PutCampaignLock": true, "CampaignLock": true, "DeleteCampaignLock": true}
}
