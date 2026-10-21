package svcaccounts_test

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// One person with two sign-in users files a create naming themselves owner (the owner stage is
// their consent) and approves the decider stage from the other user: refused (issue #415).
func TestCreate_LinkedUserCannotApproveOwnRequest(t *testing.T) {
	e := setup(t)
	bob2 := requests.Actor{Display: "Bob (second)", IdentityID: e.bob.IdentityID, Decider: true}
	e.tx(func(c *store.TenantTx) error {
		pu := &store.PlatformUser{DisplayName: bob2.Display, IdentityID: bob2.IdentityID, CreatedAt: e.now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		bob2.UserID = pu.ID
		return nil
	})
	q := e.createBy(e.bob, "svc-linked")
	if _, err := e.approve(bob2, q.ID, e.now); code(err) != "self_approval" {
		t.Errorf("the requester's other user approves: %v", err)
	}
	if got := e.get(q.ID); got.Status != store.SAPending {
		t.Errorf("status = %s", got.Status)
	}
	if _, err := e.approve(e.pat, q.ID, e.now); err != nil {
		t.Errorf("a different person approves: %v", err)
	}
}
