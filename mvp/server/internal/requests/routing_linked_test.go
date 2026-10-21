package requests_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// linkedTo adds a second platform user linked to the same identity as a (issue #415):
// one person with two sign-in users.
func (r *routed) linkedTo(a requests.Actor, name string) requests.Actor {
	r.t.Helper()
	b := requests.Actor{Display: name, IdentityID: a.IdentityID, Decider: a.Decider}
	r.tx(func(c *store.TenantTx) error {
		pu := &store.PlatformUser{DisplayName: name, IdentityID: a.IdentityID, CreatedAt: r.now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		b.UserID = pu.ID
		return nil
	})
	return b
}

// One person with two users approves two stages of one access request: refused.
func TestRouting_LinkedUsersCannotApproveTwoStages(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	r.carol.Decider = true
	carol2 := r.linkedTo(r.carol, "Carol (second)")
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(r.carol, lines[0].ID, r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(carol2, lines[0].ID, r.now); code(err) != "already_decided_a_stage" {
		t.Errorf("the same person's second user approves the next stage: %v", err)
	}
}

// A delegate cannot decide the request of the delegator's other user.
func TestRouting_LinkedDelegatorOwnRequest(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	carol2 := r.linkedTo(r.carol, "Carol (second)")
	r.tx(func(c *store.TenantTx) error {
		_, err := requests.Delegate(c, carol2, r.zed.UserID.String(), r.now.Add(-time.Hour), r.now.Add(24*time.Hour), "on leave", r.now)
		return err
	})
	own, err := r.submit(r.carol, true, []string{"bob"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(r.zed, own[0].ID, r.now); code(err) != "not_an_approver" {
		t.Errorf("delegate of the requester's other user: %v", err)
	}
}
