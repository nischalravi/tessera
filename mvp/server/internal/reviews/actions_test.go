package reviews_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func acode(err error) string {
	var ae *reviews.ActionError
	if errors.As(err, &ae) {
		return ae.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

// Consult, reassign, lock and close on a launched campaign.
func TestActions_ConsultReassignLockClose(t *testing.T) {
	s := newSched(t)
	s.template(nil)
	s.tick(s.now)
	l := s.launches()[0]

	var item *store.ReviewItem
	actors := map[string]reviews.Actor{}
	var people []int64
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(l.CampaignID)
		if err != nil || len(items) == 0 {
			t.Fatalf("items: %v %v", items, err)
		}
		item = items[0]
		for _, n := range []string{"alice", "bob", "carol"} {
			id := s.f.B.IDs[n]
			if id == item.IdentityID {
				continue
			}
			u := &store.PlatformUser{DisplayName: n, IdentityID: &id, CreatedAt: s.now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: string(auth.RoleOperator), Source: store.RoleSourceManual, CreatedAt: s.now}); err != nil {
				return err
			}
			actors[n] = reviews.Actor{User: store.UserRef{ID: u.ID, Display: n}, IdentityID: &id}
			people = append(people, id)
		}
		return c.SetItemReviewer(item.ID, people[0])
	})
	if len(people) < 2 {
		t.Skip("fixture has too few people")
	}
	var reviewer, other reviews.Actor
	for n, a := range actors {
		if *a.IdentityID == people[0] {
			reviewer = a
		} else if other.IdentityID == nil {
			other = a
		}
		_ = n
	}
	// a manager is a real user (the events table references platform_users)
	var manager reviews.Actor
	s.tx(func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "mgr", CreatedAt: s.now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		manager = reviews.Actor{User: store.UserRef{ID: u.ID, Display: "mgr"}, Manager: true}
		return nil
	})
	run := func(fn func(c *store.TenantTx) error) error {
		var e error
		s.tx(func(c *store.TenantTx) error { e = fn(c); return nil })
		return e
	}

	// consult: only the reviewer (or a manager); not oneself, not the subject
	consult := func(by reviews.Actor, target int64, q string) error {
		return run(func(c *store.TenantTx) error { _, err := reviews.Consult(c, s.now, item.ID, by, target, q); return err })
	}
	if err := consult(other, *reviewer.IdentityID, "hi"); acode(err) != reviews.ErrCodeNotYours {
		t.Errorf("a stranger consults: %v", err)
	}
	if err := consult(reviewer, *reviewer.IdentityID, "hi"); acode(err) != reviews.ErrCodeBadPerson {
		t.Errorf("consult oneself: %v", err)
	}
	if err := consult(reviewer, item.IdentityID, "hi"); acode(err) != reviews.ErrCodeBadPerson {
		t.Errorf("consult the subject: %v", err)
	}
	if err := consult(reviewer, *other.IdentityID, " "); acode(err) != "invalid_question" {
		t.Errorf("empty question: %v", err)
	}
	if err := consult(reviewer, *other.IdentityID, strings.Repeat("q", reviews.MaxActionNote+1)); acode(err) != "invalid_question" {
		t.Errorf("long question: %v", err)
	}
	var ask *store.ReviewItemEvent
	if err := run(func(c *store.TenantTx) (err error) {
		ask, err = reviews.Consult(c, s.now, item.ID, reviewer, *other.IdentityID, "is this still needed?")
		return
	}); err != nil {
		t.Fatalf("consult: %v", err)
	}
	if err := consult(reviewer, *other.IdentityID, "again"); acode(err) != "already_asked" {
		t.Errorf("asked twice: %v", err)
	}
	s.tx(func(c *store.TenantTx) error {
		open, err := c.OpenReviewConsultations(*other.IdentityID)
		if err != nil || len(open) != 1 || open[0].Note != "is this still needed?" {
			t.Errorf("open consultations: %v %v", open, err)
		}
		return nil
	})
	// answer: only the person asked, once
	answer := func(by reviews.Actor, text string) error {
		return run(func(c *store.TenantTx) error { _, err := reviews.Answer(c, s.now, ask.ID, by, text); return err })
	}
	if err := answer(reviewer, "me?"); acode(err) != "consultation_not_found" {
		t.Errorf("wrong person answers: %v", err)
	}
	if err := answer(other, ""); acode(err) != "invalid_answer" {
		t.Errorf("empty answer: %v", err)
	}
	if err := answer(other, "yes, keep it"); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if err := answer(other, "again"); acode(err) != "already_answered" {
		t.Errorf("answered twice: %v", err)
	}
	s.tx(func(c *store.TenantTx) error {
		if open, _ := c.OpenReviewConsultations(*other.IdentityID); len(open) != 0 {
			t.Errorf("still open: %v", open)
		}
		if it, _ := c.Item(item.ID); it.Decision != nil {
			t.Error("an answer decided the item")
		}
		return nil
	})

	// reassign
	reassign := func(by reviews.Actor, to int64, why string) error {
		return run(func(c *store.TenantTx) error { _, err := reviews.Reassign(c, s.now, item.ID, by, to, why); return err })
	}
	if err := reassign(other, *other.IdentityID, "mine now"); acode(err) != reviews.ErrCodeNotYours {
		t.Errorf("a stranger reassigns: %v", err)
	}
	if err := reassign(reviewer, *reviewer.IdentityID, "x"); acode(err) != "same_reviewer" {
		t.Errorf("same reviewer: %v", err)
	}
	var viewerID int64
	s.tx(func(c *store.TenantTx) error {
		id, err := newViewerPerson(c, s.now)
		viewerID = id
		return err
	})
	if err := reassign(reviewer, viewerID, "x"); acode(err) != reviews.ErrCodeBadPerson {
		t.Errorf("to someone who cannot decide reviews: %v", err)
	}
	if err := reassign(reviewer, item.IdentityID, "x"); acode(err) != reviews.ErrCodeBadPerson {
		t.Errorf("to the subject: %v", err)
	}
	if err := reassign(reviewer, *other.IdentityID, ""); acode(err) != "invalid_reason" {
		t.Errorf("no reason: %v", err)
	}
	if err := reassign(reviewer, *other.IdentityID, "knows the system better"); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if err := reassign(manager, *reviewer.IdentityID, "back"); err != nil {
		t.Errorf("a manager reassigns: %v", err)
	}
	s.tx(func(c *store.TenantTx) error {
		evs, _ := c.ReviewItemEvents(item.ID)
		kinds := ""
		for _, e := range evs {
			kinds += e.Kind + ","
		}
		if kinds != "consult,answer,reassign,reassign," {
			t.Errorf("events = %s", kinds)
		}
		return nil
	})

	// lock refuses decisions, a locked schedule waits; unlock resumes
	change := func(action, reason string) error {
		return run(func(c *store.TenantTx) error {
			_, err := reviews.ChangeCampaign(c, s.now, l.CampaignID, action, store.UserRef{Display: "mgr"}, reason)
			return err
		})
	}
	decide := func() error {
		return run(func(c *store.TenantTx) error {
			_, _, err := reviews.DecideItem(c, s.now, item.ID, "keep", store.UserRef{Display: "rev"}, nil, "")
			return err
		})
	}
	if err := change("lock", ""); acode(err) != "reason_required" {
		t.Errorf("lock without a reason: %v", err)
	}
	if err := change("unlock", ""); acode(err) != "invalid_state" {
		t.Errorf("unlock an open review: %v", err)
	}
	if err := change("lock", "audit in progress"); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := change("lock", "again"); acode(err) != "invalid_state" {
		t.Errorf("lock twice: %v", err)
	}
	if err := decide(); acode(err) != reviews.ErrCodeLocked {
		t.Errorf("decide while locked: %v", err)
	}
	if err := consult(manager, *other.IdentityID, "q"); acode(err) != reviews.ErrCodeLocked {
		t.Errorf("consult while locked: %v", err)
	}
	if r := s.tick(l.DueAt.Add(-time.Hour)); r.Closed != 0 || r.Revoked != 0 {
		t.Errorf("a locked review's deadline ran: %+v", r)
	}
	if err := change("unlock", ""); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := decide(); err != nil {
		t.Errorf("decide after unlock: %v", err)
	}

	// a scheduled review that revokes what nobody decided cannot be closed by hand while items are open
	if err := change("close", "scope changed"); acode(err) != "open_items_need_decision" {
		t.Errorf("close with open items under a revoke policy: %v", err)
	}

	// a lock is not indefinite: past MaxLock the next pass lifts it and the deadline logic resumes
	if err := change("lock", "legal hold"); err != nil {
		t.Fatalf("lock again: %v", err)
	}
	s.tx(func(c *store.TenantTx) error {
		lk, err := c.CampaignLock(l.CampaignID)
		if err != nil || !lk.ExpiresAt.Equal(s.now.Add(reviews.MaxLock)) {
			t.Errorf("lock record: %+v %v", lk, err)
		}
		return nil
	})
	late := s.now.Add(reviews.MaxLock + time.Hour)
	if r := s.tick(late); r.Closed != 1 || r.Revoked == 0 {
		t.Errorf("after the lock ran out: %+v", r)
	}
	s.tx(func(c *store.TenantTx) error {
		cmp, _ := c.Campaign(l.CampaignID)
		if cmp.Status == store.CampaignLocked {
			t.Error("still locked after it ran out")
		}
		if _, err := c.CampaignLock(l.CampaignID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("lock record kept: %v", err)
		}
		return nil
	})

	// an ad-hoc campaign has no close-out policy: closing it is final and revokes nothing
	var adhoc int64
	s.tx(func(c *store.TenantTx) (err error) {
		adhoc, err = reviews.GenerateCampaign(c, s.now, "ad hoc", 60, s.ps)
		return
	})
	var first *store.ReviewItem
	s.tx(func(c *store.TenantTx) error {
		items, _ := c.CampaignItems(adhoc)
		if len(items) > 0 {
			first = items[0]
		}
		return nil
	})
	if first == nil {
		t.Skip("no ad-hoc items")
	}
	if err := run(func(c *store.TenantTx) error {
		_, err := reviews.ChangeCampaign(c, s.now, adhoc, "close", store.UserRef{Display: "mgr"}, "scope changed")
		return err
	}); err != nil {
		t.Fatalf("close an ad-hoc review: %v", err)
	}
	if err := run(func(c *store.TenantTx) error {
		_, err := reviews.ChangeCampaign(c, s.now, adhoc, "unlock", store.UserRef{Display: "mgr"}, "")
		return err
	}); acode(err) != "invalid_state" {
		t.Errorf("unlock a closed review: %v", err)
	}
	if err := run(func(c *store.TenantTx) error {
		_, _, err := reviews.DecideItem(c, s.now, first.ID, "revoke", store.UserRef{Display: "rev"}, nil, "")
		return err
	}); acode(err) != reviews.ErrCodeClosed {
		t.Errorf("decide on a closed review: %v", err)
	}
	s.tx(func(c *store.TenantTx) error {
		if it, _ := c.Item(first.ID); it.Decision != nil {
			t.Errorf("an undecided item was decided: %v", *it.Decision)
		}
		return nil
	})
}

// newViewerPerson makes an active person who can sign in but holds only the viewer role.
func newViewerPerson(c *store.TenantTx, now time.Time) (int64, error) {
	id, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "viewer-x", Name: "Viewer X", Type: "human", Status: "active", CreatedAt: now})
	if err != nil {
		return 0, err
	}
	u := &store.PlatformUser{DisplayName: "Viewer X", IdentityID: &id, CreatedAt: now}
	if err := c.InsertPlatformUser(u); err != nil {
		return 0, err
	}
	return id, c.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: string(auth.RoleViewer), Source: store.RoleSourceManual, CreatedAt: now})
}
