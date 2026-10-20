package requests_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notifications from the request flow (issue #189): the approvers hear when a
// stage needs them, the requester and the beneficiary hear the outcome, and
// every notification commits with the change that caused it.

func (r *routed) notes(a requests.Actor, kind string) []*store.Notification {
	r.t.Helper()
	var out []*store.Notification
	r.tx(func(c *store.TenantTx) error {
		ns, err := c.Notifications(a.UserID.String(), false, -1)
		for _, n := range ns {
			if kind == "" || n.Kind == kind {
				out = append(out, n)
			}
		}
		return err
	})
	return out
}

func (r *routed) decide(a requests.Actor, id string, deny bool, at time.Time) {
	r.t.Helper()
	r.tx(func(c *store.TenantTx) error {
		var err error
		if deny {
			_, err = requests.Deny(c, id, a, "not needed for this project", at)
		} else {
			_, err = requests.Approve(c, id, a, "", at)
		}
		if err != nil {
			r.t.Fatal(err)
		}
		return nil
	})
}

func TestNotify_ApprovalChainTellsEachApproverInTurnAndThenTheRequester(t *testing.T) {
	r := newRouted(t) // manager (carol) -> owner (bob) -> decider
	grantRole(r, r.pat, "operator")
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	count := func(a requests.Actor, kind string) int { return len(r.notes(a, kind)) }

	if count(r.carol, notify.KindApprovalNeeded) != 1 {
		t.Fatalf("the manager was not told: %+v", r.notes(r.carol, ""))
	}
	n := r.notes(r.carol, notify.KindApprovalNeeded)[0]
	if n.Link != "/inbox" || n.Subject == "" || !n.InApp {
		t.Errorf("notification = %+v", n)
	}
	if count(r.bob, "")+count(r.pat, "")+count(r.alice, "") != 0 {
		t.Error("someone other than the manager was told of the first stage")
	}

	r.decide(r.carol, id, false, r.now)
	if count(r.bob, notify.KindApprovalNeeded) != 1 {
		t.Fatal("the owner was not told when the owner stage began")
	}
	if count(r.carol, notify.KindApprovalNeeded) != 1 || count(r.alice, "") != 0 {
		t.Error("an approved stage must not tell the requester or the approver again")
	}

	r.decide(r.bob, id, false, r.now)
	if count(r.pat, notify.KindApprovalNeeded) != 1 {
		t.Fatal("the decider was not told of the decider stage")
	}

	r.decide(r.pat, id, false, r.now)
	got := r.notes(r.alice, notify.KindRequestApproved)
	if len(got) != 1 { // alice is both the requester and the beneficiary: one notification
		t.Fatalf("alice has %d approved notices, want 1", len(got))
	}
	if count(r.pat, notify.KindRequestApproved) != 0 {
		t.Error("the deciding approver was told of their own decision")
	}
}

func TestNotify_DenialCarriesTheReason(t *testing.T) {
	r := newRouted(t, "decider")
	grantRole(r, r.pat, "operator")
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.decide(r.pat, lines[0].ID, true, r.now)
	got := r.notes(r.alice, notify.KindRequestDenied)
	if len(got) != 1 || !contains(got[0].Body, "not needed for this project") {
		t.Fatalf("denial notices = %+v", got)
	}
	if len(r.notes(r.alice, notify.KindRequestApproved)) != 0 {
		t.Error("a denial also said approved")
	}
}

// TestNotify_RolledBackSubmitLeavesNoNotification: the notification is part
// of the request's transaction.
func TestNotify_RolledBackSubmitLeavesNoNotification(t *testing.T) {
	r := newRouted(t)
	boom := errors.New("later step failed")
	err := r.f.DB.InTenant(context.Background(), r.f.B.ID, func(c *store.TenantTx) error {
		_, _, err := requests.Submit(c, requests.Submission{Beneficiaries: []int64{r.ids["alice"]},
			Items: []string{r.items["group:okta:platform"]}, Justification: "x"}, r.alice, false, r.now)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(r.notesIn(c, r.carol)); n != 1 {
			t.Fatalf("inside the transaction carol has %d notices, want 1", n)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if n := len(r.notes(r.carol, "")); n != 0 {
		t.Errorf("a rolled-back submit left %d notice(s)", n)
	}
}

func (r *routed) notesIn(c *store.TenantTx, a requests.Actor) []*store.Notification {
	ns, err := c.Notifications(a.UserID.String(), false, -1)
	if err != nil {
		r.t.Fatal(err)
	}
	return ns
}

// TestNotify_DelegateIsToldToo: a delegate who can act for the assignee hears
// when a stage needs them, and hears of the delegation itself.
func TestNotify_DelegateIsToldToo(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	r.tx(func(c *store.TenantTx) error {
		_, err := requests.Delegate(c, r.carol, r.zed.UserID.String(), r.now.Add(-time.Hour), r.now.Add(7*24*time.Hour), "on leave", r.now)
		return err
	})
	if got := r.notes(r.zed, notify.KindApprovalDelegated); len(got) != 1 || !contains(got[0].Body, "on leave") {
		t.Fatalf("delegation notices = %+v", got)
	}
	if _, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.notes(r.zed, notify.KindApprovalNeeded)) != 1 || len(r.notes(r.carol, notify.KindApprovalNeeded)) != 1 {
		t.Error("both the manager and her delegate should be told")
	}
}

// TestNotify_EscalationIsAnnouncedOnceToDeciders: a stage past its due time
// tells the deciders (and the assignee), and a repeat scan tells no one again.
func TestNotify_EscalationIsAnnouncedOnceToDeciders(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	grantRole(r, r.pat, "operator")
	if _, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil); err != nil {
		t.Fatal(err)
	}
	scan := func(at time.Time) (n int) {
		r.tx(func(c *store.TenantTx) error {
			rows, err := notify.Scan(c, at)
			if err != nil {
				return err
			}
			n, err = notify.Write(c, rows)
			return err
		})
		return n
	}
	if n := scan(r.now.Add(47 * time.Hour)); n != 0 {
		t.Errorf("before the due time the scan wrote %d", n)
	}
	if n := scan(r.now.Add(49 * time.Hour)); n != 2 { // the decider and the assignee (carol)
		t.Errorf("after the due time the scan wrote %d, want 2", n)
	}
	if len(r.notes(r.pat, notify.KindApprovalEscalated)) != 1 || len(r.notes(r.carol, notify.KindApprovalEscalated)) != 1 {
		t.Error("the decider and the assignee should each have one escalation notice")
	}
	if n := scan(r.now.Add(60 * time.Hour)); n != 0 {
		t.Errorf("a repeat scan wrote %d", n)
	}
	if len(r.notes(r.alice, "")) != 0 {
		t.Error("the requester was told of an internal escalation")
	}
}

// TestNotify_NoAssigneeGoesStraightToDeciders: a stage nobody can act as is
// due at once; the deciders (but not the requester) are told it needs them,
// and no escalation follows, because it never waited for anyone.
func TestNotify_NoAssigneeGoesStraightToDeciders(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	olu := r.decider()
	grantRole(r, r.pat, "operator")
	grantRole(r, olu, "operator")
	r.tx(func(c *store.TenantTx) error {
		return requests.SetPolicy(c, r.items["group:snowflake:PII_READER"], []string{"manager", "decider"}, 48, r.pat, r.now)
	})
	eight := 8.0
	if _, err := r.submit(r.pat, true, []string{"carol"}, []string{"group:snowflake:PII_READER"}, &eight); err != nil { // carol has no manager
		t.Fatal(err)
	}
	if got := r.notes(olu, notify.KindApprovalNeeded); len(got) != 1 {
		t.Errorf("the other decider has %d notices, want 1", len(got))
	}
	if got := r.notes(r.pat, ""); len(got) != 0 {
		t.Errorf("the requester was asked to approve their own request: %+v", got)
	}
	r.tx(func(c *store.TenantTx) error {
		rows, err := notify.Scan(c, r.now.Add(72*time.Hour))
		for _, n := range rows {
			if n.Kind == notify.KindApprovalEscalated {
				t.Errorf("a stage that was due at once was escalated: %+v", n)
			}
		}
		return err
	})
}

func grantRole(r *routed, a requests.Actor, role string) {
	r.t.Helper()
	r.tx(func(c *store.TenantTx) error {
		return c.InsertRoleAssignment(&store.RoleAssignment{UserID: a.UserID, Role: role, Source: "manual", CreatedAt: r.now})
	})
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
