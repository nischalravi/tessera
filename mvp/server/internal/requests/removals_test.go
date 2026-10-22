package requests_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// carolAsManager makes carol alice's manager and returns carol and a user
// who is neither (bob's login).
func (w *world) managerAndStranger() (carol, bob requests.Actor) {
	w.tx(func(c *store.TenantTx) error {
		a, cr, bb := w.ids["alice"], w.ids["carol"], w.ids["bob"]
		if err := c.SetIdentityManager(a, &cr); err != nil {
			return err
		}
		for _, u := range []struct {
			out   *requests.Actor
			name  string
			ident *int64
		}{{&carol, "Carol", &cr}, {&bob, "Bob", &bb}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: w.now}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.out = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		return nil
	})
	return carol, bob
}

func (w *world) removalOf(acct, group string) (*store.GrantEdge, int64) {
	w.t.Helper()
	e := w.edge(acct, group)
	if e == nil {
		w.t.Fatalf("no edge %s -> %s in the fixture", acct, group)
	}
	return e, e.ID
}

func (w *world) submitRemoval(by requests.Actor, others bool, edge int64, just string) (*store.RemovalRequest, error) {
	var q *store.RemovalRequest
	var err error
	w.tx(func(c *store.TenantTx) error {
		q, err = requests.SubmitRemoval(c, edge, just, by, others, w.now)
		return nil
	})
	return q, err
}

func (w *world) decideRemoval(fn func(c *store.TenantTx) (*store.RemovalRequest, error)) (*store.RemovalRequest, error) {
	var q *store.RemovalRequest
	var err error
	w.tx(func(c *store.TenantTx) error {
		q, err = fn(c)
		return nil
	})
	return q, err
}

func TestRemoval_SubmitRules(t *testing.T) {
	tests := []struct {
		name    string
		by      func(w *world) requests.Actor
		others  bool
		unknown bool
		just    string
		want    string
	}{
		{"own access", func(w *world) requests.Actor { return w.alice }, false, false, "no longer needed", ""},
		{"no justification", func(w *world) requests.Actor { return w.alice }, false, false, "  ", "justification_required"},
		{"someone else's access", func(w *world) requests.Actor { return w.pat }, false, false, "cleanup", "for_others_not_allowed"},
		{"for others when allowed", func(w *world) requests.Actor { return w.pat }, true, false, "cleanup", ""},
		{"unknown grant", func(w *world) requests.Actor { return w.alice }, false, true, "x", "grant_not_found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			_, edge := w.removalOf("acct:okta:alice", "group:okta:eng")
			if tc.unknown {
				edge = 999999
			}
			q, err := w.submitRemoval(tc.by(w), tc.others, edge, tc.just)
			if got := code(err); got != tc.want {
				t.Fatalf("code = %q, want %q (%v)", got, tc.want, err)
			}
			if tc.want == "" && (q.Status != store.RequestPending || q.BeneficiaryID != w.ids["alice"]) {
				t.Errorf("request = %+v", q)
			}
		})
	}
}

func TestRemoval_OnePendingPerGrant(t *testing.T) {
	w := newWorld(t)
	_, eng := w.removalOf("acct:okta:alice", "group:okta:eng")
	if _, err := w.submitRemoval(w.alice, false, eng, "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.submitRemoval(w.alice, false, eng, "second"); code(err) != "already_requested" {
		t.Errorf("second = %v", err)
	}
}

func TestRemoval_NotRemovableSources(t *testing.T) {
	w := newWorld(t)
	for _, src := range []string{"jit", "role"} {
		var id int64
		w.tx(func(c *store.TenantTx) error {
			var err error
			exp := w.now.Add(time.Hour)
			e := &store.GrantEdge{Src: "account:" + itoa(w.ids["acct:okta:alice"]), Dst: "group:" + itoa(w.ids["group:aws:ProdAdmin"]),
				Relation: "member_of", Source: src, CreatedAt: w.now}
			if src == "jit" {
				e.ExpiresAt = &exp
			} else {
				e.Dst = "group:" + itoa(w.ids["group:snowflake:PII_READER"])
			}
			id, err = c.InsertEdge(e)
			return err
		})
		if _, err := w.submitRemoval(w.alice, false, id, "x"); code(err) != "not_removable" {
			t.Errorf("%s edge: %v", src, err)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestRemoval_Decisions(t *testing.T) {
	t.Run("the manager approves and the grant is removed with a tombstone", func(t *testing.T) {
		w := newWorld(t)
		carol, _ := w.managerAndStranger()
		e, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, err := w.submitRemoval(w.alice, false, id, "no longer needed")
		if err != nil {
			t.Fatal(err)
		}
		out, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, carol, "ok", w.now)
		})
		if err != nil || out.Status != store.RequestApproved || out.Outcome == nil || *out.Outcome != requests.OutcomeRevoked {
			t.Fatalf("approve = %+v, %v", out, err)
		}
		if w.edge("acct:okta:alice", "group:okta:eng") != nil {
			t.Error("the grant is still there after approval")
		}
		var tombs []*store.RevokedGrant
		w.tx(func(c *store.TenantTx) error { var err error; tombs, err = c.RevokedGrants(); return err })
		found := false
		for _, r := range tombs {
			found = found || (r.Src == e.Src && r.Dst == e.Dst)
		}
		if !found {
			t.Error("no tombstone: a sync would bring the grant back")
		}
	})

	t.Run("who may decide", func(t *testing.T) {
		w := newWorld(t)
		carol, bob := w.managerAndStranger()
		_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, _ := w.submitRemoval(w.alice, false, id, "x")
		for _, tc := range []struct {
			name string
			by   requests.Actor
			want string
		}{
			{"the requester", w.alice, "self_approval"},
			{"someone with no authority", bob, "not_an_approver"},
			{"the manager", carol, ""},
		} {
			_, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
				return requests.DenyRemoval(c, q.ID, tc.by, "not now", w.now)
			})
			if got := code(err); got != tc.want {
				t.Errorf("%s: deny = %q, want %q", tc.name, got, tc.want)
			}
		}
		// it is decided now: nobody decides it twice
		if _, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, w.pat, "", w.now)
		}); code(err) != "not_pending" {
			t.Errorf("approve of a denied request = %v", err)
		}
		if w.edge("acct:okta:alice", "group:okta:eng") == nil {
			t.Error("a denied removal removed the grant")
		}
	})

	t.Run("a denial needs a reason; a decider may approve", func(t *testing.T) {
		w := newWorld(t)
		_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, _ := w.submitRemoval(w.alice, false, id, "x")
		if _, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.DenyRemoval(c, q.ID, w.pat, "", w.now)
		}); code(err) != "reason_required" {
			t.Errorf("deny without reason = %v", err)
		}
		if _, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, w.pat, "", w.now)
		}); err != nil {
			t.Errorf("decider approve = %v", err)
		}
	})

	t.Run("an unlinked decider is refused", func(t *testing.T) {
		w := newWorld(t)
		_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, _ := w.submitRemoval(w.alice, false, id, "x")
		unlinked := w.pat
		unlinked.IdentityID = nil
		if _, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, unlinked, "", w.now)
		}); code(err) != "approver_unlinked" {
			t.Errorf("unlinked approve = %v", err)
		}
		w.tx(func(c *store.TenantTx) error {
			if ok, err := requests.CanDecideRemoval(c, q, unlinked, w.now); err != nil || ok {
				t.Errorf("CanDecideRemoval for an unlinked decider = %v, %v", ok, err)
			}
			return nil
		})
	})

	t.Run("only the requester cancels", func(t *testing.T) {
		w := newWorld(t)
		_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, _ := w.submitRemoval(w.alice, false, id, "x")
		if _, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.CancelRemoval(c, q.ID, w.pat, w.now)
		}); code(err) != "request_not_found" {
			t.Errorf("cancel by another = %v", err)
		}
		if out, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.CancelRemoval(c, q.ID, w.alice, w.now)
		}); err != nil || out.Status != store.RequestCancelled {
			t.Errorf("cancel = %+v, %v", out, err)
		}
	})

	t.Run("the grant already gone is closed as already removed", func(t *testing.T) {
		w := newWorld(t)
		_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
		q, _ := w.submitRemoval(w.alice, false, id, "x")
		w.tx(func(c *store.TenantTx) error { return c.DeleteEdge(id, time.Now()) })
		out, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, w.pat, "", w.now)
		})
		if err != nil || out.Outcome == nil || *out.Outcome != requests.OutcomeAlreadyRemoved {
			t.Errorf("approve = %+v, %v", out, err)
		}
	})

	t.Run("a grant from an approved request ends that request", func(t *testing.T) {
		w := newWorld(t)
		lines, err := w.submit(w.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.tx(func(c *store.TenantTx) error {
			_, err := requests.Approve(c, lines[0].ID, w.pat, "", w.now)
			return err
		})
		_, id := w.removalOf("acct:okta:alice", "group:okta:platform")
		q, err := w.submitRemoval(w.alice, false, id, "no longer needed")
		if err != nil {
			t.Fatal(err)
		}
		out, err := w.decideRemoval(func(c *store.TenantTx) (*store.RemovalRequest, error) {
			return requests.ApproveRemoval(c, q.ID, w.pat, "", w.now)
		})
		if err != nil || out.Outcome == nil || *out.Outcome != requests.OutcomeRequestRemoved {
			t.Fatalf("approve = %+v, %v", out, err)
		}
		w.tx(func(c *store.TenantTx) error {
			l, err := c.RequestLine(lines[0].ID)
			if err != nil || l.Status != store.RequestRemoved {
				t.Errorf("the access request is %v (%v), want removed", l, err)
			}
			return nil
		})
		if w.edge("acct:okta:alice", "group:okta:platform") != nil {
			t.Error("the grant is still there")
		}
	})
}

func TestRemoval_TenantScoped(t *testing.T) {
	w := newWorld(t)
	_, id := w.removalOf("acct:okta:alice", "group:okta:eng")
	// tenant A's alice cannot be reached with tenant B's edge id
	err := w.f.DB.InTenant(t.Context(), w.f.A.ID, func(c *store.TenantTx) error {
		_, err := requests.SubmitRemoval(c, id, "x", requests.Actor{UserID: w.alice.UserID}, true, w.now)
		return err
	})
	var re *requests.Error
	if !errors.As(err, &re) || re.Code != "grant_not_found" {
		t.Errorf("another tenant's edge = %v", err)
	}
}
