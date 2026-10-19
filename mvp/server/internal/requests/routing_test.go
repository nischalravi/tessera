package requests_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Routing on the tiny world: alice and bob report to carol; carol has no
// manager. okta:platform is owned by bob and routed manager → owner → decider.

type routed struct {
	*world
	carol, bob, zed requests.Actor
	item            string
}

func newRouted(t *testing.T, stages ...string) *routed {
	t.Helper()
	r := &routed{world: newWorld(t), item: ""}
	r.item = r.items["group:okta:platform"]
	r.tx(func(c *store.TenantTx) error {
		for _, u := range []struct {
			a     *requests.Actor
			name  string
			ident string
		}{{&r.carol, "Carol", "carol"}, {&r.bob, "Bob", "bob"}, {&r.zed, "Zed", ""}} {
			pu := &store.PlatformUser{DisplayName: u.name, CreatedAt: r.now}
			if u.ident != "" {
				id := r.ids[u.ident]
				pu.IdentityID = &id
			}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.a = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: pu.IdentityID}
		}
		bob := r.ids["bob"]
		if _, err := requests.PutItem(c, r.ids["group:okta:platform"], requests.ItemSpec{Requestable: true, Risk: "medium",
			OwnerIdentityID: &bob}, r.pat, r.now); err != nil {
			return err
		}
		if len(stages) == 0 {
			stages = []string{"manager", "owner", "decider"}
		}
		return requests.SetPolicy(c, r.item, stages, 48, r.pat, r.now)
	})
	return r
}

func (r *routed) inbox(a requests.Actor, at time.Time) []string {
	var ids []string
	r.tx(func(c *store.TenantTx) error {
		ps, err := requests.Inbox(c, a, at)
		for _, p := range ps {
			ids = append(ids, p.Line.ID)
		}
		return err
	})
	return ids
}

func (r *routed) approve(a requests.Actor, id string, at time.Time) (*store.RequestLine, error) {
	var l *store.RequestLine
	var aerr error
	r.tx(func(c *store.TenantTx) error {
		l, aerr = requests.Approve(c, id, a, "", at)
		return nil
	})
	return l, aerr
}

func (r *routed) stages(id string) []*store.RequestStage {
	var ss []*store.RequestStage
	r.tx(func(c *store.TenantTx) (err error) { ss, err = c.RequestStages(id); return })
	return ss
}

func TestRouting_ManagerOwnerDecider(t *testing.T) {
	r := newRouted(t)
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := lines[0].ID
	if got := r.inbox(r.carol, r.now); len(got) != 1 || got[0] != id {
		t.Fatalf("carol's inbox = %v", got)
	}
	if got := r.inbox(r.bob, r.now); len(got) != 0 {
		t.Errorf("bob sees the manager stage: %v", got)
	}
	if _, err := r.approve(r.pat, id, r.now); code(err) != "not_an_approver" {
		t.Errorf("decider before escalation: %v", err)
	}
	l, err := r.approve(r.carol, id, r.now)
	if err != nil || l.Status != store.RequestPending {
		t.Fatalf("manager approves: %v %v", l, err)
	}
	if _, err := r.approve(r.carol, id, r.now); code(err) != "already_decided_a_stage" && code(err) != "not_an_approver" {
		t.Errorf("carol again: %v", err)
	}
	if l, err := r.approve(r.bob, id, r.now); err != nil || l.Status != store.RequestPending {
		t.Fatalf("owner approves: %v %v", l, err)
	}
	if l, err := r.approve(r.pat, id, r.now); err != nil || l.Status != store.RequestApproved {
		t.Fatalf("decider approves: %v %v", l, err)
	}
	if r.edge("acct:okta:alice", "group:okta:platform") == nil {
		t.Error("no grant after the last stage")
	}
	want := []string{"manager", "owner", "decider"}
	for i, s := range r.stages(id) {
		if s.Kind != want[i] || s.Status != store.StageApproved || s.DecidedBy == nil {
			t.Errorf("stage %d = %+v", i, s)
		}
	}
}

// The same person never approves two stages of one line.
func TestRouting_FourEyesAcrossStages(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	r.carol.Decider = true // carol could also act as a decider
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(r.carol, lines[0].ID, r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(r.carol, lines[0].ID, r.now); code(err) != "already_decided_a_stage" {
		t.Errorf("carol approves the decider stage too: %v", err)
	}
	if got := r.inbox(r.carol, r.now); len(got) != 0 {
		t.Errorf("carol's inbox still has it: %v", got)
	}
}

func TestRouting_EscalationAndNoAssignee(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	later := r.now.Add(49 * time.Hour)
	if got := r.inbox(r.pat, later); len(got) != 1 {
		t.Errorf("escalated stage not in the decider's inbox: %v", got)
	}
	if _, err := r.approve(r.pat, lines[0].ID, later); err != nil {
		t.Fatalf("decider on an escalated stage: %v", err)
	}
	// carol has no manager: the manager stage is due at once
	r.tx(func(c *store.TenantTx) error {
		return requests.SetPolicy(c, r.items["group:snowflake:PII_READER"], []string{"manager", "decider"}, 48, r.pat, r.now)
	})
	eight := 8.0
	other, err := r.submit(r.pat, true, []string{"carol"}, []string{"group:snowflake:PII_READER"}, &eight)
	if err != nil {
		t.Fatal(err)
	}
	olu := r.decider()
	if _, err := r.approve(olu, other[0].ID, r.now); err != nil {
		t.Errorf("decider on a stage without an assignee: %v", err)
	}
}

func TestRouting_Delegation(t *testing.T) {
	r := newRouted(t, "manager", "decider")
	var d *store.ApprovalDelegationRow
	r.tx(func(c *store.TenantTx) error {
		var err error
		if _, err = requests.Delegate(c, r.carol, r.carol.UserID.String(), r.now, r.now.Add(time.Hour), "x", r.now); code(err) != "self_delegation" {
			t.Errorf("self delegation: %v", err)
		}
		if _, err = requests.Delegate(c, r.carol, r.zed.UserID.String(), r.now, r.now.Add(100*24*time.Hour), "x", r.now); code(err) != "invalid_window" {
			t.Errorf("too long: %v", err)
		}
		d, err = requests.Delegate(c, r.carol, r.zed.UserID.String(), r.now.Add(-time.Hour), r.now.Add(7*24*time.Hour), "on leave", r.now)
		return err
	})
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.inbox(r.zed, r.now); len(got) != 1 {
		t.Fatalf("delegate's inbox = %v", got)
	}
	if _, err := r.approve(r.zed, lines[0].ID, r.now); err != nil {
		t.Fatalf("delegate approves: %v", err)
	}
	ss := r.stages(lines[0].ID)
	if ss[0].OnBehalfOf == nil || *ss[0].OnBehalfOf != r.carol.UserID.String() || *ss[0].DecidedBy != r.zed.UserID.String() {
		t.Errorf("stage = %+v", ss[0])
	}
	// carol requests for bob (her report): her delegate cannot approve her own request
	carolsOwn, err := r.submit(r.carol, true, []string{"bob"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.approve(r.zed, carolsOwn[0].ID, r.now); code(err) != "not_an_approver" {
		t.Errorf("delegate on the delegator's own request: %v", err)
	}
	// revoked: no longer acts
	r.tx(func(c *store.TenantTx) error {
		_, err := requests.RevokeDelegation(c, d.ID, r.carol, r.now)
		return err
	})
	if got := r.inbox(r.zed, r.now); len(got) != 0 {
		t.Errorf("revoked delegate still sees %v", got)
	}
}

func TestRouting_DenyAtFirstStage(t *testing.T) {
	r := newRouted(t)
	lines, err := r.submit(r.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.tx(func(c *store.TenantTx) error {
		l, err := requests.Deny(c, lines[0].ID, r.carol, "not on my team's plan", r.now)
		if err == nil && l.Status != store.RequestDenied {
			t.Errorf("status %s", l.Status)
		}
		return err
	})
	for _, s := range r.stages(lines[0].ID) {
		if s.Status == store.StageWaiting || s.Status == store.StageQueued {
			t.Errorf("stage %d still open: %s", s.Idx, s.Status)
		}
	}
}

func TestRouting_PolicyRules(t *testing.T) {
	r := newRouted(t)
	r.tx(func(c *store.TenantTx) error {
		for _, tc := range []struct {
			stages []string
			hours  float64
			want   string
		}{
			{nil, 48, "invalid_stages"},
			{[]string{"manager", "manager"}, 48, "invalid_stages"},
			{[]string{"cfo"}, 48, "invalid_stages"},
			{[]string{"manager"}, 0, "invalid_escalation"},
		} {
			if err := requests.SetPolicy(c, r.item, tc.stages, tc.hours, r.pat, r.now); code(err) != tc.want {
				t.Errorf("%v %v: %v, want %s", tc.stages, tc.hours, err, tc.want)
			}
		}
		return nil
	})
}

// decider is a fresh user holding requests.decide.
func (r *routed) decider() requests.Actor {
	var a requests.Actor
	r.tx(func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "Olu", CreatedAt: r.now}
		a = requests.Actor{UserID: u.ID, Display: "Olu", Decider: true}
		err := c.InsertPlatformUser(u)
		a.UserID = u.ID
		return err
	})
	return a
}
