package requests_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The fixture is the tiny world (connectors.Tiny) in tenant B: alice is in
// okta:eng, bob in the payments groups, carol in platform and eng, dave is
// terminated; aws:ProdAdmin is privileged. Everyone has an okta account.

type world struct {
	t          *testing.T
	f          *storetest.Fixture
	ids        map[string]int64
	alice, pat requests.Actor // alice requests for herself; pat decides
	items      map[string]string
	now        time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, ids: f.B.IDs, items: map[string]string{}, now: storetest.Now}
	w.tx(func(c *store.TenantTx) error {
		alice := w.ids["alice"]
		for _, u := range []struct {
			a     *requests.Actor
			name  string
			ident *int64
		}{{&w.alice, "Alice", &alice}, {&w.pat, "Pat", nil}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: w.now}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.a = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		eight, max := 8.0, 72.0
		for key, spec := range map[string]requests.ItemSpec{
			"group:okta:platform":           {Requestable: true, Risk: "low"},
			"group:okta:payments-clerks":    {Requestable: true, Risk: "medium", EligibleDepartments: []string{"Finance"}},
			"group:aws:ProdAdmin":           {Requestable: true, Risk: "high", DefaultHours: &eight, MaxHours: &max},
			"group:snowflake:ANALYST":       {Requestable: false, Risk: "low"},
			"group:okta:eng":                {Requestable: true, Risk: "low", EligibleTypes: []string{"human"}},
			"group:snowflake:PII_READER":    {Requestable: true, Risk: "high", MaxHours: &max},
			"group:okta:payments-approvers": {Requestable: true, Risk: "medium", EligibleTypes: []string{"service"}},
		} {
			it, err := requests.PutItem(c, w.ids[key], spec, w.pat, w.now)
			if err != nil {
				return err
			}
			w.items[key] = it.ID
		}
		return nil
	})
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

func code(err error) string {
	var e *requests.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func (w *world) submit(by requests.Actor, others bool, bens []string, items []string, hours *float64) ([]*store.RequestLine, error) {
	var lines []*store.RequestLine
	var serr error
	w.tx(func(c *store.TenantTx) error {
		s := requests.Submission{Justification: "project Atlas", DurationHours: hours}
		for _, b := range bens {
			s.Beneficiaries = append(s.Beneficiaries, w.ids[b])
		}
		for _, i := range items {
			s.Items = append(s.Items, w.items[i])
		}
		_, lines, serr = requests.Submit(c, s, by, others, w.now)
		return nil
	})
	return lines, serr
}

func (w *world) edge(acct, group string) *store.GrantEdge {
	w.t.Helper()
	var e *store.GrantEdge
	w.tx(func(c *store.TenantTx) error {
		var err error
		e, err = c.EdgeBetween(graph.Key("account", w.ids[acct]), graph.Key("group", w.ids[group]))
		if errors.Is(err, store.ErrNotFound) {
			e, err = nil, nil
		}
		return err
	})
	return e
}

func TestRequest_SubmitApproveExpire(t *testing.T) {
	w := newWorld(t)
	lines, err := w.submit(w.alice, false, []string{"alice"}, []string{"group:okta:platform", "group:aws:ProdAdmin"}, nil)
	if err != nil || len(lines) != 2 {
		t.Fatalf("submit = %v, %v", lines, err)
	}
	if lines[0].DurationHours != nil || lines[1].DurationHours == nil || *lines[1].DurationHours != 8 {
		t.Errorf("durations: %v / %v (want until removed, then the item's 8h default)", lines[0].DurationHours, lines[1].DurationHours)
	}
	if lines[0].BatchID != lines[1].BatchID {
		t.Error("lines of one submission have different batch ids")
	}
	w.tx(func(c *store.TenantTx) error {
		for _, l := range lines {
			if _, err := requests.Approve(c, l.ID, w.pat, "", w.now); err != nil {
				return err
			}
		}
		return nil
	})
	plat := w.edge("acct:okta:alice", "group:okta:platform")
	prod := w.edge("acct:okta:alice", "group:aws:ProdAdmin")
	if plat == nil || plat.Source != "request" || plat.ExpiresAt != nil {
		t.Fatalf("platform grant = %+v", plat)
	}
	if prod == nil || prod.ExpiresAt == nil || !prod.ExpiresAt.Equal(w.now.Add(8*time.Hour)) {
		t.Fatalf("ProdAdmin grant = %+v", prod)
	}
	// 9 hours later the sweep closes the 8-hour line and removes its grant
	later := w.now.Add(9 * time.Hour)
	w.tx(func(c *store.TenantTx) error {
		n, err := requests.Sweep(c, later)
		if n != 1 {
			t.Errorf("swept %d, want 1", n)
		}
		return err
	})
	if w.edge("acct:okta:alice", "group:aws:ProdAdmin") != nil {
		t.Error("the expired grant is still there")
	}
	w.tx(func(c *store.TenantTx) error {
		l, err := c.RequestLine(lines[1].ID)
		if err != nil || l.Status != store.RequestExpired {
			t.Errorf("line = %+v, %v", l, err)
		}
		evs, err := c.RequestEvents(lines[1].ID)
		var got []string
		for _, e := range evs {
			got = append(got, e.Event)
		}
		if len(got) != 3 || got[0] != "submitted" || got[1] != "approved" || got[2] != "expired" {
			t.Errorf("events = %v", got)
		}
		if need, err := requests.NeedsSweep(c, later); err != nil || need {
			t.Errorf("still needs a sweep: %v %v", need, err)
		}
		return err
	})
}

func TestRequest_SubmitRefusals(t *testing.T) {
	w := newWorld(t)
	ten := 100.0
	cases := []struct {
		name   string
		by     requests.Actor
		others bool
		bens   []string
		items  []string
		hours  *float64
		want   string
	}{
		{"not requestable", w.alice, false, []string{"alice"}, []string{"group:snowflake:ANALYST"}, nil, "not_requestable"},
		{"department", w.alice, false, []string{"alice"}, []string{"group:okta:payments-clerks"}, nil, "not_eligible"},
		{"type", w.alice, false, []string{"alice"}, []string{"group:okta:payments-approvers"}, nil, "not_eligible"},
		{"already has it", w.alice, false, []string{"alice"}, []string{"group:okta:eng"}, nil, "already_has_access"},
		{"needs a duration", w.alice, false, []string{"alice"}, []string{"group:snowflake:PII_READER"}, nil, "duration_required"},
		{"too long", w.alice, false, []string{"alice"}, []string{"group:aws:ProdAdmin"}, &ten, "duration_too_long"},
		{"for someone else", w.alice, false, []string{"bob"}, []string{"group:okta:platform"}, nil, "for_others_not_allowed"},
		{"not active", w.pat, true, []string{"dave"}, []string{"group:okta:platform"}, nil, "beneficiary_not_active"},
		{"nothing", w.alice, false, nil, []string{"group:okta:platform"}, nil, "empty_request"},
		// all or nothing: one bad item refuses the good one too
		{"mixed", w.alice, false, []string{"alice"}, []string{"group:okta:platform", "group:snowflake:ANALYST"}, nil, "not_requestable"},
	}
	for _, tc := range cases {
		if _, err := w.submit(tc.by, tc.others, tc.bens, tc.items, tc.hours); code(err) != tc.want {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
	}
	w.tx(func(c *store.TenantTx) error {
		ls, err := c.RequestLines(store.RequestFilter{})
		if err == nil && len(ls) != 0 {
			t.Errorf("refused submissions left %d lines", len(ls))
		}
		return err
	})
	// a second request for something already requested
	if _, err := w.submit(w.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.submit(w.pat, true, []string{"alice"}, []string{"group:okta:platform"}, nil); code(err) != "already_requested" {
		t.Errorf("duplicate: %v", err)
	}
}

func TestRequest_DecisionRules(t *testing.T) {
	w := newWorld(t)
	// pat requests for alice and for bob
	lines, err := w.submit(w.pat, true, []string{"alice", "bob"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forAlice, forBob := lines[0], lines[1]
	other0 := requests.Actor{UserID: uuid.New(), Display: "Someone"}
	w.tx(func(c *store.TenantTx) error {
		if _, err := requests.Approve(c, forBob.ID, w.pat, "", w.now); code(err) != "self_approval" {
			t.Errorf("requester approves: %v", err)
		}
		if _, err := requests.Approve(c, forAlice.ID, w.alice, "", w.now); code(err) != "self_approval" {
			t.Errorf("beneficiary approves: %v", err)
		}
		if _, err := requests.Deny(c, forBob.ID, w.alice, " ", w.now); code(err) != "reason_required" {
			t.Errorf("deny without reason: %v", err)
		}
		if _, err := requests.Cancel(c, forBob.ID, w.alice, w.now); code(err) != "request_not_found" {
			t.Errorf("cancel someone else's: %v", err)
		}
		if _, err := requests.Deny(c, forBob.ID, w.alice, "not needed", w.now); err != nil {
			return err
		}
		if _, err := requests.Approve(c, forBob.ID, w.alice, "", w.now); code(err) != "not_pending" {
			t.Errorf("approve a denied line: %v", err)
		}
		// alice left before the decision
		if err := c.TerminateIdentity(w.ids["alice"], w.now); err != nil {
			return err
		}
		if _, err := requests.Approve(c, forAlice.ID, other0, "", w.now); code(err) != "beneficiary_not_active" {
			t.Errorf("approve for a leaver: %v", err)
		}
		_, err := requests.Cancel(c, forAlice.ID, w.pat, w.now)
		return err
	})
	// alice comes back; she asks again for herself; another approver grants; she removes it herself.
	// A connector sync no longer reverts a termination (UAT #134), so the rehire is set directly.
	w.tx(func(c *store.TenantTx) error {
		return c.SetIdentityStatus(w.ids["alice"], "active")
	})
	again, err := w.submit(w.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := requests.Actor{Display: "Olu"}
	w.tx(func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "Olu", CreatedAt: w.now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		other.UserID = u.ID
		if _, err := requests.Approve(c, again[0].ID, other, "ok", w.now); err != nil {
			return err
		}
		bob := w.ids["bob"]
		stranger := requests.Actor{UserID: uuid.New(), Display: "Bob", IdentityID: &bob}
		if _, err := requests.Remove(c, again[0].ID, stranger, false, "x", w.now); code(err) != "forbidden" {
			t.Errorf("someone else removes: %v", err)
		}
		_, err := requests.Remove(c, again[0].ID, w.alice, false, "", w.now)
		return err
	})
	if w.edge("acct:okta:alice", "group:okta:platform") != nil {
		t.Error("removed access is still granted")
	}
}

// A grant removed outside the request (an access review, a revoke) closes
// the line on the next sweep.
func TestRequest_SweepNoticesRemovedGrant(t *testing.T) {
	w := newWorld(t)
	lines, err := w.submit(w.alice, false, []string{"alice"}, []string{"group:okta:platform"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		l, err := requests.Approve(c, lines[0].ID, w.pat, "", w.now)
		if err != nil {
			return err
		}
		return c.DeleteEdge(*l.EdgeID)
	})
	w.tx(func(c *store.TenantTx) error {
		if n, err := requests.Sweep(c, w.now); err != nil || n != 1 {
			t.Errorf("sweep = %d, %v", n, err)
		}
		l, err := c.RequestLine(lines[0].ID)
		if err == nil && l.Status != store.RequestRemoved {
			t.Errorf("status = %s, want removed", l.Status)
		}
		return err
	})
}

func TestCatalog_PutItemRules(t *testing.T) {
	w := newWorld(t)
	one, two := 1.0, 2.0
	w.tx(func(c *store.TenantTx) error {
		for _, tc := range []struct {
			group string
			spec  requests.ItemSpec
			want  string
		}{
			{"group:okta:platform", requests.ItemSpec{Risk: "extreme"}, "invalid_risk"},
			{"group:okta:platform", requests.ItemSpec{Risk: "low", DefaultHours: &two, MaxHours: &one}, "invalid_duration"},
			{"group:aws:ProdAdmin", requests.ItemSpec{Requestable: true, Risk: "high"}, "privileged_needs_duration"},
			{"group:okta:platform", requests.ItemSpec{Risk: "low", EligibleTypes: []string{"robot"}}, "invalid_type"},
		} {
			if _, err := requests.PutItem(c, w.ids[tc.group], tc.spec, w.pat, w.now); code(err) != tc.want {
				t.Errorf("%+v: %v, want %s", tc.spec, err, tc.want)
			}
		}
		// an update keeps the item's id
		it, err := requests.PutItem(c, w.ids["group:okta:platform"], requests.ItemSpec{Requestable: false, Risk: "medium"}, w.pat, w.now)
		if err != nil {
			return err
		}
		if it.ID != w.items["group:okta:platform"] || it.Requestable {
			t.Errorf("updated item = %+v", it)
		}
		cat, err := requests.Catalog(c, true)
		for _, e := range cat {
			if e.Group.ID == w.ids["group:okta:platform"] || e.Group.ID == w.ids["group:snowflake:ANALYST"] {
				t.Errorf("non-requestable %s listed", e.Group.Name)
			}
		}
		return err
	})
}
