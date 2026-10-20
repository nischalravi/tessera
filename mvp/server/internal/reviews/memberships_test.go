package reviews_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Role memberships in reviews (issue #214), on the tiny world in tenant B:
// alice and carol are in Engineering, alice has okta:eng from the connector,
// and a role granting okta:platform gives alice a "role" grant.

var (
	pat      = roles.Actor{Display: "Pat"}
	reviewer = store.UserRef{Display: "Rita"}
)

func (s *sched) id(name string) int64 { return s.f.B.IDs[name] }

func (s *sched) group(name string) int64 { return s.f.B.IDs["group:"+name] }

// role creates a role granting okta:platform; with rule, to Engineering by birthright.
func (s *sched) role(name string, rule bool) string {
	s.t.Helper()
	spec := roles.Spec{Name: name, Risk: "medium", Entitlements: []int64{s.group("okta:platform")}, Note: "test"}
	if rule {
		spec.Birthright = &roles.Rule{Department: []string{"Engineering"}}
	}
	var id string
	s.tx(func(c *store.TenantTx) error {
		res, err := roles.Create(c, spec, pat, false, s.now)
		if err == nil {
			id = res.Role.ID
		}
		return err
	})
	return id
}

func (s *sched) assign(roleID, person string) {
	s.t.Helper()
	s.tx(func(c *store.TenantTx) error {
		_, err := roles.Assign(c, roleID, s.id(person), "test", pat, false, s.now)
		return err
	})
}

func (s *sched) campaign(scope reviews.Scope) int64 {
	s.t.Helper()
	var id int64
	s.tx(func(c *store.TenantTx) (err error) {
		id, err = reviews.GenerateScopedCampaign(c, s.now, "memberships", 60, s.ps, scope)
		return
	})
	return id
}

// memberItem finds the membership item of a person in a role.
func (s *sched) memberItem(camp int64, roleID, person string) *store.ReviewItem {
	s.t.Helper()
	var found *store.ReviewItem
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(camp)
		for _, it := range items {
			if ir, ierr := c.ReviewItemRole(it.ID); ierr == nil && ir.RoleID == roleID && it.IdentityID == s.id(person) {
				found = it
			}
		}
		return err
	})
	return found
}

func (s *sched) edgeSource(person, group string) string {
	s.t.Helper()
	var src string
	s.tx(func(c *store.TenantTx) error {
		e, err := c.EdgeBetween(graph.Key("account", s.id("acct:okta:"+person)), graph.Key("group", s.group(group)))
		if err == nil {
			src = e.Source
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return nil
	})
	return src
}

func (s *sched) isMember(roleID, person string) bool {
	s.t.Helper()
	var is bool
	s.tx(func(c *store.TenantTx) error {
		ms, err := c.RoleMembers(roleID)
		for _, m := range ms {
			is = is || m.IdentityID == s.id(person)
		}
		return err
	})
	return is
}

func (s *sched) decide(itemID int64, decision, choice string) (string, error) {
	s.t.Helper()
	var res string
	var derr error
	s.tx(func(c *store.TenantTx) error {
		_, res, derr = reviews.DecideItem(c, s.now, itemID, decision, reviewer, nil, choice)
		if derr != nil {
			return nil // keep the transaction: the refusal wrote nothing
		}
		return nil
	})
	return res, derr
}

func (s *sched) reconcile(roleID string) *roles.Plan {
	s.t.Helper()
	var p *roles.Plan
	s.tx(func(c *store.TenantTx) error {
		res, err := roles.Reconcile(c, roleID, pat, false, s.now)
		if err == nil {
			p = res.Plan
		}
		return err
	})
	return p
}

func (s *sched) audited(action string) bool {
	s.t.Helper()
	var found bool
	s.tx(func(c *store.TenantTx) error {
		evs, err := c.AuditLog(200)
		for _, e := range evs {
			found = found || e.Action == action
		}
		return err
	})
	return found
}

func TestMembership_ListedWithItsGrantsUnderIt(t *testing.T) {
	s := newSched(t)
	id := s.role("Platform", false)
	s.assign(id, "alice")
	if src := s.edgeSource("alice", "okta:platform"); src != "role" {
		t.Fatalf("alice platform source = %q", src)
	}
	camp := s.campaign(reviews.Scope{})
	it := s.memberItem(camp, id, "alice")
	if it == nil {
		t.Fatal("no membership item for alice")
	}
	s.tx(func(c *store.TenantTx) error {
		ir, err := c.ReviewItemRole(it.ID)
		if err != nil || ir.MemberSource != store.MemberManual {
			t.Errorf("item role = %+v, %v", ir, err)
		}
		items, err := c.CampaignItems(camp)
		for _, x := range items {
			// the role's grant is not a separate item
			if x.EdgeDst == graph.Key("group", s.group("okta:platform")) && x.IdentityID == s.id("alice") {
				t.Errorf("the role's grant is a separate item: %+v", x)
			}
		}
		return err
	})
}

func TestMembership_RevokeManualRemovesGrantsAndReconcileDoesNotRestore(t *testing.T) {
	s := newSched(t)
	id := s.role("Platform", false)
	s.assign(id, "alice")
	it := s.memberItem(s.campaign(reviews.Scope{}), id, "alice")
	if it == nil {
		t.Fatal("no membership item")
	}
	res, err := s.decide(it.ID, "revoke", "")
	if err != nil || res != store.ResolveUnassign {
		t.Fatalf("revoke = %q, %v", res, err)
	}
	if s.isMember(id, "alice") {
		t.Error("alice still holds the role")
	}
	if src := s.edgeSource("alice", "okta:platform"); src != "" {
		t.Errorf("the role's grant is still there (%s)", src)
	}
	// Reconcile does not restore what the reviewer revoked
	if p := s.reconcile(id); len(p.Steps) != 0 {
		t.Errorf("reconcile plan = %+v", p.Steps)
	}
	if src := s.edgeSource("alice", "okta:platform"); src != "" {
		t.Errorf("reconcile restored the grant (%s)", src)
	}
	// the role change and the review decision are both audited
	if !s.audited("role.unassign") || !s.audited("review.revoke") {
		t.Error("missing role.unassign or review.revoke audit event")
	}
	// a decision is final
	if _, err := s.decide(it.ID, "keep", ""); err == nil {
		t.Error("a decided item was decided again")
	}
}

func TestMembership_KeepChangesNothing(t *testing.T) {
	s := newSched(t)
	id := s.role("Platform", false)
	s.assign(id, "alice")
	it := s.memberItem(s.campaign(reviews.Scope{}), id, "alice")
	if _, err := s.decide(it.ID, "keep", ""); err != nil {
		t.Fatal(err)
	}
	if !s.isMember(id, "alice") || s.edgeSource("alice", "okta:platform") != "role" {
		t.Error("keep removed access")
	}
}

func TestMembership_RuleMemberNeedsAChoice(t *testing.T) {
	s := newSched(t)
	id := s.role("Engineer", true) // alice and carol by rule
	camp := s.campaign(reviews.Scope{})
	it := s.memberItem(camp, id, "alice")
	if it == nil {
		t.Fatal("no membership item for alice")
	}
	var ce *reviews.ChoiceRequiredError
	if _, err := s.decide(it.ID, "revoke", ""); !errors.As(err, &ce) {
		t.Fatalf("revoke without a choice = %v", err)
	}
	if !s.isMember(id, "alice") {
		t.Fatal("a refused revoke removed alice")
	}

	// exclude: removed with the grants only the role justified, and the rule honours it
	res, err := s.decide(it.ID, "revoke", reviews.ChoiceExclude)
	if err != nil || res != store.ResolveExclude {
		t.Fatalf("exclude = %q, %v", res, err)
	}
	if s.isMember(id, "alice") || s.edgeSource("alice", "okta:platform") != "" {
		t.Error("alice still holds the role or its grant")
	}
	if p := s.reconcile(id); p.Members != 0 || len(steps(p, roles.AddGrant)) != 0 {
		t.Errorf("reconcile re-added an excluded person: %+v", p.Steps)
	}
	if s.isMember(id, "alice") {
		t.Error("birthright evaluation ignored the exclusion")
	}
	s.tx(func(c *store.TenantTx) error {
		xs, err := c.RoleExclusions(id)
		if err != nil || len(xs) != 1 || !xs[0].Active() || xs[0].Version != 1 || xs[0].ReviewItemID == nil || *xs[0].ReviewItemID != it.ID {
			t.Errorf("exclusions = %+v, %v", xs, err)
		}
		// carol is still a rule member
		ms, _ := c.RoleMembers(id)
		if len(ms) != 1 || ms[0].IdentityID != s.id("carol") {
			t.Errorf("members = %+v", ms)
		}
		return nil
	})
	if !s.audited("role.exclude") {
		t.Error("no role.exclude audit event")
	}

	// taking the person off the list lets the rule assign them again, as a new version
	s.tx(func(c *store.TenantTx) error {
		v, err := roles.Unexclude(c, id, s.id("alice"), "mistake", pat, s.now)
		if err != nil || v != 2 {
			t.Errorf("Unexclude = %d, %v", v, err)
		}
		return nil
	})
	s.reconcile(id)
	if !s.isMember(id, "alice") {
		t.Error("alice was not assigned again once off the list")
	}
}

func TestMembership_RuleMemberFlagged(t *testing.T) {
	s := newSched(t)
	id := s.role("Engineer", true)
	it := s.memberItem(s.campaign(reviews.Scope{}), id, "alice")
	res, err := s.decide(it.ID, "revoke", reviews.ChoiceFlag)
	if err != nil || res != store.ResolveFlag {
		t.Fatalf("flag = %q, %v", res, err)
	}
	if !s.isMember(id, "alice") {
		t.Error("flagging removed alice")
	}
	if !s.audited("review.rule_flagged") {
		t.Error("no review.rule_flagged audit event")
	}
	s.tx(func(c *store.TenantTx) error {
		fl, err := c.FlaggedRoleItems(id)
		if err != nil || len(fl) != 1 || fl[0].ItemID != it.ID {
			t.Errorf("flagged = %+v, %v", fl, err)
		}
		return nil
	})
}

// An item generated before memberships were items: the grant a role made.
func TestMembership_OldStyleGrantRevokeIsConverted(t *testing.T) {
	for _, tc := range []struct {
		name, choice string
		rule         bool
		member, edge bool // after the revoke: still a member, grant still there
		err          bool
	}{
		{"manual", "", false, false, false, false},
		{"rule without a choice", "", true, true, true, true},
		{"rule excluded", reviews.ChoiceExclude, true, false, false, false},
		{"rule flagged", reviews.ChoiceFlag, true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSched(t)
			id := s.role("Platform", tc.rule)
			if !tc.rule {
				s.assign(id, "alice")
			}
			var item int64
			s.tx(func(c *store.TenantTx) error {
				camp, err := c.InsertCampaign(&store.ReviewCampaign{Name: "old", CreatedAt: s.now, Status: "open", UnusedDays: 60})
				if err != nil {
					return err
				}
				e, err := c.EdgeBetween(graph.Key("account", s.id("acct:okta:alice")), graph.Key("group", s.group("okta:platform")))
				if err != nil {
					return err
				}
				if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: camp, IdentityID: s.id("alice"), EdgeID: &e.ID,
					EdgeSrc: e.Src, EdgeDst: e.Dst, GrantLabel: "alice → platform", Reasons: []string{"unused_60d"},
					Context: []byte(`{}`)}); err != nil {
					return err
				}
				items, err := c.CampaignItems(camp)
				item = items[0].ID
				return err
			})
			_, err := s.decide(item, "revoke", tc.choice)
			if (err != nil) != tc.err {
				t.Fatalf("revoke = %v, want error %v", err, tc.err)
			}
			if got := s.isMember(id, "alice"); got != tc.member {
				t.Errorf("member = %v, want %v", got, tc.member)
			}
			if got := s.edgeSource("alice", "okta:platform") != ""; got != tc.edge {
				t.Errorf("grant present = %v, want %v", got, tc.edge)
			}
			if !tc.err && !tc.member {
				if p := s.reconcile(id); p.Adds != 0 {
					t.Errorf("reconcile restored the grant: %+v", p.Steps)
				}
			}
		})
	}
}

func steps(p *roles.Plan, action string) []roles.Step {
	var out []roles.Step
	for _, st := range p.Steps {
		if st.Action == action {
			out = append(out, st)
		}
	}
	return out
}

func TestMembership_CampaignScopedToRoles(t *testing.T) {
	s := newSched(t)
	eng := s.role("Engineer", true)
	other := s.role("Other", false)
	s.assign(other, "bob")

	camp := s.campaign(reviews.Scope{RoleIDs: []string{eng}})
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(camp)
		if err != nil {
			return err
		}
		// every member of the scoped role, whatever the risk, and nothing else
		if len(items) != 2 {
			t.Fatalf("items = %d, want alice and carol", len(items))
		}
		for _, it := range items {
			ir, err := c.ReviewItemRole(it.ID)
			if err != nil || ir.RoleID != eng {
				t.Errorf("item %d is not a membership of the scoped role: %+v, %v", it.ID, ir, err)
			}
		}
		return nil
	})
	if it := s.memberItem(camp, other, "bob"); it != nil {
		t.Error("an unscoped role was reviewed")
	}

	// a scope of roles that are gone reviews nothing (it does not widen to everything)
	none := s.campaign(reviews.Scope{RoleIDs: []string{"no-such-role"}})
	s.tx(func(c *store.TenantTx) error {
		if items, err := c.CampaignItems(none); err != nil || len(items) != 0 {
			t.Errorf("items for a gone role = %d, %v", len(items), err)
		}
		return nil
	})
}

func TestSchedule_ScopedToRoles(t *testing.T) {
	s := newSched(t)
	eng := s.role("Engineer", true)
	s.template(nil)
	s.tx(func(c *store.TenantTx) error {
		if _, err := reviews.ValidateRoleScope(c, []string{"no-such-role"}); err == nil {
			t.Error("an unknown role was accepted")
		}
		ids, err := reviews.ValidateRoleScope(c, []string{eng, eng})
		if err != nil || len(ids) != 1 {
			t.Errorf("ValidateRoleScope = %v, %v", ids, err)
		}
		return c.SetReviewTemplateRoles("t1", ids)
	})
	s.tick(s.now)
	l := s.launches()[0]
	s.tx(func(c *store.TenantTx) error {
		items, err := c.CampaignItems(l.CampaignID)
		if err != nil || len(items) != 2 {
			t.Fatalf("items = %d, %v", len(items), err)
		}
		return nil
	})
	// at the deadline a rule membership nobody decided is flagged, not removed
	r := s.tick(l.DueAt.Add(time.Minute))
	if r.Closed != 1 || r.Revoked != 2 {
		t.Fatalf("close-out = %+v", r)
	}
	if !s.isMember(eng, "alice") || !s.audited("review.rule_flagged") {
		t.Error("the close-out removed a rule member instead of flagging it")
	}
}

// Issue #365: the memberships a campaign certified, and what was decided on
// them, are in the frozen population, its hash and the auditor export.
func TestMembership_InPopulationAndExport(t *testing.T) {
	s := newSched(t)
	eng := s.role("Engineer", true) // rule role: alice and carol
	camp := s.campaign(reviews.Scope{RoleIDs: []string{eng}})
	if res, err := s.decide(s.memberItem(camp, eng, "alice").ID, "revoke", reviews.ChoiceExclude); err != nil || res != store.ResolveExclude {
		t.Fatalf("exclude alice = %q, %v", res, err)
	}
	if _, err := s.decide(s.memberItem(camp, eng, "carol").ID, "keep", ""); err != nil {
		t.Fatal(err)
	}
	s.tx(func(c *store.TenantTx) error {
		e, err := reviews.BuildExport(c, camp, s.now)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Rows) != 2 || e.Population.ItemCount != 2 || len(e.Decisions) != 2 || !e.HashMatch() {
			t.Fatalf("rows %d, item_count %d, decisions %d, hash match %v; want 2, 2, 2, true",
				len(e.Rows), e.Population.ItemCount, len(e.Decisions), e.HashMatch())
		}
		got := map[string]reviews.Decision{}
		for _, d := range e.Decisions {
			if d.Kind != "membership" || d.Row.InScopeReason != reviews.InScopeMembership || d.Row.EdgeID != 0 ||
				d.Row.System != reviews.MembershipSystem || d.Row.Entitlement != "Role Engineer" || d.Reviewer == "" && d.Decision == "open" {
				t.Errorf("unexpected membership decision %+v row %+v", d, d.Row)
			}
			got[d.Row.EdgeDst] = d
		}
		a, k := got["identity:"+strconv.FormatInt(s.id("alice"), 10)], got["identity:"+strconv.FormatInt(s.id("carol"), 10)]
		if a.Decision != "revoke" || a.RuleAction != store.ResolveExclude || a.Source != "reviewer" || a.DecidedAt == nil ||
			a.Verification != reviews.VerifyVerified {
			t.Errorf("alice's decision = %+v", a)
		}
		if k.Decision != "keep" || k.RuleAction != "" || k.Verification != reviews.VerifyNotApplicable {
			t.Errorf("carol's decision = %+v", k)
		}
		doc, err := e.JSON()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(doc)
		for _, want := range []string{`"kind":"membership"`, `"rule_action":"exclude"`, `"entitlement":"Role Engineer"`, "business-role memberships"} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("JSON export lacks %s", want)
			}
		}
		var buf bytes.Buffer
		if err := e.WriteCSV(&buf); err != nil {
			t.Fatal(err)
		}
		if lines := strings.Count(buf.String(), "\n"); lines != 3 || !strings.Contains(buf.String(), "Role Engineer") {
			t.Errorf("CSV has %d lines, want header and 2 members:\n%s", lines, buf.String())
		}
		// the hash covers the rows: a tampered membership row no longer matches
		rows, _ := c.PopulationRows(camp)
		rows[0].Entitlement = "Role Other"
		if h, err := reviews.PopulationHash(rows); err != nil || h == e.Population.PopulationHash {
			t.Errorf("hash did not change when a membership row changed (%v)", err)
		}
		return nil
	})
}
