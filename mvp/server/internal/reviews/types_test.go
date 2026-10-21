package reviews_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Review types (issue #298): settings validation, who reviews under each type,
// and what happens at the due date.

func TestTypeSettings_Check(t *testing.T) {
	fb := int64(5)
	ok := reviews.TypeSettings{Type: reviews.TypeApplicationOwner, Enabled: true, ReviewerSource: reviews.SourceOwner,
		OnIncomplete: reviews.IncompleteRevoke, EscalationDays: 7}
	for name, tc := range map[string]struct {
		mod  func(*reviews.TypeSettings)
		code string
	}{
		"valid":                     {func(*reviews.TypeSettings) {}, ""},
		"valid escalate":            {func(s *reviews.TypeSettings) { s.OnIncomplete, s.FallbackID = reviews.IncompleteEscalate, &fb }, ""},
		"valid keep":                {func(s *reviews.TypeSettings) { s.OnIncomplete = reviews.IncompleteKeep }, ""},
		"unknown type":              {func(s *reviews.TypeSettings) { s.Type = "friends" }, "review_type_not_found"},
		"unknown source":            {func(s *reviews.TypeSettings) { s.ReviewerSource = "anyone" }, "invalid_reviewer_source"},
		"fixed without reviewer":    {func(s *reviews.TypeSettings) { s.ReviewerSource = reviews.SourceFixed }, "reviewer_required"},
		"unknown outcome":           {func(s *reviews.TypeSettings) { s.OnIncomplete = "ignore" }, "invalid_on_incomplete"},
		"escalate without fallback": {func(s *reviews.TypeSettings) { s.OnIncomplete = reviews.IncompleteEscalate }, "fallback_required"},
		"escalation days low":       {func(s *reviews.TypeSettings) { s.EscalationDays = 0 }, "invalid_escalation_days"},
		"escalation days high":      {func(s *reviews.TypeSettings) { s.EscalationDays = 31 }, "invalid_escalation_days"},
	} {
		s := ok
		tc.mod(&s)
		err := s.Check()
		var ce *cfgerr.Error
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.code != "" && (!errors.As(err, &ce) || ce.Code != tc.code):
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	if len(reviews.Types) != 6 {
		t.Errorf("types = %d", len(reviews.Types))
	}
}

func TestSaveType_PeopleVersionAndAudit(t *testing.T) {
	s := newSched(t)
	carol, bob := s.f.B.IDs["carol"], s.f.B.IDs["bob"]
	set := reviews.DefaultTypeSettings(reviews.TypeEntitlementOwner)
	set.FallbackID = &carol
	s.tx(func(c *store.TenantTx) error {
		saved, ver, err := reviews.SaveType(c, set, 0, "admin", s.now)
		if err != nil || ver != 1 || saved.FallbackID == nil {
			t.Fatalf("save: %+v %d %v", saved, ver, err)
		}
		if _, _, err := reviews.SaveType(c, set, 0, "admin", s.now); err == nil {
			t.Error("a stale version saved")
		}
		bad := set
		bad.FallbackID = new(int64)
		*bad.FallbackID = 987654
		if _, _, err := reviews.SaveType(c, bad, 1, "admin", s.now); err == nil {
			t.Error("an unknown fallback reviewer saved")
		}
		fixed := set
		fixed.ReviewerSource, fixed.ReviewerID = reviews.SourceFixed, &bob
		if _, ver, err := reviews.SaveType(c, fixed, 1, "admin", s.now); err != nil || ver != 2 {
			t.Errorf("fixed reviewer: %d %v", ver, err)
		}
		// a reviewer is kept only while the source uses it
		back := set
		back.ReviewerID = &bob
		if saved, _, err := reviews.SaveType(c, back, 2, "admin", s.now); err != nil || saved.ReviewerID != nil {
			t.Errorf("a stale reviewer kept: %+v %v", saved, err)
		}
		log, err := c.AuditEvents(store.AuditFilter{Action: "review.type.update"})
		if err != nil || len(log) != 3 {
			t.Errorf("audit events: %d %v", len(log), err)
		}
		return nil
	})
}

func ident(id int64, kind, status string, mgr, owner *int64, dept string) *store.Identity {
	i := &store.Identity{ID: id, Type: kind, Status: status, ManagerID: mgr, OwnerID: owner}
	if dept != "" {
		i.Department = &dept
	}
	return i
}

func TestResolver_WhoReviews(t *testing.T) {
	// the resolver's reads come from the tenant's rows; build it from the fixture
	s := newSched(t)
	carol, bob, alice := s.f.B.IDs["carol"], s.f.B.IDs["bob"], s.f.B.IDs["alice"]
	var people map[int64]*store.Identity
	s.tx(func(c *store.TenantTx) (err error) {
		people, _, err = c.IdentityMap()
		if err != nil {
			return err
		}
		// bob owns app "okta" with carol as backup; carol owns an entitlement
		for _, o := range []*store.Ownership{
			{Kind: store.OwnedApp, Key: "okta", PrimaryID: &bob, BackupID: &carol, UpdatedAt: s.now},
			{Kind: store.OwnedApp, Key: "github", PrimaryID: nil, BackupID: &carol, UpdatedAt: s.now},
		} {
			if err := c.PutOwnership(o); err != nil {
				return err
			}
		}
		return nil
	})
	aliceID := people[alice]
	dst := func(system string) *graph.Node { return &graph.Node{System: system, Kind: "group"} }
	mk := func(typ, source string, fixed, fallback *int64) *reviews.Resolver {
		set := reviews.DefaultTypeSettings(typ)
		set.ReviewerSource, set.ReviewerID, set.FallbackID = source, fixed, fallback
		var r *reviews.Resolver
		s.tx(func(c *store.TenantTx) (err error) { r, err = reviews.NewResolver(c, set, people); return })
		return r
	}
	who := func(i *store.Identity) int64 {
		if i == nil {
			return 0
		}
		return i.ID
	}
	// application owner: the primary, else (owner_or_backup) the backup, else the fallback
	if got := who(mk(reviews.TypeApplicationOwner, reviews.SourceOwner, nil, nil).ForGrant(aliceID, dst("okta"))); got != bob {
		t.Errorf("application owner = %d, want bob %d", got, bob)
	}
	if got := who(mk(reviews.TypeApplicationOwner, reviews.SourceOwner, nil, nil).ForGrant(aliceID, dst("github"))); got != 0 {
		t.Errorf("owner source with no primary = %d, want nobody (the caller's default)", got)
	}
	if got := who(mk(reviews.TypeApplicationOwner, reviews.SourceOwnerOrBackup, nil, nil).ForGrant(aliceID, dst("github"))); got != carol {
		t.Errorf("owner or backup = %d, want carol", got)
	}
	if got := who(mk(reviews.TypeApplicationOwner, reviews.SourceOwner, nil, &carol).ForGrant(aliceID, dst("unowned"))); got != carol {
		t.Errorf("fallback = %d, want carol", got)
	}
	if got := who(mk(reviews.TypeApplicationOwner, reviews.SourceFixed, &bob, &carol).ForGrant(aliceID, dst("github"))); got != bob {
		t.Errorf("fixed = %d, want bob", got)
	}
	// user manager: the person's manager; machine identities are not in scope
	m := mk(reviews.TypeUserManager, reviews.SourceOwner, nil, nil)
	if !m.Includes(aliceID) || m.Includes(ident(900, "service", "active", nil, nil, "")) {
		t.Error("the user manager type covers people only")
	}
	if aliceID.ManagerID != nil {
		if got := who(m.ForGrant(aliceID, dst("okta"))); got != *aliceID.ManagerID {
			t.Errorf("manager = %d, want %d", got, *aliceID.ManagerID)
		}
	}
	// service account: machine identities only; the owner on the identity
	sa := mk(reviews.TypeServiceAccount, reviews.SourceOwner, nil, nil)
	svc := ident(901, "service", "active", nil, &bob, "")
	if sa.Includes(aliceID) || !sa.Includes(svc) {
		t.Error("the service account type covers machine identities only")
	}
	if got := who(sa.ForGrant(svc, dst("okta"))); got != bob {
		t.Errorf("service account owner = %d, want bob", got)
	}
	// role owner reviews memberships
	ro := mk(reviews.TypeRoleOwner, reviews.SourceOwner, nil, nil)
	if got := who(ro.ForRole(&store.BusinessRole{OwnerIdentityID: &carol})); got != carol {
		t.Errorf("role owner = %d", got)
	}
	if got := ro.ForGrant(aliceID, dst("okta")); got != nil {
		t.Errorf("role owner type picked a grant reviewer: %v", got)
	}
	// organization owner: an owner of the person's department
	oo := mk(reviews.TypeOrganizationOwner, reviews.SourceOwnerOrBackup, nil, &carol)
	if got := oo.ForGrant(aliceID, dst("okta")); got == nil {
		t.Error("organization owner: nobody (the fallback should at least answer)")
	}
}

func TestSchedule_ReviewTypeSettingsDriveCloseOut(t *testing.T) {
	carol := func(s *sched) int64 { return s.f.B.IDs["carol"] }
	run := func(t *testing.T, onIncomplete string) (*sched, *store.ReviewLaunch, reviews.TickResult) {
		s := newSched(t)
		s.template(nil)
		set := reviews.DefaultTypeSettings(reviews.TypeUserManager)
		set.OnIncomplete = onIncomplete
		set.EscalationDays = 3
		c := carol(s)
		set.FallbackID = &c
		s.tx(func(tx *store.TenantTx) error {
			if _, _, err := reviews.SaveType(tx, set, 0, "admin", s.now); err != nil {
				return err
			}
			return reviews.SetTemplateType(tx, "t1", reviews.TypeUserManager)
		})
		s.tick(s.now)
		ls := s.launches()
		if len(ls) != 1 {
			t.Fatalf("launches = %d", len(ls))
		}
		return s, ls[0], s.tick(ls[0].DueAt.Add(time.Minute))
	}
	t.Run("keep leaves the access and closes the review", func(t *testing.T) {
		s, l, r := run(t, reviews.IncompleteKeep)
		if r.Closed != 1 || r.Revoked != 0 {
			t.Fatalf("keep: %+v", r)
		}
		s.tx(func(c *store.TenantTx) error {
			items, err := c.CampaignItems(l.CampaignID)
			for _, it := range items {
				if it.Decision != nil {
					t.Errorf("item %d was decided: %v", it.ID, *it.Decision)
				}
				if _, err := c.EdgeBetween(it.EdgeSrc, it.EdgeDst); err != nil {
					t.Errorf("kept grant %s → %s is gone: %v", it.EdgeSrc, it.EdgeDst, err)
				}
			}
			return err
		})
		if got := s.launches()[0]; got.ClosedAt == nil {
			t.Error("the launch is not closed")
		}
	})
	t.Run("escalate goes to the fallback for the type's days", func(t *testing.T) {
		s, l, r := run(t, reviews.IncompleteEscalate)
		if r.Escalated != 1 || r.Revoked != 0 {
			t.Fatalf("escalate: %+v", r)
		}
		if got := s.launches()[0]; !got.DueAt.Equal(l.DueAt.Add(time.Minute).Add(3 * 24 * time.Hour)) {
			t.Errorf("escalated due = %v", got.DueAt)
		}
	})
	t.Run("revoke is what every review did before", func(t *testing.T) {
		_, _, r := run(t, reviews.IncompleteRevoke)
		if r.Closed != 1 || r.Revoked == 0 {
			t.Errorf("revoke: %+v", r)
		}
	})
	t.Run("a turned-off type launches nothing", func(t *testing.T) {
		s := newSched(t)
		s.template(nil)
		set := reviews.DefaultTypeSettings(reviews.TypeApplicationOwner)
		s.tx(func(c *store.TenantTx) error {
			if err := reviews.SetTemplateType(c, "t1", reviews.TypeApplicationOwner); err != nil {
				return err
			}
			set.Enabled = false
			_, _, err := reviews.SaveType(c, set, 0, "admin", s.now)
			return err
		})
		if r := s.tick(s.now); r.Launched != 0 {
			t.Errorf("launched %+v", r)
		}
		s.tx(func(c *store.TenantTx) error {
			if err := reviews.SetTemplateType(c, "t1", reviews.TypeApplicationOwner); err == nil {
				t.Error("a template was typed with a turned-off type")
			}
			return nil
		})
	})
	t.Run("an owner-based campaign routes items to owners", func(t *testing.T) {
		s := newSched(t)
		s.template(nil)
		bob := s.f.B.IDs["bob"]
		var systems []string
		s.tx(func(c *store.TenantTx) error {
			gs, err := c.Groups()
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			for _, g := range gs {
				if !seen[g.System] {
					seen[g.System] = true
					systems = append(systems, g.System)
					if err := c.PutOwnership(&store.Ownership{Kind: store.OwnedApp, Key: g.System, PrimaryID: &bob, UpdatedAt: s.now}); err != nil {
						return err
					}
				}
			}
			return reviews.SetTemplateType(c, "t1", reviews.TypeApplicationOwner)
		})
		s.tick(s.now)
		l := s.launches()[0]
		s.tx(func(c *store.TenantTx) error {
			items, err := c.CampaignItems(l.CampaignID)
			if len(items) == 0 {
				t.Fatal("no items")
			}
			for _, it := range items {
				if it.ReviewerID == nil || *it.ReviewerID != bob {
					t.Errorf("item %d reviewer %v, want bob (the application owner)", it.ID, it.ReviewerID)
				}
			}
			return err
		})
	})
}
