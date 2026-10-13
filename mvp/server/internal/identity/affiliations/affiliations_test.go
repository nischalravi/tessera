package affiliations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

func day(n int) *time.Time {
	t := now.AddDate(0, 0, n)
	return &t
}

func aff(typ, status string, starts int, ends *time.Time) *store.Affiliation {
	return &store.Affiliation{Type: typ, Status: status, StartsAt: now.AddDate(0, 0, starts), EndsAt: ends}
}

// TestLifecycleState_DerivedFromAffiliations: a person is active while any
// affiliation is, expiring when the last active one ends within the notice
// window, and conversion (one ends, another starts) never leaves a gap.
func TestLifecycleState_DerivedFromAffiliations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		affs   []*store.Affiliation
		want   affiliations.State
	}{
		{"no affiliations", "active", nil, affiliations.StateNone},
		{"open-ended employee", "active", []*store.Affiliation{aff("employee", "active", -400, nil)}, affiliations.StateActive},
		{"guest far from its end", "active", []*store.Affiliation{aff("guest_visitor", "active", -2, day(20))}, affiliations.StateActive},
		{"guest ending in a week", "active", []*store.Affiliation{aff("guest_visitor", "active", -20, day(7))}, affiliations.StateExpiring},
		{"two guests, one open-ended", "active", []*store.Affiliation{
			aff("guest_visitor", "active", -20, day(3)), aff("employee", "active", -20, nil)}, affiliations.StateActive},
		{"two guests both ending soon", "active", []*store.Affiliation{
			aff("guest_visitor", "active", -20, day(3)), aff("contractor", "active", -20, day(10))}, affiliations.StateExpiring},
		{"the Michigan rule: one ends, the other keeps the person active", "active", []*store.Affiliation{
			aff("contractor", "ended", -90, day(-1)), aff("volunteer", "active", -30, day(200))}, affiliations.StateActive},
		{"not started yet", "active", []*store.Affiliation{aff("prehire", "pending", 30, nil)}, affiliations.StateProspect},
		{"active status with a future start reads as prospective", "active", []*store.Affiliation{aff("prehire", "active", 5, nil)}, affiliations.StateProspect},
		{"conversion: prehire ended, employee started", "active", []*store.Affiliation{
			aff("prehire", "ended", -60, day(-1)), aff("employee", "active", -1, nil)}, affiliations.StateActive},
		{"all ended", "active", []*store.Affiliation{aff("guest_visitor", "ended", -40, day(-10))}, affiliations.StateExpired},
		{"active past its end reads as expired until swept", "active", []*store.Affiliation{aff("guest_visitor", "active", -40, day(-1))}, affiliations.StateExpired},
		{"last one revoked", "active", []*store.Affiliation{
			aff("guest_visitor", "ended", -40, day(-30)), aff("contractor", "revoked", -20, day(-2))}, affiliations.StateRevoked},
		{"an older revoked one does not decide", "active", []*store.Affiliation{
			aff("contractor", "revoked", -40, day(-30)), aff("guest_visitor", "ended", -20, day(-2))}, affiliations.StateExpired},
		{"merged wins", "merged", []*store.Affiliation{aff("employee", "active", -400, nil)}, affiliations.StateMerged},
		{"merged without affiliations", "merged", nil, affiliations.StateMerged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := affiliations.Derive(tc.status, tc.affs, now, affiliations.DefaultNotice); got != tc.want {
				t.Errorf("Derive = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEffective(t *testing.T) {
	for name, tc := range map[string]struct {
		a    *store.Affiliation
		want string
	}{
		"running":             {aff("guest_visitor", "active", -1, day(5)), "active"},
		"end passed":          {aff("guest_visitor", "active", -9, day(-1)), "ended"},
		"end exactly now":     {aff("guest_visitor", "active", -9, day(0)), "ended"},
		"not started":         {aff("prehire", "pending", 3, nil), "pending"},
		"final stays final":   {aff("guest_visitor", "revoked", -9, day(5)), "revoked"},
		"ended stays ended":   {aff("employee", "ended", -9, nil), "ended"},
		"started, no end set": {aff("employee", "pending", -1, nil), "active"},
	} {
		if got := affiliations.Effective(tc.a, now); got != tc.want {
			t.Errorf("%s: Effective = %s, want %s", name, got, tc.want)
		}
	}
}

func inTenant(t *testing.T, f *storetest.Fixture, fn func(c *store.TenantTx) error) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err != nil {
		t.Fatal(err)
	}
}

func code(err error) string {
	var e *affiliations.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "other: " + err.Error()
}

func TestAdd(t *testing.T) {
	f := storetest.TwoTenants(t)
	alice := f.B.IDs["alice"]
	var machine int64
	inTenant(t, f, func(c *store.TenantTx) error {
		ids, err := c.Identities()
		for _, i := range ids {
			if i.Type != "human" {
				machine = i.ID
			}
		}
		return err
	})
	if machine == 0 {
		t.Fatal("fixture has no machine identity")
	}
	base := affiliations.AddInput{IdentityID: alice, Type: store.AffGuestVisitor, EndsAt: day(10), Reason: "conference"}
	with := func(mod func(*affiliations.AddInput)) affiliations.AddInput { in := base; mod(&in); return in }
	for _, tc := range []struct {
		name string
		in   affiliations.AddInput
		code string // empty: accepted
	}{
		{"visitor with an end", base, ""},
		{"visitor without an end", with(func(i *affiliations.AddInput) { i.EndsAt = nil }), "end_required"},
		{"alum may be open-ended", with(func(i *affiliations.AddInput) { i.Type, i.EndsAt = store.AffAlum, nil }), ""},
		{"employee is an HR fact", with(func(i *affiliations.AddInput) { i.Type = store.AffEmployee }), "type_not_manual"},
		{"prehire is an HR fact", with(func(i *affiliations.AddInput) { i.Type = store.AffPrehire }), "type_not_manual"},
		{"student is an SIS fact", with(func(i *affiliations.AddInput) { i.Type = store.AffStudent }), "type_not_manual"},
		{"unknown type", with(func(i *affiliations.AddInput) { i.Type = "wizard" }), "invalid_type"},
		{"no reason", with(func(i *affiliations.AddInput) { i.Reason = "  " }), "invalid_reason"},
		{"unknown person", with(func(i *affiliations.AddInput) { i.IdentityID = 987654 }), "not_found"},
		{"machine identity", with(func(i *affiliations.AddInput) { i.IdentityID = machine }), "not_a_person"},
		{"end before start", with(func(i *affiliations.AddInput) { i.EndsAt = day(-1) }), "invalid_end"},
		{"visitor over 30 days", with(func(i *affiliations.AddInput) { i.EndsAt = day(31) }), "exceeds_maximum"},
		{"contractor 200 days", with(func(i *affiliations.AddInput) { i.Type, i.EndsAt = store.AffContractor, day(200) }), ""},
		{"contractor over a year", with(func(i *affiliations.AddInput) { i.Type, i.EndsAt = store.AffContractor, day(400) }), "exceeds_maximum"},
		{"unknown population", with(func(i *affiliations.AddInput) { i.Population = "nowhere" }), "unknown_population"},
		{"start far in the past", with(func(i *affiliations.AddInput) { i.StartsAt = now.AddDate(0, -3, 0) }), "invalid_start"},
		{"start in the future is pending", with(func(i *affiliations.AddInput) { i.StartsAt = now.AddDate(0, 0, 3) }), ""},
		{"org unit too long", with(func(i *affiliations.AddInput) {
			for len(i.OrgUnit) <= affiliations.MaxOrgUnit {
				i.OrgUnit += "x"
			}
		}), "invalid_org_unit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
				in := tc.in
				a, err := affiliations.Add(c, in, now)
				if err != nil {
					return err
				}
				if a.Source != store.AffSourceManual {
					t.Errorf("source = %s, want manual", a.Source)
				}
				if a.Type == store.AffGuestVisitor && (a.Population == nil || *a.Population != "guest") {
					t.Errorf("population = %v, want the type's default", a.Population)
				}
				want := store.AffActive
				if a.StartsAt.After(now) {
					want = store.AffPending
				}
				if a.Status != want {
					t.Errorf("status = %s, want %s", a.Status, want)
				}
				return nil
			})
			if tc.code == "" && err != nil || tc.code != "" && code(err) != tc.code {
				t.Errorf("Add = %v, want %q", err, tc.code)
			}
		})
	}
}

func TestAdd_MergedIdentityRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	inTenant(t, f, func(c *store.TenantTx) error { return c.SetIdentityStatus(f.B.IDs["bob"], store.IdentityStatusMerged) })
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		_, err := affiliations.Add(c, affiliations.AddInput{IdentityID: f.B.IDs["bob"], Type: store.AffAlum, Reason: "x"}, now)
		return err
	})
	if code(err) != "identity_merged" {
		t.Errorf("Add on a merged identity = %v", err)
	}
}

func TestEnd(t *testing.T) {
	f := storetest.TwoTenants(t)
	var running, future *store.Affiliation
	inTenant(t, f, func(c *store.TenantTx) (err error) {
		running, err = affiliations.Add(c, affiliations.AddInput{IdentityID: f.B.IDs["alice"], Type: store.AffContractor,
			EndsAt: day(60), Reason: "x"}, now.Add(-time.Hour))
		if err != nil {
			return err
		}
		future, err = affiliations.Add(c, affiliations.AddInput{IdentityID: f.B.IDs["alice"], Type: store.AffVolunteer,
			StartsAt: now.AddDate(0, 0, 5), EndsAt: day(60), Reason: "x"}, now)
		return err
	})
	by := "user-1"
	inTenant(t, f, func(c *store.TenantTx) error {
		a, err := affiliations.End(c, running.ID, "  project over ", by, now)
		if err != nil || a.Status != store.AffEnded || a.EndsAt == nil || !a.EndsAt.Equal(now) || *a.EndReason != "project over" ||
			a.EndedBy == nil || *a.EndedBy != by {
			t.Errorf("End running = %+v, %v", a, err)
		}
		if _, err := affiliations.End(c, running.ID, "again", by, now); code(err) != "already_ended" {
			t.Errorf("End twice = %v", err)
		}
		a, err = affiliations.End(c, future.ID, "never started", by, now)
		if err != nil || a.Status != store.AffRevoked || !a.EndsAt.Equal(future.StartsAt) {
			t.Errorf("End not-yet-started = %+v, %v", a, err)
		}
		if _, err := affiliations.End(c, running.ID, "", by, now); code(err) != "invalid_reason" {
			t.Errorf("End without reason = %v", err)
		}
		if _, err := affiliations.End(c, "00000000-0000-4000-8000-00000000dead", "x", by, now); code(err) != "not_found" {
			t.Errorf("End unknown = %v", err)
		}
		// an HR affiliation ends in the HR system: an administrator may not end it
		hr := &store.Affiliation{ID: "00000000-0000-4000-8000-0000000000e1", IdentityID: f.B.IDs["alice"], Type: store.AffEmployee,
			Source: store.AffSourceHRIS, StartsAt: now.AddDate(-1, 0, 0), Status: store.AffActive, CreatedAt: now}
		if err := c.InsertAffiliation(hr); err != nil {
			return err
		}
		if _, err := affiliations.End(c, hr.ID, "left", by, now); code(err) != "type_not_manual" {
			t.Errorf("End HR employee = %v, want type_not_manual", err)
		}
		return nil
	})
	// an ended affiliation is history: the table refuses to change it
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.EndAffiliation(running.ID, store.AffRevoked, now, nil, "rewrite")
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("EndAffiliation on a final row = %v, want ErrNotFound", err)
	}
}

func TestPopulationFor(t *testing.T) {
	for typ, want := range map[string]string{store.AffGuestVisitor: "guest", store.AffContractor: "guest", store.AffAdmit: "applicant",
		store.AffPrehire: "prehire", store.AffPartner: "partner", store.AffAlum: "", store.AffEmployee: ""} {
		if got := affiliations.PopulationFor(typ); got != want {
			t.Errorf("PopulationFor(%s) = %q, want %q", typ, got, want)
		}
	}
}
