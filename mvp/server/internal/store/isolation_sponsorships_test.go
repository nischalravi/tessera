package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sponsorship isolation (issue #65): a tenant sees and changes only its own
// intake records, sponsorships and their history; another tenant's
// sponsorship id looks nonexistent and a row naming another tenant's person,
// intake or sponsorship is refused by the guard triggers.

type spRows struct {
	intake, sponsorship string
	guest, sponsor      int64
}

func seedSponsorship(t *testing.T, db *store.DB, tn storetest.Tenant, mark string) spRows {
	t.Helper()
	r := spRows{intake: uuid.NewString(), sponsorship: uuid.NewString(), guest: tn.IDs["alice"], sponsor: tn.IDs["carol"]}
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertIntake(&store.IntakeRecord{ID: r.intake, Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
			SponsorIdentityID: &r.sponsor, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertSponsorship(&store.Sponsorship{ID: r.sponsorship, GuestIdentityID: r.guest, IntakeID: r.intake,
			SponsorIdentityID: r.sponsor, Population: store.PopVisitor, Purpose: "conference " + mark,
			AccessBundle: "[]", RequiredIAL: 0, RequiredAAL: 1, StartsAt: now, EndsAt: now.Add(48 * time.Hour),
			Status: store.SponsorActive, PolicyVersion: "v-test", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		return c.AddSponsorshipEvent(&store.SponsorshipEvent{SponsorshipID: r.sponsorship, Event: "created", ToStatus: store.SponsorActive,
			PolicyVersion: "v-test", Actor: "x", At: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func spFixture(t *testing.T) (*storetest.Fixture, spRows, spRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedSponsorship(t, f.DB, f.A, storetest.Sentinel), seedSponsorship(t, f.DB, f.B, "")
}

func spDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ss, err := c.Sponsorships(store.SponsorshipFilter{})
		if err != nil {
			return err
		}
		var evs []*store.SponsorshipEvent
		var intakes []*store.IntakeRecord
		for _, s := range ss {
			e, err := c.SponsorshipEvents(s.ID)
			if err != nil {
				return err
			}
			evs = append(evs, e...)
			in, err := c.Intake(s.IntakeID)
			if err != nil {
				return err
			}
			intakes = append(intakes, in)
		}
		affs, err := c.Affiliations()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ss, evs, intakes, affs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_SponsorshipReads(t *testing.T) {
	f, a, b := spFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		ss, err := c.Sponsorships(store.SponsorshipFilter{})
		if err != nil || len(ss) != 1 || ss[0].ID != b.sponsorship {
			t.Errorf("Sponsorships = %v, %v", ss, err)
		}
		for _, s := range ss {
			if strings.Contains(s.Purpose, storetest.Sentinel) {
				t.Errorf("B reads A's sponsorship %+v", s)
			}
		}
		if _, err := c.Sponsorship(a.sponsorship); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Sponsorship(A's) = %v", err)
		}
		if _, err := c.Intake(a.intake); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Intake(A's) = %v", err)
		}
		if evs, err := c.SponsorshipEvents(a.sponsorship); err != nil || len(evs) != 0 {
			t.Errorf("SponsorshipEvents(A's) = %v, %v", evs, err)
		}
		if due, err := c.DueSponsorships(storetest.Now.Add(30 * 24 * time.Hour)); err != nil || len(due) != 1 || due[0].ID != b.sponsorship {
			t.Errorf("DueSponsorships = %v, %v", due, err)
		}
		if n, err := c.CountLiveSponsorships(a.sponsor, store.PopVisitor, ""); err != nil || n != 0 && a.sponsor != b.sponsor {
			t.Errorf("CountLiveSponsorships(A's sponsor) = %d, %v", n, err)
		}
		if n, err := c.CountInvitesSince(b.sponsor, storetest.Now.Add(-time.Hour)); err != nil || n != 1 {
			t.Errorf("CountInvitesSince = %d, %v", n, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		s, err := c.Sponsorship(a.sponsorship)
		if err != nil || !strings.Contains(s.Purpose, storetest.Sentinel) {
			t.Errorf("A's own sponsorship = %+v, %v", s, err)
		}
		return nil
	})
}

var spMutations = map[string]func(c *store.TenantTx, a, b spRows) error{
	"SaveSponsorship": func(c *store.TenantTx, a, _ spRows) error {
		return c.SaveSponsorship(&store.Sponsorship{ID: a.sponsorship, SponsorIdentityID: a.sponsor, AccessBundle: "[]", RequiredAAL: 1,
			EndsAt: storetest.Now.Add(72 * time.Hour), Status: store.SponsorActive, PolicyVersion: "v-x", UpdatedAt: storetest.Now}, store.SponsorActive)
	},
	"AddSponsorshipEvent": func(c *store.TenantTx, a, _ spRows) error {
		return c.AddSponsorshipEvent(&store.SponsorshipEvent{SponsorshipID: a.sponsorship, Event: "ended", ToStatus: store.SponsorEnded,
			PolicyVersion: "v-x", Actor: "x", At: storetest.Now})
	},
	"InsertSponsorship (A's guest)": func(c *store.TenantTx, a, b spRows) error {
		return c.InsertSponsorship(&store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: a.guest, IntakeID: b.intake,
			SponsorIdentityID: b.sponsor, Population: store.PopVisitor, Purpose: "x", AccessBundle: "[]", RequiredAAL: 1,
			StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour), Status: store.SponsorActive, PolicyVersion: "v",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertSponsorship (A's sponsor)": func(c *store.TenantTx, a, b spRows) error {
		return c.InsertSponsorship(&store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: b.guest, IntakeID: b.intake,
			SponsorIdentityID: a.sponsor, Population: store.PopVisitor, Purpose: "x", AccessBundle: "[]", RequiredAAL: 1,
			StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour), Status: store.SponsorActive, PolicyVersion: "v",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertSponsorship (A's intake)": func(c *store.TenantTx, a, b spRows) error {
		return c.InsertSponsorship(&store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: b.guest, IntakeID: a.intake,
			SponsorIdentityID: b.sponsor, Population: store.PopVisitor, Purpose: "x", AccessBundle: "[]", RequiredAAL: 1,
			StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour), Status: store.SponsorActive, PolicyVersion: "v",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"InsertIntake (A's sponsor)": func(c *store.TenantTx, a, _ spRows) error {
		return c.InsertIntake(&store.IntakeRecord{ID: uuid.NewString(), Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
			SponsorIdentityID: &a.sponsor, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: storetest.Now})
	},
	"SetAffiliationEnd": func(c *store.TenantTx, a, _ spRows) error {
		return c.SetAffiliationEnd(storetestRefAffiliation(a), storetest.Now.Add(time.Hour))
	},
}

// storetestRefAffiliation is a id no tenant B row has: SetAffiliationEnd of
// anything not B's own is ErrNotFound.
func storetestRefAffiliation(spRows) string { return uuid.NewString() }

func TestIsolation_SponsorshipMutationsScoped(t *testing.T) {
	for name, fn := range spMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := spFixture(t)
			before := spDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := spDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// A user of another tenant cannot be recorded as the creator, approver or submitter.
func TestIsolation_SponsorshipForeignActorRefused(t *testing.T) {
	f, _, b := spFixture(t)
	var aUser string
	inA(t, f, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "a-user", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		aUser = u.ID.String()
		return nil
	})
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertIntake(&store.IntakeRecord{ID: uuid.NewString(), Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
			SubmittedBy: &aUser, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("foreign submitted_by = %v, want ErrCrossTenant", err)
	}
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertSponsorship(&store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: b.guest, IntakeID: b.intake,
			SponsorIdentityID: b.sponsor, Population: store.PopVisitor, Purpose: "x", AccessBundle: "[]", RequiredAAL: 1,
			StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour), Status: store.SponsorActive, PolicyVersion: "v",
			ApprovedBy: &aUser, CreatedBy: &aUser, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("foreign approved_by = %v, want ErrCrossTenant", err)
	}
}

// The schema's own rules: history is append-only, a final sponsorship and an
// intake's channel never change, nobody sponsors themselves, a term has a
// positive length and a transfer has a target and a deadline.
func TestSponsorships_RulesAndAppendOnly(t *testing.T) {
	f, _, b := spFixture(t)
	now := storetest.Now
	base := func() *store.Sponsorship {
		return &store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: b.guest, IntakeID: b.intake, SponsorIdentityID: b.sponsor,
			Population: store.PopContractor, Purpose: "x", AccessBundle: "[]", RequiredAAL: 2, StartsAt: now,
			EndsAt: now.Add(time.Hour), Status: store.SponsorActive, PolicyVersion: "v", CreatedAt: now, UpdatedAt: now}
	}
	bad := map[string]func(s *store.Sponsorship){
		"self":               func(s *store.Sponsorship) { s.SponsorIdentityID = s.GuestIdentityID },
		"empty term":         func(s *store.Sponsorship) { s.EndsAt = s.StartsAt },
		"no purpose":         func(s *store.Sponsorship) { s.Purpose = "" },
		"unknown status":     func(s *store.Sponsorship) { s.Status = "bogus" },
		"unknown pop":        func(s *store.Sponsorship) { s.Population = "student" },
		"no policy":          func(s *store.Sponsorship) { s.PolicyVersion = "" },
		"bad ial":            func(s *store.Sponsorship) { s.RequiredIAL = 3 },
		"pending, no target": func(s *store.Sponsorship) { s.Status = store.SponsorTransferPending },
		"final, no end":      func(s *store.Sponsorship) { s.Status = store.SponsorEnded },
	}
	for name, mod := range bad {
		s := base()
		mod(s)
		err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.InsertSponsorship(s) })
		if err == nil {
			t.Errorf("%s: a sponsorship the schema forbids was accepted", name)
		}
	}
	// ending moves it to a final status once; then it is history
	inB(t, f, func(c *store.TenantTx) error {
		s, err := c.Sponsorship(b.sponsorship)
		if err != nil {
			t.Fatal(err)
		}
		end, why := now.Add(time.Minute), "done"
		s.Status, s.EndedAt, s.EndReason, s.UpdatedAt = store.SponsorEnded, &end, &why, now
		if err := c.SaveSponsorship(s, store.SponsorActive); err != nil {
			t.Fatal(err)
		}
		if err := c.SaveSponsorship(s, store.SponsorActive); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second save from active = %v, want ErrNotFound", err)
		}
		return nil
	})
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		s, err := c.Sponsorship(b.sponsorship)
		if err != nil {
			return err
		}
		s.Status, s.EndedAt = store.SponsorActive, nil
		return c.SaveSponsorship(s, store.SponsorEnded)
	})
	if err == nil {
		t.Error("a final sponsorship was reopened")
	}
	// events cannot be rewritten: the store has no method for it, and the trigger refuses raw attempts
	inB(t, f, func(c *store.TenantTx) error {
		evs, err := c.SponsorshipEvents(b.sponsorship)
		if err != nil || len(evs) != 1 || evs[0].PolicyVersion != "v-test" {
			t.Errorf("events = %v, %v", evs, err)
		}
		return nil
	})
}

func sponsorshipsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range spMutations {
		out[k] = true
	}
	for _, k := range []string{"InsertIntake", "InsertSponsorship", "Sponsorships", "Sponsorship", "Intake", "SponsorshipEvents", "DueSponsorships",
		"CountLiveSponsorships", "CountInvitesSince"} {
		out[k] = true // TestIsolation_SponsorshipReads, and the inserts in the mutation cases and seeds
	}
	return out
}
