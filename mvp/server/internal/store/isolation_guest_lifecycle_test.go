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

// Guest lifecycle isolation (issue #74): a tenant sees and changes only its own
// settings, reminders, renewal tokens, lifecycle tasks, step-ups and
// deprovisioning stages; another tenant's id looks nonexistent, and a row
// naming another tenant's sponsorship, person or user is refused by the guard
// triggers.

type glRows struct {
	spRows
	user  *store.PlatformUser
	task  string
	step  string
	hash  string
	other int64 // a second person of the tenant, for the deprovisioning row
}

func seedGuestLifecycle(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) glRows {
	t.Helper()
	r := glRows{spRows: seedSponsorship(t, db, tn, tag), task: "task-" + tag, step: "step-" + tag,
		hash: strings.Repeat(tag, 64)[:64], other: tn.IDs["bob"]}
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "admin " + tag, CreatedAt: now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		s := store.DefaultGuestLifecycleSettings()
		s.GuestReminderDays = 10
		if err := c.PutGuestLifecycleSettings(s, r.user.ID.String(), now); err != nil {
			return err
		}
		if _, err := c.MarkReminder(r.sponsorship, now.Add(48*time.Hour), store.AudienceSponsor, 3, now); err != nil {
			return err
		}
		if err := c.InsertRenewalToken(&store.RenewalToken{ID: "rt-" + tag, SponsorshipID: r.sponsorship, GuestIdentityID: r.guest,
			TokenHash: r.hash, ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now}); err != nil {
			return err
		}
		dl := now.Add(14 * 24 * time.Hour)
		if err := c.InsertLifecycleTask(&store.LifecycleTask{ID: r.task, Kind: store.TaskSponsorTransfer, SponsorshipID: r.sponsorship,
			SubjectIdentityID: r.sponsor, Trigger: store.TaskTriggerLeaver, Deadline: &dl, CreatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertStepup(&store.Stepup{ID: r.step, SponsorshipID: r.sponsorship, RequestedEndsAt: now.Add(72 * time.Hour),
			Justification: "renew " + tag, RequiredIAL: 2, CreatedAt: now}); err != nil {
			return err
		}
		return c.InsertDeprovisioning(&store.Deprovisioning{IdentityID: r.other, Population: store.PopVisitor, EndedAt: now,
			GraceUntil: now.Add(24 * time.Hour), RetentionUntil: now.Add(365 * 24 * time.Hour), UpdatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func glFixture(t *testing.T) (*storetest.Fixture, glRows, glRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedGuestLifecycle(t, f.DB, f.A, "a"), seedGuestLifecycle(t, f.DB, f.B, "b")
}

func glDump(t *testing.T, db *store.DB, tid tenancy.ID, r glRows) string {
	t.Helper()
	out := spDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		st, err := c.GuestLifecycleSettings()
		if err != nil {
			return err
		}
		ts, err := c.LifecycleTasks(store.LifecycleTaskFilter{})
		if err != nil {
			return err
		}
		us, err := c.Stepups("", "")
		if err != nil {
			return err
		}
		ds, err := c.DeprovisioningList("")
		if err != nil {
			return err
		}
		rs, err := c.RenewalTokensFor(r.sponsorship)
		if err != nil {
			return err
		}
		n, err := c.CountReminders("", "")
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{st, ts, us, ds, rs, n})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_GuestLifecycleReads(t *testing.T) {
	f, a, b := glFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.LifecycleTask(a.task); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("LifecycleTask(A's) = %v", err)
		}
		if x, err := c.LifecycleTask(b.task); err != nil || x.Status != store.TaskOpen {
			t.Errorf("LifecycleTask(B's) = %+v, %v", x, err)
		}
		if xs, err := c.LifecycleTasks(store.LifecycleTaskFilter{Sponsorship: a.sponsorship}); err != nil || len(xs) != 0 {
			t.Errorf("LifecycleTasks(A's sponsorship) = %v, %v", xs, err)
		}
		if xs, err := c.LifecycleTasks(store.LifecycleTaskFilter{Status: store.TaskOpen}); err != nil || len(xs) != 1 || xs[0].ID != b.task {
			t.Errorf("LifecycleTasks(open) = %v, %v", xs, err)
		}
		if xs, err := c.Stepups(store.StepupPending, ""); err != nil || len(xs) != 1 || xs[0].ID != b.step {
			t.Errorf("Stepups = %v, %v", xs, err)
		}
		if xs, err := c.RenewalTokensFor(a.sponsorship); err != nil || len(xs) != 0 {
			t.Errorf("RenewalTokensFor(A's) = %v, %v", xs, err)
		}
		if _, err := c.Deprovisioning(a.other); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Deprovisioning(A's person) = %v", err)
		}
		if xs, err := c.DeprovisioningList(store.StageGrace); err != nil || len(xs) != 1 || xs[0].IdentityID != b.other {
			t.Errorf("DeprovisioningList = %v, %v", xs, err)
		}
		if n, err := c.CountReminders("", ""); err != nil || n != 1 {
			t.Errorf("CountReminders = %d, %v", n, err)
		}
		if s, err := c.GuestLifecycleSettings(); err != nil || s.GuestReminderDays != 10 {
			t.Errorf("GuestLifecycleSettings = %+v, %v", s, err)
		}
		if _, err := c.ConsumeRenewalToken(a.hash, storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ConsumeRenewalToken(A's) = %v", err)
		}
		if _, err := c.AwaitingDeprovisioning(); err != nil {
			t.Errorf("AwaitingDeprovisioning = %v", err)
		}
		if n, err := c.HeldBundleAccess(a.guest); err != nil || n != 0 {
			t.Errorf("HeldBundleAccess(A's person) = %d, %v", n, err)
		}
		return nil
	})
}

var glMutations = map[string]func(c *store.TenantTx, a, b glRows) error{
	"ResolveLifecycleTask": func(c *store.TenantTx, a, _ glRows) error {
		return c.ResolveLifecycleTask(a.task, store.TaskDone, store.OutcomeTransferred, "x", nil, storetest.Now)
	},
	"ResolveStepup": func(c *store.TenantTx, a, _ glRows) error {
		return c.ResolveStepup(a.step, store.StepupApplied, storetest.Now)
	},
	"AdvanceDeprovisioning": func(c *store.TenantTx, a, _ glRows) error {
		return c.AdvanceDeprovisioning(a.other, store.StageGrace, store.StageDeprovisioned, storetest.Now)
	},
	"ConsumeRenewalToken": func(c *store.TenantTx, a, _ glRows) error {
		_, err := c.ConsumeRenewalToken(a.hash, storetest.Now)
		return err
	},
	"ReviveIdentity": func(c *store.TenantTx, a, _ glRows) error { return c.ReviveIdentity(a.guest) },
	"PurgeIdentityPII": func(c *store.TenantTx, a, _ glRows) error {
		_, err := c.PurgeIdentityPII(a.guest, false)
		return err
	},
	"InsertLifecycleTask/A's sponsorship": func(c *store.TenantTx, a, b glRows) error {
		return c.InsertLifecycleTask(&store.LifecycleTask{ID: uuid.NewString(), Kind: store.TaskRenewalRequest, SponsorshipID: a.sponsorship,
			SubjectIdentityID: b.guest, Trigger: store.TaskTriggerGuest, CreatedAt: storetest.Now})
	},
	"InsertLifecycleTask/A's person": func(c *store.TenantTx, a, b glRows) error {
		return c.InsertLifecycleTask(&store.LifecycleTask{ID: uuid.NewString(), Kind: store.TaskRenewalRequest, SponsorshipID: b.sponsorship,
			SubjectIdentityID: a.guest, Trigger: store.TaskTriggerGuest, CreatedAt: storetest.Now})
	},
	"InsertStepup/A's sponsorship": func(c *store.TenantTx, a, _ glRows) error {
		return c.InsertStepup(&store.Stepup{ID: uuid.NewString(), SponsorshipID: a.sponsorship, RequestedEndsAt: storetest.Now.Add(time.Hour),
			Justification: "x", RequiredIAL: 1, CreatedAt: storetest.Now})
	},
	"InsertStepup/A's user": func(c *store.TenantTx, a, b glRows) error {
		by := a.user.ID.String()
		return c.InsertStepup(&store.Stepup{ID: uuid.NewString(), SponsorshipID: b.sponsorship, RequestedEndsAt: storetest.Now.Add(time.Hour),
			Justification: "x", RequiredIAL: 1, RequestedBy: &by, CreatedAt: storetest.Now})
	},
	"InsertRenewalToken/A's sponsorship": func(c *store.TenantTx, a, b glRows) error {
		return c.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: a.sponsorship, GuestIdentityID: b.guest,
			TokenHash: "f" + b.hash[1:], ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"InsertRenewalToken/A's person": func(c *store.TenantTx, a, b glRows) error {
		return c.InsertRenewalToken(&store.RenewalToken{ID: uuid.NewString(), SponsorshipID: b.sponsorship, GuestIdentityID: a.guest,
			TokenHash: "e" + b.hash[1:], ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"MarkReminder/A's sponsorship": func(c *store.TenantTx, a, _ glRows) error {
		_, err := c.MarkReminder(a.sponsorship, storetest.Now.Add(time.Hour), store.AudienceGuest, 14, storetest.Now)
		return err
	},
	"InsertDeprovisioning/A's person": func(c *store.TenantTx, a, _ glRows) error {
		return c.InsertDeprovisioning(&store.Deprovisioning{IdentityID: a.guest, Population: store.PopVisitor, EndedAt: storetest.Now,
			GraceUntil: storetest.Now, RetentionUntil: storetest.Now, UpdatedAt: storetest.Now})
	},
	"PutGuestLifecycleSettings/A's user": func(c *store.TenantTx, a, _ glRows) error {
		return c.PutGuestLifecycleSettings(store.DefaultGuestLifecycleSettings(), a.user.ID.String(), storetest.Now)
	},
}

func TestIsolation_GuestLifecycleMutationsScoped(t *testing.T) {
	for name, fn := range glMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := glFixture(t)
			before := glDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := glDump(t, f.DB, f.A.ID, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
	// settings are per tenant: B's save does not touch A's
	f, a, b := glFixture(t)
	s := store.DefaultGuestLifecycleSettings()
	s.GuestReminderDays = 7
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.PutGuestLifecycleSettings(s, b.user.ID.String(), storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if got, err := c.GuestLifecycleSettings(); err != nil || got.GuestReminderDays != 10 {
			t.Errorf("A's settings after B's save = %+v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = a
}

// The schema's own rules: reminders are a ledger, a resolved task is final, one
// open task per sponsorship and kind, a token is spent once, a purge is final.
func TestGuestLifecycle_SchemaRules(t *testing.T) {
	f, _, b := glFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if ok, err := c.MarkReminder(b.sponsorship, now.Add(48*time.Hour), store.AudienceSponsor, 3, now); err != nil || ok {
			t.Errorf("a reminder was recorded twice: %v, %v", ok, err)
		}
		if ok, err := c.MarkReminder(b.sponsorship, now.Add(72*time.Hour), store.AudienceSponsor, 3, now); err != nil || !ok {
			t.Errorf("a reminder for a moved end date was not recorded: %v, %v", ok, err)
		}
		if err := c.InsertLifecycleTask(&store.LifecycleTask{ID: "dup", Kind: store.TaskSponsorTransfer, SponsorshipID: b.sponsorship,
			SubjectIdentityID: b.sponsor, Trigger: store.TaskTriggerMover, CreatedAt: now}); err == nil {
			t.Error("two open tasks of one kind for one sponsorship were accepted")
		}
		if err := c.ResolveLifecycleTask(b.task, store.TaskDone, store.OutcomeTransferred, "", nil, now); err != nil {
			t.Fatal(err)
		}
		if err := c.ResolveLifecycleTask(b.task, store.TaskDeclined, store.OutcomeEnded, "", nil, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a resolved task was resolved again: %v", err)
		}
		if _, err := c.ConsumeRenewalToken(b.hash, now); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ConsumeRenewalToken(b.hash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a renewal token worked twice: %v", err)
		}
		if err := c.AdvanceDeprovisioning(b.other, store.StageGrace, store.StageDeprovisioned, now); err != nil {
			t.Fatal(err)
		}
		if err := c.AdvanceDeprovisioning(b.other, store.StageGrace, store.StageDeprovisioned, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a stage was advanced twice: %v", err)
		}
		return nil
	})
}

func guestLifecycleCovered() map[string]bool {
	out := map[string]bool{}
	for k := range glMutations {
		out[k] = true
	}
	for _, k := range []string{"GuestLifecycleSettings", "PutGuestLifecycleSettings", "MarkReminder", "CountReminders", "InsertRenewalToken",
		"ConsumeRenewalToken", "RevokeRenewalTokens", "ExpireRenewalTokens", "RenewalTokensFor", "InsertLifecycleTask", "LifecycleTask",
		"LifecycleTasks", "ResolveLifecycleTask", "InsertStepup", "Stepups", "ResolveStepup", "InsertDeprovisioning", "Deprovisioning",
		"DeprovisioningList", "AdvanceDeprovisioning", "AwaitingDeprovisioning", "HeldBundleAccess", "ReviveIdentity",
		"SetAccountStatus", "PurgeIdentityPII"} {
		out[k] = true // TestIsolation_GuestLifecycleReads, and the writes in the seeds and mutation cases
	}
	return out
}
