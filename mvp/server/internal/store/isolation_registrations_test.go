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

// Guest self-registration isolation (issue #66): a tenant sees and changes only
// its own registration requests and sponsor codes; another tenant's id looks
// nonexistent, and a row naming another tenant's person, intake or user is
// refused by the guard triggers.

type regRows struct {
	spRows
	user *store.PlatformUser
	reg  string
	hash string
	code string
}

func seedRegistrations(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) regRows {
	t.Helper()
	r := regRows{spRows: seedSponsorship(t, db, tn, tag), reg: "reg-" + tag, hash: strings.Repeat(tag, 64)[:64], code: "code-" + tag}
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		sponsor := tn.IDs["carol"]
		r.user = &store.PlatformUser{DisplayName: "sponsor " + tag, IdentityID: &sponsor, CreatedAt: now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		g, f, e, p := "Gwen "+tag, "Guest", "gwen-"+tag+"@guest.example", "conference "+tag
		if err := c.InsertRegistration(&store.Registration{ID: r.reg, SponsorIdentityID: sponsor, Via: store.RegViaSearch, GivenName: &g,
			FamilyName: &f, Email: &e, Purpose: &p, EmailHMAC: "hmac-" + tag, StartsAt: now, EndsAt: now.Add(48 * time.Hour),
			ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now}); err != nil {
			return err
		}
		return c.InsertSponsorCode(&store.SponsorCode{ID: r.code, SponsorIdentityID: sponsor, CodeHash: r.hash, ExpiresAt: now.Add(time.Hour), CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func regFixture(t *testing.T) (*storetest.Fixture, regRows, regRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedRegistrations(t, f.DB, f.A, "a"), seedRegistrations(t, f.DB, f.B, "b")
}

func regDump(t *testing.T, db *store.DB, tid tenancy.ID, r regRows) string {
	t.Helper()
	out := spDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		rs, err := c.RegistrationsForSponsor(r.sponsor, "")
		if err != nil {
			return err
		}
		cs, cerr := c.SponsorCodeByHash(r.hash, storetest.Now)
		n, err2 := c.RegistrationsHoldingData()
		b, err3 := json.Marshal([]any{rs, cs, cerr != nil, n})
		out += "\n" + string(b)
		return errors.Join(err2, err3)
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_RegistrationReads(t *testing.T) {
	f, a, b := regFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.Registration(a.reg); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Registration(A's) = %v", err)
		}
		if x, err := c.Registration(b.reg); err != nil || x.Status != store.RegPending {
			t.Errorf("Registration(B's) = %+v, %v", x, err)
		}
		if xs, err := c.RegistrationsForSponsor(a.sponsor, ""); err != nil || len(xs) != 0 {
			t.Errorf("RegistrationsForSponsor(A's sponsor) = %v, %v", xs, err)
		}
		if ok, err := c.HasPendingRegistration(b.sponsor, "hmac-a"); err != nil || ok {
			t.Errorf("HasPendingRegistration(A's address) = %v, %v", ok, err)
		}
		if xs, err := c.DueRegistrations(now.Add(72 * time.Hour)); err != nil || len(xs) != 1 || xs[0].ID != b.reg {
			t.Errorf("DueRegistrations = %v, %v", xs, err)
		}
		if n, err := c.RegistrationsHoldingData(); err != nil || n != 1 {
			t.Errorf("RegistrationsHoldingData = %d, %v", n, err)
		}
		if _, err := c.SponsorCodeByHash(a.hash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SponsorCodeByHash(A's) = %v", err)
		}
		if x, err := c.SponsorCodeByHash(b.hash, now); err != nil || x.ID != b.code {
			t.Errorf("SponsorCodeByHash(B's) = %+v, %v", x, err)
		}
		if known, err := c.IdentityKnownByEmail("zz@nowhere.example"); err != nil || known {
			t.Errorf("IdentityKnownByEmail = %v, %v", known, err)
		}
		// the candidates are B's people only
		cs, err := c.SponsorCandidates("", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range cs {
			if x.TenantID != f.B.ID {
				t.Errorf("SponsorCandidates returned tenant %v's person", x.TenantID)
			}
		}
		if len(cs) != 1 || cs[0].ID != b.sponsor {
			t.Errorf("SponsorCandidates = %d people, want B's linked sponsor only", len(cs))
		}
		if xs, err := c.SponsorCandidates("100%", 10); err != nil || len(xs) != 0 {
			t.Errorf("a wildcard matched: %v, %v", xs, err)
		}
		return nil
	})
}

var regMutations = map[string]func(c *store.TenantTx, a, b regRows) error{
	"DecideRegistration": func(c *store.TenantTx, a, _ regRows) error {
		return c.DecideRegistration(a.reg, store.RegDenied, nil, nil, nil, storetest.Now, storetest.Now)
	},
	"RedactRegistration": func(c *store.TenantTx, a, _ regRows) error { return c.RedactRegistration(a.reg, storetest.Now) },
	"RevokeSponsorCodes": func(c *store.TenantTx, a, _ regRows) error {
		n, err := c.RevokeSponsorCodes(a.sponsor, storetest.Now)
		if err == nil && n == 0 {
			return store.ErrNotFound
		}
		return err
	},
	"RedactDueRegistrations": func(c *store.TenantTx, a, _ regRows) error {
		n, err := c.RedactDueRegistrations(storetest.Now.Add(1000 * time.Hour))
		if err == nil && n == 0 {
			return store.ErrNotFound // B has nothing decided
		}
		return err
	},
	"InsertRegistration/A's sponsor": func(c *store.TenantTx, a, _ regRows) error {
		g, f, e, p := "x", "x", "x@x.example", "x"
		return c.InsertRegistration(&store.Registration{ID: uuid.NewString(), SponsorIdentityID: a.sponsor, Via: store.RegViaCode, GivenName: &g,
			FamilyName: &f, Email: &e, Purpose: &p, EmailHMAC: "other", StartsAt: storetest.Now, EndsAt: storetest.Now.Add(time.Hour),
			ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"InsertSponsorCode/A's sponsor": func(c *store.TenantTx, a, _ regRows) error {
		return c.InsertSponsorCode(&store.SponsorCode{ID: uuid.NewString(), SponsorIdentityID: a.sponsor, CodeHash: strings.Repeat("9", 64),
			ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"DecideRegistration/A's person": func(c *store.TenantTx, a, b regRows) error {
		in := b.intake
		return c.DecideRegistration(b.reg, store.RegApproved, nil, &a.guest, &in, storetest.Now, storetest.Now)
	},
	"DecideRegistration/A's intake": func(c *store.TenantTx, a, b regRows) error {
		return c.DecideRegistration(b.reg, store.RegApproved, nil, &b.guest, &a.intake, storetest.Now, storetest.Now)
	},
	"DecideRegistration/A's user": func(c *store.TenantTx, a, b regRows) error {
		u := a.user.ID.String()
		return c.DecideRegistration(b.reg, store.RegDenied, &u, nil, nil, storetest.Now, storetest.Now)
	},
}

func TestIsolation_RegistrationMutationsScoped(t *testing.T) {
	for name, fn := range regMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := regFixture(t)
			before := regDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := regDump(t, f.DB, f.A.ID, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// The schema's own rules: one pending request per sponsor and address, a
// decision is made once and is final, personal data goes and does not come
// back, a request is never deleted, a revoked code stays revoked.
func TestGuestRegistration_SchemaRules(t *testing.T) {
	f, _, b := regFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		g, fam, e, p := "x", "x", "x@x.example", "x"
		dup := &store.Registration{ID: "dup", SponsorIdentityID: b.sponsor, Via: store.RegViaSearch, GivenName: &g, FamilyName: &fam, Email: &e,
			Purpose: &p, EmailHMAC: "hmac-b", StartsAt: now, EndsAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		if err := c.InsertRegistration(dup); err == nil {
			t.Error("two pending requests for one sponsor and address were accepted")
		}
		if err := c.DecideRegistration(b.reg, store.RegApproved, nil, nil, nil, now, now); err == nil {
			t.Error("an approval without a person was accepted")
		}
		if err := c.DecideRegistration(b.reg, store.RegDenied, nil, nil, nil, now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
		if err := c.DecideRegistration(b.reg, store.RegExpired, nil, nil, nil, now, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a decided request was decided again: %v", err)
		}
		// a denied address may ask again
		if err := c.InsertRegistration(dup); err != nil {
			t.Errorf("a new request after a denial: %v", err)
		}
		if n, err := c.RedactDueRegistrations(now); err != nil || n != 0 {
			t.Errorf("reduced before its time: %d, %v", n, err)
		}
		if n, err := c.RedactDueRegistrations(now.Add(2 * time.Hour)); err != nil || n != 1 {
			t.Errorf("RedactDueRegistrations = %d, %v", n, err)
		}
		if err := c.RedactRegistration(b.reg, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a reduced request was reduced again: %v", err)
		}
		x, err := c.Registration(b.reg)
		if err != nil || x.Email != nil || x.GivenName != nil || x.FamilyName != nil || x.Purpose != nil || x.RedactedAt == nil || x.EmailHMAC == "" {
			t.Errorf("tombstone = %+v, %v", x, err)
		}
		if n, err := c.RevokeSponsorCodes(b.sponsor, now); err != nil || n != 1 {
			t.Errorf("RevokeSponsorCodes = %d, %v", n, err)
		}
		if _, err := c.SponsorCodeByHash(b.hash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a revoked code still works: %v", err)
		}
		if _, err := c.SponsorCodeByHash(strings.Repeat("0", 64), now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an unknown code: %v", err)
		}
		return nil
	})
	// an expired code does not work
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.InsertSponsorCode(&store.SponsorCode{ID: "late", SponsorIdentityID: b.sponsor, CodeHash: strings.Repeat("7", 64),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
			return err
		}
		if _, err := c.SponsorCodeByHash(strings.Repeat("7", 64), now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an expired code works: %v", err)
		}
		return nil
	})
}

func registrationsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range regMutations {
		out[k] = true
	}
	for _, k := range []string{"InsertRegistration", "Registration", "RegistrationsForSponsor", "HasPendingRegistration", "DueRegistrations",
		"RegistrationsHoldingData", "InsertSponsorCode", "SponsorCodeByHash", "SponsorCandidates", "IdentityKnownByEmail"} {
		out[k] = true // TestIsolation_RegistrationReads, and the writes in the seeds and mutation cases
	}
	return out
}
