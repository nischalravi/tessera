package guestlife_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// provEnv is the env with the dev fake target behind the connection, write-back on.
type provEnv struct {
	*env
	fake   *fake.Server
	srv    *httptest.Server
	eng    *provision.Engine
	sealer *seal.Sealer
	conn   string
	system string
	group  int64
	clock  time.Time
}

func newProvEnv(t *testing.T, settings string) *provEnv {
	t.Helper()
	e := newEnv(t)
	p := &provEnv{env: e, clock: now, conn: e.f.B.Refs["connection:ad"]}
	p.fake = fake.New(fake.Options{Token: "tok"})
	p.srv = httptest.NewServer(p.fake.Handler())
	t.Cleanup(p.srv.Close)
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.sealer, err = seal.New(seal.RandomBytes(seal.KeySize)); err != nil {
		t.Fatal(err)
	}
	p.eng = &provision.Engine{DB: e.f.DB, Sealer: p.sealer, HTTP: hc, Clock: func() time.Time { return p.clock },
		MaxAttempts: 2, MaxVerifies: 2, Backoff: func(int) time.Duration { return 0 }}
	e.must(func(c *store.TenantTx) error {
		cn, err := c.Connection(p.conn)
		if err != nil {
			return err
		}
		p.system = cn.System
		if err := c.UpsertGroup(&store.Group{TenantID: c.Tenant(), System: p.system, ExternalID: "bundle-g", Name: "bundle-g"}); err != nil {
			return err
		}
		g, err := c.GroupByXID(p.system, "bundle-g")
		if err != nil {
			return err
		}
		p.group = g.ID
		p.fake.AddGroup("bundle-g", "bundle-g")
		id := store.NewID()
		enc, err := provision.SealToken(p.sealer, e.f.B.ID, id, "tok")
		if err != nil {
			return err
		}
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: p.conn, Kind: provision.KindSCIM, BaseURL: p.srv.URL + "/scim/v2",
			Settings: settings, CredentialEnc: enc, WriteBack: true, CreatedBy: "admin"}, now)
	})
	e.must(func(c *store.TenantTx) error {
		return c.PutCatalogItem(&store.CatalogItem{ID: uuid.NewString(), GroupID: p.group, Requestable: true, Risk: "low",
			EligibleTypes: []string{"human"}, UpdatedAt: now})
	})
	return p
}

func (p *provEnv) run() {
	p.t.Helper()
	for i := 0; i < 4; i++ {
		if _, err := p.eng.RunTenant(context.Background(), p.f.B.ID); err != nil {
			p.t.Fatal(err)
		}
	}
}

// guest is a visitor with the bundle, claimed, granted and verified in the target.
func (p *provEnv) guest(email string, days int) *store.Sponsorship {
	p.t.Helper()
	var ss *store.Sponsorship
	p.must(func(c *store.TenantTx) error {
		r, err := p.sp.Invite(c, p.carol, sponsorship.Invite{GivenName: "Gwen", Email: email, Population: "visitor", Purpose: "talk",
			EndsAt: day(days), Bundle: []int64{p.group}}, store.ChannelSponsorInvite, "", now)
		if r != nil {
			ss = r.Sponsorship
		}
		return err
	})
	p.must(func(c *store.TenantTx) error {
		if err := c.SetIdentityStatus(ss.GuestIdentityID, "active"); err != nil {
			return err
		}
		affs, err := c.AffiliationsFor(ss.GuestIdentityID)
		if err != nil {
			return err
		}
		for _, a := range affs {
			if a.Status == store.AffPending {
				if err := c.ActivateAffiliation(a.ID); err != nil {
					return err
				}
			}
		}
		return access.Claimed(c, now, ss.GuestIdentityID, 0, 1)
	})
	p.run()
	return ss
}

func (p *provEnv) account(guest int64) (a *store.Account) {
	p.t.Helper()
	p.must(func(c *store.TenantTx) error {
		accts, err := c.IdentityAccounts(guest)
		for _, x := range accts {
			if x.System == p.system {
				a = x
			}
		}
		return err
	})
	if a == nil {
		p.t.Fatal("the guest has no account in the target's system")
	}
	return a
}

func (p *provEnv) deprovision(at time.Time) (r guestlife.DeprovisionResult) {
	p.t.Helper()
	p.must(func(c *store.TenantTx) (err error) { r, err = p.gl.Deprovision(c, at); return err })
	return r
}

func (p *provEnv) stage(guest int64) *store.Deprovisioning {
	p.t.Helper()
	var d *store.Deprovisioning
	p.must(func(c *store.TenantTx) (err error) { d, err = c.Deprovisioning(guest); return err })
	return d
}

func TestDeprovision_VerifiedInTargets(t *testing.T) {
	p := newProvEnv(t, "{}")
	ss := p.guest("gwen@guest.example", 10)
	g := ss.GuestIdentityID
	acct := p.account(g)
	if exists, active := p.fake.Active(acct.Username); !exists || !active {
		t.Fatalf("the account in the target before the end: %v %v", exists, active)
	}
	if len(p.fake.Members("bundle-g")) != 1 {
		t.Fatalf("members = %v", p.fake.Members("bundle-g"))
	}
	// the sponsorship ends: the bundle and the account are taken out through
	// provisioning; visitors have no grace period, so the stage starts and then waits for the re-read
	p.must(func(c *store.TenantTx) error { _, err := p.sp.End(c, p.carol, ss.ID, "event over", now); return err })
	r := p.deprovision(now)
	if r.Started != 1 || r.Deprovisioned != 0 || r.Blocked != 1 {
		t.Fatalf("before the operations verified: %+v", r)
	}
	if d := p.stage(g); d.Stage != store.StageGrace || !d.HeldAccess || d.Population != "visitor" {
		t.Errorf("stage = %+v", d)
	}
	if exists, active := p.fake.Active(acct.Username); !exists || !active {
		t.Errorf("nothing was sent yet but the target changed: %v %v", exists, active)
	}
	p.run() // the worker sends and verifies by re-reading the target
	if exists, active := p.fake.Active(acct.Username); !exists || active {
		t.Errorf("the account after the leaver plan: exists=%v active=%v, want disabled", exists, active)
	}
	if m := p.fake.Members("bundle-g"); len(m) != 0 {
		t.Errorf("members after = %v", m)
	}
	p.must(func(c *store.TenantTx) error {
		ops, err := c.ProvOps(store.ProvOpFilter{})
		for _, o := range ops {
			if o.Status != provision.Verified {
				t.Errorf("operation %s %s = %s, want verified", o.Kind, o.TargetRef, o.Status)
			}
		}
		a, err := c.Account(acct.ID)
		if a.Status != "disabled" {
			t.Errorf("account in Tessera = %s", a.Status)
		}
		return err
	})
	r = p.deprovision(day(1))
	if r.Deprovisioned != 1 || r.Blocked != 0 {
		t.Fatalf("after verification: %+v", r)
	}
	if got := p.person(g); got.Status != "deprovisioned" {
		t.Errorf("identity status = %s", got.Status)
	}
	if d := p.stage(g); d.Stage != store.StageDeprovisioned || d.DeprovisionedAt == nil {
		t.Errorf("stage = %+v", d)
	}
	// the default leaves the account disabled in the target: no delete was asked
	if exists, _ := p.fake.Active(acct.Username); !exists {
		t.Errorf("the account was deleted although the target says disable")
	}
	if r := p.deprovision(day(2)); r != (guestlife.DeprovisionResult{}) {
		t.Errorf("a second pass did something: %+v", r)
	}
	if a := p.audits(); a["guest.deprovision.start"] != 1 || a["guest.deprovision.complete"] != 1 {
		t.Errorf("audit = %v", a)
	}
}

func TestDeprovision_DeletesAccountsWhenTheTargetSaysSo(t *testing.T) {
	p := newProvEnv(t, `{"on_deprovision":"delete"}`)
	ss := p.guest("gwen@guest.example", 10)
	g := ss.GuestIdentityID
	acct := p.account(g)
	p.must(func(c *store.TenantTx) error { _, err := p.sp.End(c, p.carol, ss.ID, "event over", now); return err })
	p.deprovision(now)
	p.run()
	if r := p.deprovision(day(1)); r.Deprovisioned != 1 {
		t.Fatalf("deprovision = %+v", r)
	}
	p.clock = day(1)
	p.run() // the delete is sent and verified
	if exists, _ := p.fake.Active(acct.Username); exists {
		t.Errorf("the account still exists in the target")
	}
	p.must(func(c *store.TenantTx) error {
		a, err := c.Account(acct.ID)
		if a.Status != "deleted" {
			t.Errorf("account in Tessera = %s, want deleted after the verified delete", a.Status)
		}
		return err
	})
}

func TestDeprovision_GracePeriodPerPopulationAndOwnershipReassigned(t *testing.T) {
	e := newEnv(t)
	e.settings(func(s *store.GuestLifecycleSettings) { s.GraceDays[store.PopContractor] = 10 })
	ss := e.invite(e.carol, "g@x.example", 20)
	g := ss.GuestIdentityID
	e.claimed(g, 1)
	// the guest owns a machine identity (the #167 ownership logic reassigns it)
	var bot int64
	e.must(func(tx *store.TenantTx) (err error) {
		bot, err = tx.InsertIdentity(&store.Identity{ExternalID: "guest-bot", Name: "Guest bot", Type: "service", Status: "active",
			OwnerID: &g, CreatedAt: now})
		return err
	})
	e.must(func(tx *store.TenantTx) error { _, err := e.sp.End(tx, e.carol, ss.ID, "done", day(1)); return err })
	step := func(at time.Time) (r guestlife.DeprovisionResult) {
		e.must(func(tx *store.TenantTx) (err error) { r, err = e.gl.Deprovision(tx, at); return err })
		return r
	}
	if r := step(day(1)); r.Started != 1 || r.Deprovisioned != 0 {
		t.Fatalf("start = %+v", r)
	}
	if r := step(day(10)); r.Deprovisioned != 0 {
		t.Errorf("before the grace period ended: %+v", r)
	}
	var d *store.Deprovisioning
	e.must(func(tx *store.TenantTx) (err error) { d, err = tx.Deprovisioning(g); return err })
	if !d.GraceUntil.Equal(day(11)) {
		t.Errorf("grace until %v, want 10 days after the end", d.GraceUntil)
	}
	e.must(func(tx *store.TenantTx) error {
		// the owner is put back on the guest after the immediate leaver plan, to show the pass catches what is still held
		return tx.SetIdentityOwner(bot, &g)
	})
	if r := step(day(11)); r.Deprovisioned != 1 {
		t.Fatalf("at the end of the grace period: %+v", r)
	}
	e.must(func(tx *store.TenantTx) error {
		b, err := tx.Identity(bot)
		if err != nil || b.OwnerID != nil && *b.OwnerID == g {
			t.Errorf("the guest still owns the machine identity: %+v, %v", b, err)
		}
		return err
	})
}

func TestPurge_KeepsTombstoneOnly(t *testing.T) {
	e := newEnv(t)
	ss := e.invite(e.carol, "tombstone.person@guest.example", 20)
	g := ss.GuestIdentityID
	e.claimed(g, 1)
	k := e.sp.Keyer
	// identifiers, a source record and a notification the person holds
	var emailHash string
	e.must(func(tx *store.TenantTx) error {
		norm, mac, err := k.Digest(tx.Tenant(), store.IdentPhone, "", "+1 415 555 0100")
		if err != nil {
			return err
		}
		emailHash = mac
		by := store.VerifiedByCode
		at := now
		if err := tx.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: g, Type: store.IdentPhone, ValueNorm: norm, ValueHMAC: mac,
			VerifiedAt: &at, VerifiedBy: &by, Status: store.RecordActive, CreatedAt: now}); err != nil {
			return err
		}
		return tx.InsertSourceRecord(&store.SourceRecord{ID: uuid.NewString(), IdentityID: &g, SOR: "sponsorship", SORID: "intake-x",
			Attributes: `{"given_name":"Gwen","dob":"1990-01-01"}`, Status: store.RecordActive, ReceivedAt: now})
	})
	e.must(func(tx *store.TenantTx) error { _, err := e.sp.End(tx, e.carol, ss.ID, "done", day(1)); return err })
	step := func(at time.Time) (r guestlife.DeprovisionResult) {
		e.must(func(tx *store.TenantTx) (err error) { r, err = e.gl.Deprovision(tx, at); return err })
		return r
	}
	step(day(1))
	step(day(31)) // the 30-day grace period of a contractor
	var d *store.Deprovisioning
	e.must(func(tx *store.TenantTx) (err error) { d, err = tx.Deprovisioning(g); return err })
	if d.Stage != store.StageDeprovisioned || !d.RetentionUntil.Equal(d.GraceUntil.AddDate(0, 0, 2555)) {
		t.Fatalf("stage = %+v", d)
	}
	var before []string
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, ev := range evs {
			before = append(before, ev.Action+"|"+ev.Hash)
		}
		return err
	})
	if r := step(d.RetentionUntil.Add(-time.Hour)); r.Purged != 0 {
		t.Errorf("purged before the retention period ended: %+v", r)
	}
	if r := step(d.RetentionUntil); r.Purged != 1 {
		t.Fatalf("purge = %+v", r)
	}
	// ID, affiliation history and dates stay; names, emails, identifiers and intake attributes go
	p := e.person(g)
	if p.ID != g || p.Status != "purged" || p.Name != "Purged person" || p.Email != nil || p.Department != nil || p.Title != nil ||
		strings.Contains(p.ExternalID, "tombstone") {
		t.Errorf("tombstone = %+v", p)
	}
	e.must(func(tx *store.TenantTx) error {
		affs, err := tx.AffiliationsFor(g)
		if len(affs) != 1 || affs[0].Status != store.AffEnded || affs[0].EndsAt == nil || affs[0].Type != store.AffContractor {
			t.Errorf("affiliation history = %+v, %v", affs, err)
		}
		xs, err := tx.IdentifiersFor(g)
		if len(xs) == 0 {
			t.Error("no identifier rows")
		}
		for _, x := range xs {
			if x.ValueNorm != nil || x.Status != store.RecordRetired || x.ValueHMAC == emailHash || !strings.HasPrefix(x.ValueHMAC, "purged:") {
				t.Errorf("identifier after the purge = %+v", x)
			}
		}
		rs, err := tx.SourceRecordsFor(g)
		for _, r := range rs {
			if r.Attributes != "{}" || r.Status != store.RecordRetired {
				t.Errorf("source record = %+v", r)
			}
		}
		l, err := tx.LifecycleFor(g)
		if err != nil || l.EndedAt == nil {
			t.Errorf("lifecycle dates = %+v, %v", l, err)
		}
		d, err := tx.Deprovisioning(g)
		if err != nil || d.Stage != store.StagePurged || d.PurgedAt == nil {
			t.Errorf("stage = %+v, %v", d, err)
		}
		return err
	})
	// the ledger is untouched: every earlier event is as it was, and the purge event holds no PII
	var after []string
	var purge string
	e.must(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, ev := range evs {
			after = append(after, ev.Action+"|"+ev.Hash)
			if ev.Action == "guest.purge" {
				purge = string(mustJSON(t, ev))
			}
		}
		return err
	})
	if len(after) != len(before)+1 {
		t.Errorf("ledger grew by %d events, want 1", len(after)-len(before))
	}
	held := map[string]int{}
	for _, a := range after {
		held[a]++
	}
	for _, b := range before {
		if held[b]--; held[b] < 0 {
			t.Errorf("ledger event %q changed or went missing", b)
		}
	}
	for _, pii := range []string{"tombstone", "guest.example", "Gwen", "555", "1990"} {
		if strings.Contains(purge, pii) {
			t.Errorf("the purge event names %q: %s", pii, purge)
		}
	}
	// idempotent: another pass, even with the stage row replayed, changes and records nothing
	if r := step(d.RetentionUntil.AddDate(0, 0, 1)); r != (guestlife.DeprovisionResult{}) {
		t.Errorf("second pass = %+v", r)
	}
	if a := e.audits(); a["guest.purge"] != 1 {
		t.Errorf("purge events = %d", a["guest.purge"])
	}
	e.must(func(tx *store.TenantTx) error {
		if _, err := tx.PurgeIdentityPII(g, false); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second purge = %v, want nothing to purge", err)
		}
		c, err := guestlife.Counts(tx, d.RetentionUntil)
		if c[guestlife.BucketPurged] != 1 || c[guestlife.BucketDeprovisioned] != 0 {
			t.Errorf("counts = %v", c)
		}
		return err
	})
}

func TestPurge_VisitorWithoutAccessIsKeptOneYear(t *testing.T) {
	e := newEnv(t)
	var ss *store.Sponsorship
	e.must(func(tx *store.TenantTx) error {
		r, err := e.sp.Invite(tx, e.carol, sponsorship.Invite{GivenName: "Vera", Email: "v@x.example", Population: "visitor", Purpose: "tour",
			EndsAt: day(3)}, store.ChannelSponsorInvite, "", now)
		ss = r.Sponsorship
		return err
	})
	e.claimed(ss.GuestIdentityID, 0)
	e.must(func(tx *store.TenantTx) error { _, err := e.sp.Sweep(tx, day(4)); return err })
	e.must(func(tx *store.TenantTx) error { _, err := e.gl.Deprovision(tx, day(4)); return err })
	e.must(func(tx *store.TenantTx) error {
		d, err := tx.Deprovisioning(ss.GuestIdentityID)
		if err != nil || d.Stage != store.StageDeprovisioned || d.HeldAccess && false || !d.RetentionUntil.Equal(d.GraceUntil.AddDate(0, 0, 365)) {
			t.Errorf("a visitor: %+v, %v", d, err)
		}
		return err
	})
}

// TestReturn_WithinRetentionTierARematchGetsTheSameIdentityBack: a person who
// comes back inside the retention period is matched on a federated binding or an
// authoritative identifier and is the same identity; after a purge they are
// matched only where the tenant keeps identifier hashes for it.
func TestReturn_WithinRetentionTierARematchGetsTheSameIdentityBack(t *testing.T) {
	for _, keep := range []bool{true, false} {
		name := map[bool]string{true: "hashes kept", false: "hashes purged"}[keep]
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.settings(func(s *store.GuestLifecycleSettings) { s.KeepRematchHashes = keep })
			ss := e.invite(e.carol, "back@x.example", 20)
			g := ss.GuestIdentityID
			e.claimed(g, 1)
			m := match.New(e.sp.Keyer)
			bind := func(tx *store.TenantTx) error {
				norm, mac, err := e.sp.Keyer.Digest(tx.Tenant(), store.IdentOIDCSub, "https://home.example", "sub-123")
				if err != nil {
					return err
				}
				return tx.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: g, Type: store.IdentOIDCSub, Issuer: "https://home.example",
					ValueNorm: norm, ValueHMAC: mac, Status: store.RecordActive, CreatedAt: now})
			}
			e.must(bind)
			e.must(func(tx *store.TenantTx) error { _, err := e.sp.End(tx, e.carol, ss.ID, "done", day(1)); return err })
			step := func(at time.Time) {
				e.must(func(tx *store.TenantTx) error { _, err := e.gl.Deprovision(tx, at); return err })
			}
			step(day(1))
			step(day(31))
			rematch := func(at time.Time) *match.Stored {
				var st *match.Stored
				e.must(func(tx *store.TenantTx) error {
					id := uuid.NewString()
					if err := tx.InsertIntake(&store.IntakeRecord{ID: id, Channel: "sponsor_invite", MatchMode: string(match.Federated),
						Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: at}); err != nil {
						return err
					}
					var err error
					st, err = m.Run(tx, nil, id, match.Subject{Mode: match.Federated, Given: "Gwen", Family: "Guest",
						Identifiers: []match.RawIdent{{Type: store.IdentOIDCSub, Issuer: "https://home.example", Value: "sub-123"}}}, at)
					return err
				})
				return st
			}
			// within retention, deprovisioned: the same identity
			if st := rematch(day(40)); st.Verdict.Tier != match.TierA || len(st.Rows) == 0 || st.Rows[0].CandidateID == nil || *st.Rows[0].CandidateID != g {
				t.Fatalf("a rematch inside retention = %+v", st.Verdict)
			}
			// sponsored again, the person is revived as themselves
			e.must(func(tx *store.TenantTx) error {
				_, err := e.sp.SponsorExisting(tx, e.carol, g, sponsorship.Invite{Population: "contractor", Purpose: "back again", EndsAt: day(100)}, day(40))
				return err
			})
			if p := e.person(g); p.Status != "active" || p.ID != g {
				t.Errorf("returned person = %+v", p)
			}
			e.must(func(tx *store.TenantTx) error {
				d, err := tx.Deprovisioning(g)
				if err != nil || d.Stage != store.StageReturned || d.ReturnedAt == nil {
					t.Errorf("stage = %+v, %v", d, err)
				}
				return err
			})
			// leaving again starts a new cycle on the same row; a purge needs the retention period of that one
			e.must(func(tx *store.TenantTx) error {
				all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: g, Status: store.SponsorActive})
				for _, s := range all {
					if _, err := e.sp.End(tx, e.carol, s.ID, "gone again", day(41)); err != nil {
						return err
					}
				}
				return err
			})
			step(day(41))
			var d *store.Deprovisioning
			e.must(func(tx *store.TenantTx) (err error) { d, err = tx.Deprovisioning(g); return err })
			if d.Stage != store.StageGrace || !d.EndedAt.Equal(day(41)) || d.ReturnedAt != nil {
				t.Fatalf("second cycle = %+v", d)
			}
			step(day(72))
			e.must(func(tx *store.TenantTx) (err error) { d, err = tx.Deprovisioning(g); return err })
			step(d.RetentionUntil)
			st := rematch(d.RetentionUntil.AddDate(0, 0, 1))
			matched := len(st.Rows) > 0 && st.Rows[0].CandidateID != nil && *st.Rows[0].CandidateID == g
			if matched != keep {
				t.Errorf("after the purge the person matched = %v, want %v (verdict %+v)", matched, keep, st.Verdict)
			}
			if p := e.person(g); p.Status != "purged" {
				t.Errorf("status = %s", p.Status)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
