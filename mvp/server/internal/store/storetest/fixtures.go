// Package storetest holds the shared tenant-isolation fixture (design §14.4):
// two tenants with the same external ids, tenant A's names, emails and tags
// carrying a sentinel string, and one of every kind of row in each.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Sentinel appears in tenant A's names, emails (lower-cased), tags, campaign
// name, HRIS payload and audit detail. No response or read in tenant B may
// contain it.
const Sentinel = "ZZ-LARKSPUR-SENTINEL"

// Now is the fixture's reference time.
var Now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// Tenant ids of the fixture.
var (
	AID = tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	BID = tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
)

// Tenant is one fixture tenant and the ids of its rows. Keys: external ids
// ("alice"), "acct:<system>:<xid>", "group:<system>:<xid>",
// "perm:<system>:<xid>", "resource:<system>:<xid>", "edge:<n>" (every grant
// edge, in id order), and "request:pending", "request:approved",
// "request:expired", "edge:jit-active", "edge:jit-expired", "campaign",
// "item", "qa" (an auto-decision sampled for QA), "hris:leaver", "hris:joiner", "secret", "delegation".
type Tenant struct {
	ID   tenancy.ID
	Slug string
	IDs  map[string]int64
	// Refs are the deployment-readiness row ids (UUIDs); see seedReadiness.
	Refs map[string]string
}

// Fixture is a database with tenants A (sentinel) and B, each with the same
// deployment-readiness rows (tenant B's carry ReadinessSentinel).
type Fixture struct {
	DB   *store.DB
	A, B Tenant
}

// seeded is the fixture, built once per test binary: the database
// file as bytes (the seed is by far the slowest part of a store or API test,
// especially under -race) and the ids of its rows.
var seeded struct {
	once sync.Once
	db   []byte // SQLite: the seeded file
	src  string // Postgres: the template database
	a, b Tenant
	err  error
}

// TwoTenants returns the fixture in a private database in a temporary
// directory. A is seeded first, so its integer ids are the lower ones. The
// seed runs once per test binary; every call gets its own byte-identical copy
// of that database, with the same ids.
func TwoTenants(tb testing.TB) *Fixture {
	tb.Helper()
	seeded.once.Do(buildTemplate)
	if seeded.err != nil {
		tb.Fatal(seeded.err)
	}
	target := seeded.src
	if seeded.db != nil { // SQLite: a private copy of the seeded file
		target = filepath.Join(tb.TempDir(), "two-tenants.db")
		if err := os.WriteFile(target, seeded.db, 0o600); err != nil {
			tb.Fatal(err)
		}
	} else { // Postgres: a database created from the seeded template
		target = store.TestClone(tb, seeded.src)
	}
	db, err := store.Open(context.Background(), target)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return &Fixture{DB: db, A: seeded.a.clone(), B: seeded.b.clone()}
}

func (t Tenant) clone() Tenant {
	return Tenant{ID: t.ID, Slug: t.Slug, IDs: maps.Clone(t.IDs), Refs: maps.Clone(t.Refs)}
}

func buildTemplate() {
	dir, err := os.MkdirTemp("", "tessera-storetest-")
	if err != nil {
		seeded.err = err
		return
	}
	defer os.RemoveAll(dir)
	// A SQLite file in dir, or (TESSERA_TEST_PG_URL) a Postgres template database.
	src, err := store.TestSharedTarget(dir, "two_tenants", seedTemplate)
	if err != nil {
		seeded.err = err
		return
	}
	if store.IsPostgresDSN(src) {
		seeded.src = src
		return
	}
	seeded.db, seeded.err = os.ReadFile(src) // #nosec G304 -- path made above
}

// seedTemplate seeds the two tenants into the (empty) database at target.
func seedTemplate(target string) error {
	ctx := context.Background()
	db, err := store.Open(ctx, target)
	if err != nil {
		return err
	}
	// seedTenant and seedReadiness report failures to a testing.TB; collect
	// them in a recorder so a failed seed fails every test that needs it.
	rec := &seedTB{}
	func() {
		defer func() {
			if p := recover(); p != nil && p != errSeedFailed {
				panic(p)
			}
		}()
		seeded.a = seedTenant(rec, db, AID, "tenant-a", Sentinel)
		seeded.b = seedTenant(rec, db, BID, "tenant-b", "")
		seedReadiness(rec, db, &seeded.a, "")
		seedReadiness(rec, db, &seeded.b, ReadinessSentinel)
	}()
	if rec.msg != "" {
		_ = db.Close()
		return errors.New(rec.msg)
	}
	if err := db.Checkpoint(ctx); err != nil {
		_ = db.Close()
		return err
	}
	return db.Close()
}

func seedTenant(tb testing.TB, db *store.DB, id tenancy.ID, slug, sentinel string) Tenant {
	tb.Helper()
	ctx := context.Background()
	if err := db.InSystem(ctx, "storetest", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: id, Slug: slug, Name: slug, CreatedAt: Now})
		return err
	}); err != nil {
		tb.Fatal(err)
	}
	t := Tenant{ID: id, Slug: slug, IDs: map[string]int64{}, Refs: map[string]string{}}
	mark := func(s string) string {
		if sentinel == "" {
			return s
		}
		return s + " " + sentinel
	}
	err := db.InTenant(ctx, id, func(c *store.TenantTx) error {
		if _, err := ingest.Sync(c, Now, []connectors.Connector{connectors.Tiny{Now: Now, Sentinel: sentinel}}, nil); err != nil {
			return err
		}
		if err := loadIDs(c, t.IDs); err != nil {
			return err
		}
		if err := seedIdentityModel(c, &t, mark); err != nil {
			return err
		}
		key := func(kind, k string) string { return fmt.Sprintf("%s:%d", kind, t.IDs[k]) }
		// JIT: a pending request, an active grant and one whose grant expired an hour ago.
		var err error
		if t.IDs["request:pending"], err = c.InsertRequest(&store.AccessRequest{IdentityID: t.IDs["alice"],
			AccountID: t.IDs["acct:okta:alice"], GroupID: t.IDs["group:aws:ProdAdmin"], Justification: mark("pending"),
			DurationHours: 1, Status: "pending", RequestedAt: Now}); err != nil {
			return err
		}
		for _, j := range []struct{ name, who string }{{"active", "bob"}, {"expired", "carol"}} {
			exp := Now.Add(time.Hour)
			if j.name == "expired" {
				exp = Now.Add(-time.Hour)
			}
			edge, err := c.InsertEdge(&store.GrantEdge{Src: key("account", "acct:okta:"+j.who),
				Dst: key("group", "group:aws:ProdAdmin"), Relation: "member_of", Source: "jit", ExpiresAt: &exp,
				CreatedAt: Now.Add(-2 * time.Hour)})
			if err != nil {
				return err
			}
			t.IDs["edge:jit-"+j.name] = edge
			decided, by := Now.Add(-2*time.Hour), mark("approver")
			rid, err := c.InsertRequest(&store.AccessRequest{IdentityID: t.IDs[j.who], AccountID: t.IDs["acct:okta:"+j.who],
				GroupID: t.IDs["group:aws:ProdAdmin"], Justification: mark(j.name), DurationHours: 1, Status: "approved",
				RequestedAt: decided, DecidedAt: &decided, DecidedBy: &by, ExpiresAt: &exp, EdgeID: &edge})
			if err != nil {
				return err
			}
			if j.name == "active" {
				t.IDs["request:approved"] = rid
			} else {
				t.IDs["request:expired"] = rid
			}
		}
		// A review campaign with one item on bob's approver grant.
		if t.IDs["campaign"], err = c.InsertCampaign(&store.ReviewCampaign{Name: mark("Q4 review"), CreatedAt: Now,
			Status: "open", UnusedDays: 60, TotalGrants: 1}); err != nil {
			return err
		}
		edge, err := c.EdgeBetween(key("account", "acct:okta:bob"), key("group", "group:okta:payments-approvers"))
		if err != nil {
			return err
		}
		ctxJSON, _ := json.Marshal(map[string]string{"note": mark("context")})
		reviewer := t.IDs["carol"]
		if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: t.IDs["campaign"], IdentityID: t.IDs["bob"],
			EdgeID: &edge.ID, EdgeSrc: edge.Src, EdgeDst: edge.Dst, GrantLabel: mark("bob → payments-approvers"),
			Reasons: []string{"policy_violation"}, Context: ctxJSON, ReviewerID: &reviewer}); err != nil {
			return err
		}
		items, err := c.CampaignItems(t.IDs["campaign"])
		if err != nil || len(items) != 1 {
			return fmt.Errorf("storetest: campaign items: %v %w", items, err)
		}
		t.IDs["item"] = items[0].ID
		// The campaign's frozen population: bob's grant, auto-certified and sampled for QA.
		if err := c.InsertReviewPopulation(&store.ReviewPopulation{CampaignID: t.IDs["campaign"], CreatedAt: Now,
			PopulationHash: "fixture-hash", ItemCount: 1, SystemCounts: json.RawMessage(`{"okta":1}`),
			SourceSyncs: json.RawMessage(`{"okta":null}`), Scope: json.RawMessage(`{}`), RulesVersion: "exception-only-v1",
			QASamplePct: 5}, []*store.PopulationRow{{CampaignID: t.IDs["campaign"], Ordinal: 1, EdgeID: edge.ID,
			IdentityID: t.IDs["bob"], IdentityRef: "bob", AccountRef: "bob", System: "okta",
			Entitlement: mark("payments-approvers"), EdgeSrc: edge.Src, EdgeDst: edge.Dst, InScopeReason: "standing_grant",
			Disposition: "auto_certified"}}); err != nil {
			return err
		}
		if err := c.InsertAutoDecision(&store.AutoDecision{CampaignID: t.IDs["campaign"], Ordinal: 1, EdgeID: edge.ID,
			IdentityID: t.IDs["bob"], Rule: json.RawMessage(`{"id":"exception_only.no_exception_signals","version":1,"note":"` +
				mark("rule") + `"}`), QASample: true}); err != nil {
			return err
		}
		ads, err := c.AutoDecisions(t.IDs["campaign"])
		if err != nil || len(ads) != 1 {
			return fmt.Errorf("storetest: auto-decisions: %v %w", ads, err)
		}
		t.IDs["qa"] = ads[0].ID
		// HRIS: a pending leaver for alice and a pending joiner.
		alice := t.IDs["alice"]
		if t.IDs["hris:leaver"], err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-leaver", Type: "leaver",
			IdentityID: &alice, Payload: ojson.Object{{Key: "reason", Value: mark("leaving")}}, EffectiveAt: Now,
			Status: "pending"}); err != nil {
			return err
		}
		if t.IDs["hris:joiner"], err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "evt-joiner", Type: "joiner",
			Payload: ojson.Object{{Key: "name", Value: mark("New Hire")}, {Key: "team", Value: "backend"},
				{Key: "email", Value: "new.hire@t.example"}}, EffectiveAt: Now, Status: "pending"}); err != nil {
			return err
		}
		secrets, err := c.Secrets()
		if err != nil || len(secrets) != 1 {
			return fmt.Errorf("storetest: secrets: %v %w", secrets, err)
		}
		t.IDs["secret"] = secrets[0].ID
		dels, err := c.Delegations()
		if err != nil || len(dels) != 1 {
			return fmt.Errorf("storetest: delegations: %v %w", dels, err)
		}
		t.IDs["delegation"] = dels[0].ID
		edges, err := c.Edges()
		if err != nil {
			return err
		}
		for i, e := range edges {
			t.IDs[fmt.Sprintf("edge:%d", i)] = e.ID
		}
		return c.Audit(Now, mark("auditor"), "storetest.seeded", ojson.Object{{Key: "tenant", Value: mark(slug)}})
	})
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

func loadIDs(c *store.TenantTx, ids map[string]int64) error {
	idents, err := c.Identities()
	if err != nil {
		return err
	}
	for _, i := range idents {
		ids[i.ExternalID] = i.ID
	}
	accts, err := c.Accounts()
	if err != nil {
		return err
	}
	for _, a := range accts {
		ids["acct:"+a.System+":"+a.ExternalID] = a.ID
	}
	groups, err := c.Groups()
	if err != nil {
		return err
	}
	for _, g := range groups {
		ids["group:"+g.System+":"+g.ExternalID] = g.ID
	}
	perms, err := c.Permissions()
	if err != nil {
		return err
	}
	for _, p := range perms {
		ids["perm:"+p.System+":"+p.ExternalID] = p.ID
	}
	res, err := c.Resources()
	if err != nil {
		return err
	}
	for _, r := range res {
		ids["resource:"+r.System+":"+r.ExternalID] = r.ID
	}
	return nil
}

// Dump reads every row of a tenant through the tenant-scoped repositories and
// returns it as JSON, so a test can assert that operations in another tenant
// left it byte-for-byte unchanged.
func Dump(tb testing.TB, db *store.DB, t tenancy.ID) string {
	tb.Helper()
	out := map[string]any{}
	err := db.ReadTenant(context.Background(), t, func(c *store.TenantTx) error {
		var err error
		get := func(name string, v any, e error) {
			if err == nil {
				err = e
			}
			out[name] = v
		}
		v1, e := c.Identities()
		get("identities", v1, e)
		v2, e := c.Accounts()
		get("accounts", v2, e)
		v3, e := c.Groups()
		get("groups", v3, e)
		v4, e := c.Resources()
		get("resources", v4, e)
		v5, e := c.Permissions()
		get("permissions", v5, e)
		v6, e := c.Edges()
		get("grant_edges", v6, e)
		v7, e := c.Secrets()
		get("secrets", v7, e)
		v8, e := c.Delegations()
		get("agent_delegations", v8, e)
		v9, e := c.UsageAggregates(time.Time{})
		get("usage_events", v9, e)
		n, e := c.CountUsageEvents()
		get("usage_events_count", n, e)
		v10, e := c.RequestsByRecency()
		get("access_requests", v10, e)
		v11, e := c.CampaignsNewestFirst()
		get("review_campaigns", v11, e)
		var items []*store.ReviewItem
		for _, cmp := range v11 {
			it, e := c.CampaignItems(cmp.ID)
			get("review_items", nil, e)
			items = append(items, it...)
		}
		out["review_items"] = items
		var pops []*store.ReviewPopulation
		var prows []*store.PopulationRow
		var autos []*store.AutoDecision
		for _, cmp := range v11 {
			if pop, e := c.ReviewPopulation(cmp.ID); e == nil {
				pops = append(pops, pop)
			} else if !errors.Is(e, store.ErrNotFound) {
				get("review_populations", nil, e)
			}
			r, e := c.PopulationRows(cmp.ID)
			get("review_population_rows", nil, e)
			prows = append(prows, r...)
			a, e := c.AutoDecisions(cmp.ID)
			get("review_auto_decisions", nil, e)
			autos = append(autos, a...)
		}
		out["review_populations"], out["review_population_rows"], out["review_auto_decisions"] = pops, prows, autos
		qs, _, e2 := c.TenantSetting("qa_sample_pct")
		get("tenant_settings", qs, e2)
		v12, e := c.HrisEvents()
		get("hris_events", v12, e)
		v13, e := c.AuditLog(-1)
		get("audit_log", v13, e)
		v14, e := c.EdgeSpans()
		get("edge_history", v14, e)
		v15, e := c.EvidencePacks()
		get("evidence_packs", v15, e)
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		tb.Fatal(err)
	}
	return string(b)
}

// IdentityKEK is the fixture's key-encryption key (identifier hashing only).
var IdentityKEK = []byte("storetest-kek-0123456789abcdef!!")

// IdentityKeyer hashes identifiers under IdentityKEK.
func IdentityKeyer(tb testing.TB) *identifiers.Keyer {
	tb.Helper()
	s, err := seal.New(IdentityKEK)
	if err != nil {
		tb.Fatal(err)
	}
	return identifiers.NewKeyer(s)
}

// seedIdentityModel adds the populations, each person's back-filled source
// record, affiliation and identifiers, and one guest affiliation for alice
// whose org unit carries the tenant's sentinel (Refs["affiliation:guest"]).
func seedIdentityModel(c *store.TenantTx, t *Tenant, mark func(string) string) error {
	if err := identity.SeedPopulations(c, Now); err != nil {
		return err
	}
	// the keyer is only needed for hashing; a failure here is a fixture bug
	s, err := seal.New(IdentityKEK)
	if err != nil {
		return err
	}
	if _, err := identity.Backfill(c, identifiers.NewKeyer(s), Now); err != nil {
		return err
	}
	unit, pop, end := mark("Visitor Services"), "guest", Now.Add(30*24*time.Hour)
	a := &store.Affiliation{ID: uuid.NewString(), IdentityID: t.IDs["alice"], Type: store.AffGuestVisitor,
		Source: store.AffSourceManual, OrgUnit: &unit, Population: &pop, StartsAt: Now, EndsAt: &end,
		Status: store.AffActive, CreatedAt: Now}
	if err := c.InsertAffiliation(a); err != nil {
		return err
	}
	t.Refs["affiliation:guest"] = a.ID
	return seedIntake(c, t, a, mark)
}

// seedIntake adds an organizational sponsor, an intake event whose detail
// carries the tenant's sentinel (Refs["intake"]) and a conversion of alice
// from her employee affiliation to the guest one (Refs["conversion"]).
func seedIntake(c *store.TenantTx, t *Tenant, guest *store.Affiliation, mark func(string) string) error {
	if err := c.PutOrgSponsor(&store.OrgSponsor{Key: "admissions", Name: mark("Office of Admissions"),
		Population: "applicant", CreatedAt: Now}); err != nil {
		return err
	}
	sponsor, eff := "admissions", Now
	rec := &store.IntakeEvent{ID: uuid.NewString(), Channel: store.ChannelSIS, MatchMode: store.MatchAuthoritative,
		SponsorOrg: &sponsor, EventKey: "sis:evt-1", EventType: "admitted", EffectiveAt: &eff, Status: store.IntakeEventResolved,
		Detail: `{"outcome":"started","note":"` + mark("fixture") + `"}`, CreatedAt: Now}
	if err := c.InsertIntakeEvent(rec); err != nil {
		return err
	}
	t.Refs["intake"] = rec.ID
	affs, err := c.AffiliationsFor(t.IDs["alice"])
	if err != nil {
		return err
	}
	for _, from := range affs {
		if from.Type != store.AffEmployee {
			continue
		}
		v := &store.Conversion{ID: uuid.NewString(), IdentityID: t.IDs["alice"], FromAffiliationID: from.ID,
			ToAffiliationID: guest.ID, FromType: from.Type, ToType: guest.Type, Trigger: store.ConvSISStatus,
			IntakeID: &rec.ID, EffectiveAt: Now, CreatedAt: Now}
		if err := c.InsertConversion(v); err != nil {
			return err
		}
		t.Refs["conversion"] = v.ID
		return nil
	}
	return errors.New("storetest: alice has no employee affiliation")
}

var errSeedFailed = errors.New("storetest: seed failed")

// seedTB is the testing.TB the one-time seed reports to: Fatal records the
// message and unwinds buildTemplate. Only the methods the seed helpers call
// are implemented.
type seedTB struct {
	testing.TB
	msg string
}

func (s *seedTB) Helper() {}

func (s *seedTB) Fatal(args ...any) {
	s.msg = fmt.Sprint(args...)
	panic(errSeedFailed)
}

func (s *seedTB) Fatalf(format string, args ...any) {
	s.msg = fmt.Sprintf(format, args...)
	panic(errSeedFailed)
}
