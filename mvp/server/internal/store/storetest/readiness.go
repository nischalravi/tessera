package storetest

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ReadinessSentinel appears in tenant B's deployment-readiness rows: a
// connection name and owner, an attestation note, a skip reason, an overlay
// item, a check result message, a finding title, a staged identity and a
// score breakdown. No readiness route or store read in tenant A may return it.
// (The graph fixture marks tenant A instead; the readiness tests read as A.)
const ReadinessSentinel = "ZZ-GLOBEX-READINESS-SENTINEL"

// Readiness keys in Tenant.Refs (every value is a UUID):
//
//	connection      the Okta (demo) connection (validated and dry-run reconciled by readiness.SeedDemo)
//	revision        its revision
//	run:live        its latest validation run
//	run:dry         its dry run (also the reconciliation run id)
//	finding         one of that dry run's findings
//	connection:ad   a draft AD connection whose name, owner, attestation and skip carry the sentinel
//	revision:ad     its revision
//	run:ad-live     a completed validation run on it, with one marked result
//	run:ad-dry      a completed dry run on it, with one marked finding and marked staged rows
//	run:ad-running  a validation run still running
//	finding:ad      the marked finding
//	item:ad-skip    the skipped Recommended item of the AD connection
//
// The AD revision also has a drift baseline (readiness_baselines) with a
// marked snapshot and degraded reason.
func seedReadiness(tb testing.TB, db *store.DB, t *Tenant, sentinel string) {
	tb.Helper()
	mark := func(s string) string {
		if sentinel == "" {
			return s
		}
		return s + " " + sentinel
	}
	ctx := context.Background()
	svc := readiness.NewService(template.MustDefault(), "dev")
	scope := readiness.Scope{DB: db, Tenant: t.ID}
	clock := func() time.Time { return Now }
	stage := func(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) error {
		_, err := ingest.Stage(c, runID, system, res)
		return err
	}
	if err := svc.SeedDemo(ctx, scope, clock, stage); err != nil {
		tb.Fatalf("storetest: readiness demo in %s: %v", t.Slug, err)
	}
	refs := t.Refs
	err := scope.Write(ctx, func(c *store.TenantTx) error {
		conns, err := c.Connections()
		if err != nil || len(conns) != 1 {
			return fmt.Errorf("storetest: connections %v %w", conns, err)
		}
		refs["connection"] = conns[0].ID
		revs, err := c.Revisions(conns[0].ID)
		if err != nil {
			return err
		}
		refs["revision"] = revs[0].ID
		live, err := c.LatestLiveRun(revs[0].ID)
		if err != nil || live == nil {
			return fmt.Errorf("storetest: no validation run: %w", err)
		}
		refs["run:live"] = live.ID
		dry, err := c.LatestDryRun(revs[0].ID)
		if err != nil || dry == nil {
			return fmt.Errorf("storetest: no dry run: %w", err)
		}
		refs["run:dry"] = dry.ID
		fs, err := c.RunFindings(dry.ID)
		if err != nil || len(fs) == 0 {
			return fmt.Errorf("storetest: no findings: %w", err)
		}
		refs["finding"] = fs[0].ID

		// A tenant overlay with a marked custom item.
		overlay, _ := json.Marshal(map[string]any{"add_items": []map[string]any{{"id": "custom.change_ticket",
			"title": mark("Change ticket linked"), "category": "ownership", "level": "required", "why": "Auditors ask for it.",
			"verify": []map[string]string{{"kind": "attestation"}}, "remediation": map[string]string{"hint": "Link the ticket."}}}})
		if _, err := svc.PutOverlay(c, "ad", overlay, "admin", Now); err != nil {
			return err
		}
		// A marked AD connection with a marked attestation and skip.
		cfg, _ := json.Marshal(map[string]any{"technical_owner": mark("Ingrid Lindqvist"), "business_owner": "Thandiwe Mokoena"})
		b, err := svc.Create(c, readiness.CreateInput{Name: mark("Active Directory"), ConnectorType: "demo-ad", Config: cfg},
			"admin", Now)
		if err != nil {
			return err
		}
		ad := b.Conn.ID
		refs["connection:ad"], refs["revision:ad"] = ad, b.Rev.ID
		if _, err := svc.Attest(c, ad, "base.owner", mark("Owners agreed in CHG-1042"), "admin", Now); err != nil {
			return err
		}
		if err := c.UpsertLiveAttestation(&store.LiveAttestation{RevisionID: b.Rev.ID, ItemID: "ldap.svc.no_write", ActorID: "admin",
			Attester: mark("Ingrid Lindqvist"), Reason: mark("The directory has no Get Effective Rights control"),
			Evidence: mark("ACL export reviewed in CHG-1043"), ItemHash: "h", ConfigHash: b.ConfigHash, AttestedAt: Now}); err != nil {
			return err
		}
		for _, it := range b.Eval.Items {
			if it.Level != template.Recommended || !it.Applicable || len(it.DependsOn) > 0 {
				continue
			}
			if _, err := svc.Skip(c, ad, it.ID, mark("Accepted gap until the Q1 migration"), nil, "admin", Now); err == nil {
				refs["item:ad-skip"] = it.ID
				break
			}
		}
		if refs["item:ad-skip"] == "" {
			return fmt.Errorf("storetest: no skippable item on the AD connection")
		}
		// Runs, results, findings, staging and a score written directly.
		at := Now.Add(time.Minute)
		runs := map[string]*store.CheckRun{
			"run:ad-live":    {Kind: "validation", Status: "completed"},
			"run:ad-dry":     {Kind: "dry_run", Status: "completed"},
			"run:ad-running": {Kind: "validation", Status: "running"},
		}
		for _, k := range []string{"run:ad-live", "run:ad-dry", "run:ad-running"} {
			r := runs[k]
			r.ID, r.RevisionID, r.Simulated, r.ActorID, r.ConfigHash, r.StartedAt = store.NewID(), b.Rev.ID, true, "admin",
				b.ConfigHash, at
			if err := c.InsertCheckRun(r); err != nil {
				return err
			}
			if r.Status == "completed" {
				if err := c.FinishCheckRun(r.ID, "completed", at); err != nil {
					return err
				}
			}
			refs[k] = r.ID
		}
		if err := c.InsertCheckResult(&store.CheckResult{RunID: refs["run:ad-live"], ItemID: "ad.bind", CheckID: "bind",
			Status: "fail", Observed: "{}", Message: mark("bind refused"), ItemHash: "x", Simulated: true}); err != nil {
			return err
		}
		dryID := refs["run:ad-dry"]
		if err := c.InsertReconRun(&store.ReconRun{ID: dryID, RevisionID: b.Rev.ID, ConnectionID: ad, Mode: "staging",
			CheckRunID: dryID, Counts: "{}", Status: "completed", StartedAt: at, FinishedAt: &at}); err != nil {
			return err
		}
		refs["finding:ad"] = store.NewID()
		if err := c.InsertFinding(&store.Finding{ID: refs["finding:ad"], RunID: dryID, ConnectionID: ad, Code: "RF-01",
			Title: mark("Orphan accounts"), Severity: "high", Count: 1, Denominator: 10, Samples: "[]", Impact: "{}",
			Status: "open", FirstSeenAt: at, LastSeenAt: at}); err != nil {
			return err
		}
		email := "zz.marked@corp.example"
		if err := c.InsertStagedIdentity(&store.StagedIdentity{RunID: dryID, ExternalID: "w-1", Name: mark("Staged Person"),
			Email: &email}); err != nil {
			return err
		}
		if err := c.InsertStagedAccount(&store.StagedAccount{RunID: dryID, System: "ad-corp", ExternalID: "S-1",
			Username: mark("staged.user"), Kind: "user", Status: "active"}); err != nil {
			return err
		}
		if err := c.InsertStagedGroup(&store.StagedGroup{RunID: dryID, System: "ad-corp", ExternalID: "G-1",
			Name: mark("Domain Admins"), Kind: "group", Privileged: true, InScope: true}); err != nil {
			return err
		}
		if err := c.InsertStagedMembership(dryID, store.StagedMembership{MemberKind: "account", MemberXID: "S-1",
			GroupXID: "G-1"}); err != nil {
			return err
		}
		if err := c.InsertAttrStat(dryID, store.AttrStat{Class: "user", Attribute: mark("employeeID"), Total: 1,
			Present: 1, Distinct: 1}); err != nil {
			return err
		}
		if err := c.SetStagedCorrelation(dryID, "ad-corp", "S-1", "correlated", 1, ptr(t.IDs["alice"]), nil); err != nil {
			return err
		}
		snapshot, _ := json.Marshal(map[string]string{"note": mark("baseline")})
		reason := mark("Required live check failed on 2 consecutive scheduled runs")
		if err := c.InsertBaseline(&store.Baseline{RevisionID: b.Rev.ID, CapturedAt: at, Score: 42, ConfigHash: b.ConfigHash,
			Snapshot: string(snapshot), FailStreak: 1, DegradedReason: &reason}); err != nil {
			return err
		}
		breakdown, _ := json.Marshal(map[string]string{"note": mark("score")})
		return c.RecordScore(&store.ScoreRow{Scope: "connection", ConnectionID: &ad, RevisionID: &b.Rev.ID, ComputedAt: at,
			Score: 42, Band: "at_risk", Breakdown: string(breakdown)})
	})
	if err != nil {
		tb.Fatalf("storetest: readiness rows in %s: %v", t.Slug, err)
	}
}

func ptr[T any](v T) *T { return &v }

// ReadinessDump reads every readiness row of a tenant (the rows the fixture
// created and anything added since) through the tenant-scoped repositories.
func ReadinessDump(tb testing.TB, db *store.DB, t tenancy.ID, refs map[string]string) string {
	tb.Helper()
	out := map[string]any{}
	err := db.ReadTenant(context.Background(), t, func(c *store.TenantTx) error {
		var first error
		put := func(k string, v any, err error) {
			if first == nil {
				first = err
			}
			out[k] = v
		}
		conns, err := c.Connections()
		put("connections", conns, err)
		for _, cn := range conns {
			revs, err := c.Revisions(cn.ID)
			put("revisions:"+cn.ID, revs, err)
			for _, r := range revs {
				v1, e := c.Attestations(r.ID)
				put("attestations:"+r.ID, v1, e)
				v1b, e := c.LiveAttestations(r.ID)
				put("live_attestations:"+r.ID, v1b, e)
				v2, e := c.Skips(r.ID)
				put("skips:"+r.ID, v2, e)
				v3, e := c.ItemStates(r.ID)
				put("item_states:"+r.ID, v3, e)
			}
			s, e := c.ScoreSeries("connection", &cn.ID, 1000)
			put("scores:"+cn.ID, s, e)
		}
		s, e := c.ScoreSeries("tenant", nil, 1000)
		put("scores:tenant", s, e)
		bls, e := c.Baselines()
		put("baselines", bls, e)
		k, e := c.AllSkips()
		put("skips", k, e)
		o, e := c.LatestOverlay("ad")
		put("overlay:ad", o, e)
		for _, key := range []string{"run:live", "run:dry", "run:ad-live", "run:ad-dry", "run:ad-running"} {
			id := refs[key]
			r, e := c.CheckRun(id)
			put("run:"+key, r, e)
			res, e := c.CheckResults(id)
			put("results:"+key, res, e)
		}
		for _, key := range []string{"run:dry", "run:ad-dry"} {
			id := refs[key]
			rr, e := c.ReconRunByID(id)
			put("recon:"+key, rr, e)
			f, e := c.RunFindings(id)
			put("findings:"+key, f, e)
			sa, e := c.StagedAccounts(id)
			put("stg_accounts:"+key, sa, e)
			si, e := c.StagedIdentities(id)
			put("stg_identities:"+key, si, e)
			sg, e := c.StagedGroups(id)
			put("stg_groups:"+key, sg, e)
			sm, e := c.StagedMemberships(id)
			put("stg_memberships:"+key, sm, e)
			as, e := c.AttrStats(id)
			put("stg_attr_stats:"+key, as, e)
		}
		return first
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
