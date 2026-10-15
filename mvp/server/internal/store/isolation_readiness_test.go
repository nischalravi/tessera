package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Deployment-readiness isolation tests. Both fixture tenants hold the same
// readiness rows; tenant B's carry storetest.ReadinessSentinel, and every
// read here runs as tenant A.

type refs = map[string]string

func hasReadinessSentinel(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(storetest.ReadinessSentinel))
}

func inA(t *testing.T, f *storetest.Fixture, fn func(*store.TenantTx) error) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), f.A.ID, fn); err != nil {
		t.Fatal(err)
	}
}

// readinessLists are the readiness list repositories. Called as A with A's
// refs they return rows and nothing of B's; called with B's refs (the
// parameterized ones) they return nothing.
var readinessLists = map[string]func(c *store.TenantTx, r refs) (any, error){
	"Connections":  func(c *store.TenantTx, _ refs) (any, error) { return c.Connections() },
	"Revisions":    func(c *store.TenantTx, r refs) (any, error) { return c.Revisions(r["connection:ad"]) },
	"Attestations": func(c *store.TenantTx, r refs) (any, error) { return c.Attestations(r["revision:ad"]) },
	"Skips":        func(c *store.TenantTx, r refs) (any, error) { return c.Skips(r["revision:ad"]) },
	"AllSkips":     func(c *store.TenantTx, _ refs) (any, error) { return c.AllSkips() },
	"ItemStates":   func(c *store.TenantTx, r refs) (any, error) { return c.ItemStates(r["revision:ad"]) },
	"CheckResults": func(c *store.TenantTx, r refs) (any, error) { return c.CheckResults(r["run:ad-live"]) },
	"RunFindings":  func(c *store.TenantTx, r refs) (any, error) { return c.RunFindings(r["run:ad-dry"]) },
	"PreviousFindings": func(c *store.TenantTx, r refs) (any, error) {
		return c.PreviousFindings(r["connection:ad"], "")
	},
	"ScoreSeries": func(c *store.TenantTx, r refs) (any, error) {
		id := r["connection:ad"]
		return c.ScoreSeries("connection", &id, 100)
	},
	"StagedAccounts":    func(c *store.TenantTx, r refs) (any, error) { return c.StagedAccounts(r["run:ad-dry"]) },
	"StagedIdentities":  func(c *store.TenantTx, r refs) (any, error) { return c.StagedIdentities(r["run:ad-dry"]) },
	"StagedGroups":      func(c *store.TenantTx, r refs) (any, error) { return c.StagedGroups(r["run:ad-dry"]) },
	"StagedMemberships": func(c *store.TenantTx, r refs) (any, error) { return c.StagedMemberships(r["run:ad-dry"]) },
	"AttrStats":         func(c *store.TenantTx, r refs) (any, error) { return c.AttrStats(r["run:ad-dry"]) },
	"OwnedIdentityXIDs": func(c *store.TenantTx, _ refs) (any, error) { return c.OwnedIdentityXIDs() },
}

var readinessUnparameterized = []string{"Connections", "AllSkips", "OwnedIdentityXIDs"}

func TestIsolation_ReadinessRepoReturnsOnlyOwnRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	// Positive control: tenant B's own rows carry the sentinel.
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		got, err := c.Connections()
		if err == nil && !hasReadinessSentinel(got) {
			t.Fatal("tenant B's connections do not carry the readiness sentinel; the leak check would never fire")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, fn := range readinessLists {
		t.Run(name, func(t *testing.T) {
			inA(t, f, func(c *store.TenantTx) error {
				got, err := fn(c, f.A.Refs)
				if err != nil {
					return err
				}
				if reflect.ValueOf(got).Len() == 0 {
					t.Fatalf("%s returned nothing for tenant A (the fixture should give it rows)", name)
				}
				if hasReadinessSentinel(got) {
					t.Errorf("%s in tenant A returned tenant B data", name)
				}
				if b, _ := json.Marshal(got); strings.Contains(string(b), f.B.ID.String()) {
					t.Errorf("%s in tenant A returned a row stamped with tenant B", name)
				}
				if !slices.Contains(readinessUnparameterized, name) {
					other, err := fn(c, f.B.Refs)
					if err != nil {
						return err
					}
					if n := reflect.ValueOf(other).Len(); n != 0 {
						t.Errorf("%s with tenant B's id returned %d rows in tenant A", name, n)
					}
				}
				return nil
			})
		})
	}
}

// notNil turns a nil "latest" row into ErrNotFound.
func notNil[T any](v *T, err error) (any, error) {
	if err == nil && v == nil {
		return nil, store.ErrNotFound
	}
	return v, err
}

// readinessGets are the single-row readiness repositories: given tenant B's
// id in tenant A they report ErrNotFound (or nothing), exactly like a missing id.
var readinessGets = map[string]func(c *store.TenantTx, r refs) (any, error){
	"Connection":     func(c *store.TenantTx, r refs) (any, error) { return c.Connection(r["connection:ad"]) },
	"Revision":       func(c *store.TenantTx, r refs) (any, error) { return c.Revision(r["revision:ad"]) },
	"CheckRun":       func(c *store.TenantTx, r refs) (any, error) { return c.CheckRun(r["run:ad-live"]) },
	"ReconRunByID":   func(c *store.TenantTx, r refs) (any, error) { return c.ReconRunByID(r["run:ad-dry"]) },
	"FindingByID":    func(c *store.TenantTx, r refs) (any, error) { return c.FindingByID(r["finding:ad"]) },
	"LatestLiveRun":  func(c *store.TenantTx, r refs) (any, error) { return notNil(c.LatestLiveRun(r["revision:ad"])) },
	"LatestDryRun":   func(c *store.TenantTx, r refs) (any, error) { return notNil(c.LatestDryRun(r["revision:ad"])) },
	"RunningLiveRun": func(c *store.TenantTx, r refs) (any, error) { return notNil(c.RunningLiveRun(r["revision:ad"])) },
}

// readinessNaturalKeys look overlays up by template id, which both tenants share.
var readinessNaturalKeys = map[string]func(c *store.TenantTx) (any, error){
	"LatestOverlay":  func(c *store.TenantTx) (any, error) { return notNil(c.LatestOverlay("ad")) },
	"OverlayVersion": func(c *store.TenantTx) (any, error) { return c.OverlayVersion("ad", 1) },
}

func TestIsolation_ReadinessGetOtherTenantNotFound(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, fn := range readinessGets {
		t.Run(name, func(t *testing.T) {
			inA(t, f, func(c *store.TenantTx) error {
				if _, err := fn(c, f.A.Refs); err != nil {
					t.Fatalf("own row: %v", err)
				}
				got, err := fn(c, f.B.Refs)
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("tenant B's row from tenant A: err = %v, want ErrNotFound", err)
				}
				if hasReadinessSentinel(got) {
					t.Errorf("tenant B's row leaked: %v", got)
				}
				return nil
			})
		})
	}
	for name, fn := range readinessNaturalKeys {
		t.Run(name, func(t *testing.T) {
			for _, tn := range []storetest.Tenant{f.A, f.B} {
				err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
					got, err := fn(c)
					if err != nil {
						return err
					}
					if hasReadinessSentinel(got) != (tn.ID == f.B.ID) {
						t.Errorf("%s in %s returned another tenant's overlay: %v", name, tn.Slug, got)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// readinessCounts must be equal and non-zero in both tenants (an unscoped
// count would be larger), and zero for the other tenant's ids.
var readinessCounts = map[string]func(c *store.TenantTx, r refs) (int, error){
	"CountCheckRunsSince": func(c *store.TenantTx, r refs) (int, error) {
		return c.CountCheckRunsSince(r["revision:ad"], "validation", time.Time{})
	},
	"StagedPrivilegedAccounts": func(c *store.TenantTx, r refs) (int, error) {
		return c.StagedPrivilegedAccounts(r["run:ad-dry"])
	},
}

func TestIsolation_ReadinessCountsOnlyOwnRows(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, fn := range readinessCounts {
		t.Run(name, func(t *testing.T) {
			counts := map[string]int{}
			for _, tn := range []storetest.Tenant{f.A, f.B} {
				err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
					n, err := fn(c, tn.Refs)
					counts[tn.Slug] = n
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if counts["tenant-a"] == 0 || counts["tenant-a"] != counts["tenant-b"] {
				t.Errorf("counts %v, want equal and non-zero", counts)
			}
			inA(t, f, func(c *store.TenantTx) error {
				if n, err := fn(c, f.B.Refs); err != nil || n != 0 {
					t.Errorf("tenant B's ids from tenant A: %d %v", n, err)
				}
				return nil
			})
		})
	}
	// At most one dry run in flight per tenant: B's running dry run does not
	// count in A.
	inA(t, f, func(c *store.TenantTx) error {
		n, err := c.RunningDryRuns()
		if err == nil && n != 0 {
			t.Errorf("RunningDryRuns in A = %d, want 0", n)
		}
		return err
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertCheckRun(&store.CheckRun{ID: store.NewID(), RevisionID: f.B.Refs["revision:ad"], Kind: "dry_run",
			Status: "running", ActorID: "b", ConfigHash: "x", StartedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		n, err := c.RunningDryRuns()
		if err == nil && n != 0 {
			t.Errorf("tenant B's running dry run counts in A: %d", n)
		}
		return err
	})
}

// ignoreConflict: a compare-and-set on another tenant's row is a lost race.
func ignoreConflict(err error) error {
	if errors.Is(err, store.ErrStateConflict) {
		return nil
	}
	return err
}

// readinessMutations run in tenant A with tenant B's ids. Tenant B must be
// byte-for-byte unchanged afterwards.
var readinessMutations = map[string]func(c *store.TenantTx, a, b refs) error{
	"UpdateConnectionOwners": func(c *store.TenantTx, _, b refs) error {
		x := "x"
		return c.UpdateConnectionOwners(b["connection:ad"], &x, &x, storetest.Now)
	},
	"SetConnectionLive": func(c *store.TenantTx, _, b refs) error {
		return c.SetConnectionLive(b["connection"], nil, "degraded", storetest.Now)
	},
	"MarkConnectionRetired": func(c *store.TenantTx, _, b refs) error {
		return c.MarkConnectionRetired(b["connection:ad"], storetest.Now)
	},
	"UpdateRevisionConfig": func(c *store.TenantTx, _, b refs) error {
		return c.UpdateRevisionConfig(b["revision:ad"], "{}", "h", "off", nil, storetest.Now)
	},
	"UpdateRevisionSecret": func(c *store.TenantTx, _, b refs) error {
		return c.UpdateRevisionSecret(b["revision:ad"], "vault:x", "1", "h", storetest.Now)
	},
	"BumpEvidence": func(c *store.TenantTx, _, b refs) error { return c.BumpEvidence(b["revision:ad"], storetest.Now) },
	"SetRevisionState": func(c *store.TenantTx, _, b refs) error {
		return ignoreConflict(c.SetRevisionState(store.StateChange{RevisionID: b["revision:ad"], From: store.StateDraft,
			To: store.StateRetired, Now: storetest.Now}))
	},
	"DeleteSkip": func(c *store.TenantTx, _, b refs) error {
		_, err := c.DeleteSkip(b["revision:ad"], b["item:ad-skip"])
		return err
	},
	"ReplaceItemStates": func(c *store.TenantTx, _, b refs) error { return c.ReplaceItemStates(b["revision:ad"], nil) },
	"FinishCheckRun": func(c *store.TenantTx, _, b refs) error {
		return c.FinishCheckRun(b["run:ad-running"], "aborted", storetest.Now)
	},
	"DeleteCheckResults": func(c *store.TenantTx, _, b refs) error { return c.DeleteCheckResults(b["run:ad-live"]) },
	"FinishReconRun": func(c *store.TenantTx, _, b refs) error {
		return c.FinishReconRun(b["run:ad-dry"], "aborted", "{}", storetest.Now)
	},
	"AcceptFinding": func(c *store.TenantTx, _, b refs) error {
		_, err := c.FindingByID(b["finding:ad"])
		if !errors.Is(err, store.ErrNotFound) {
			return errors.New("tenant B's finding is visible")
		}
		return ignoreConflict(c.AcceptFinding(b["finding:ad"], "a", "accepted from the wrong tenant", nil))
	},
	"ResolveFinding": func(c *store.TenantTx, _, b refs) error { return c.ResolveFinding(b["finding:ad"]) },
	"PruneStaging":   func(c *store.TenantTx, _, b refs) error { return c.PruneStaging(b["revision:ad"], 0) },
	"SetStagedCorrelation": func(c *store.TenantTx, _, b refs) error {
		return c.SetStagedCorrelation(b["run:ad-dry"], "ad-corp", "S-1", "uncorrelated", 0, nil, nil)
	},
	// Inserts of A's own rows with natural keys B also has.
	"InsertOverlay": func(c *store.TenantTx, _, _ refs) error {
		return c.InsertOverlay(&store.OverlayRow{ID: store.NewID(), ConnectorType: "ad", Version: 2, Body: "{}",
			UpdatedBy: "a", UpdatedAt: storetest.Now})
	},
	"InsertAttrStat": func(c *store.TenantTx, a, _ refs) error {
		return c.InsertAttrStat(a["run:ad-dry"], store.AttrStat{Class: "user", Attribute: "mail", Total: 1})
	},
}

func TestIsolation_ReadinessMutationsScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs)
	beforeA := storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs)
	for name, fn := range readinessMutations {
		t.Run(name, func(t *testing.T) {
			inA(t, f, func(c *store.TenantTx) error { return fn(c, f.A.Refs, f.B.Refs) })
			if after := storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs); after != before {
				t.Fatalf("%s in tenant A changed tenant B", name)
			}
		})
	}
	if storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs) == beforeA {
		t.Error("the mutations changed nothing in tenant A; the test is not exercising them")
	}
}

func TestIsolation_ReadinessInsertWrongTenantRejected(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs)
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"InsertConnection": func(c *store.TenantTx) error {
			return c.InsertConnection(&store.Connection{ID: store.NewID(), TenantID: f.B.ID, Name: "x", ConnectorType: "demo-ad",
				System: "x", Role: "account_source", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
		"InsertRevision": func(c *store.TenantTx) error {
			return c.InsertRevision(&store.ConnectionRevision{ID: store.NewID(), TenantID: f.B.ID,
				ConnectionID: f.A.Refs["connection:ad"], Rev: 9, TemplateID: "ad", TemplateVersion: "1.0", Config: "{}",
				ConfigHash: "h", WriteMode: "off", CreatedBy: "a", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.A.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs) != before {
		t.Error("a rejected insert left a row behind")
	}
}

// readinessCrossRefs write, inside A, a row whose reference points at one of
// B's readiness rows (or, for staged correlation, B's identity). The guard
// triggers refuse each with ErrCrossTenant.
var readinessCrossRefs = map[string]func(c *store.TenantTx, a, b refs, bIdentity int64) error{
	"InsertRevision.connection_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertRevision(&store.ConnectionRevision{ID: store.NewID(), ConnectionID: b["connection:ad"], Rev: 9,
			TemplateID: "ad", TemplateVersion: "1.0", Config: "{}", ConfigHash: "h", WriteMode: "off", CreatedBy: "a",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	},
	"SetConnectionLive.active_revision_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		rev := b["revision"]
		return c.SetConnectionLive(a["connection"], &rev, "ok", storetest.Now)
	},
	"UpsertAttestation.revision_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.UpsertAttestation(&store.Attestation{RevisionID: b["revision:ad"], ItemID: "base.owner", ActorID: "a",
			Note: "attested across tenants", ItemHash: "x", ConfigHash: "x", AttestedAt: storetest.Now})
	},
	"UpsertSkip.revision_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		return c.UpsertSkip(&store.Skip{RevisionID: b["revision:ad"], ConnectionID: a["connection:ad"], ItemID: "x.y",
			Level: "recommended", ActorID: "a", Reason: "skipped across the tenant boundary", ReviewBy: storetest.Now,
			TemplateVersion: "1.0", SkippedAt: storetest.Now})
	},
	"UpsertSkip.connection_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		return c.UpsertSkip(&store.Skip{RevisionID: a["revision:ad"], ConnectionID: b["connection:ad"], ItemID: "x.y",
			Level: "recommended", ActorID: "a", Reason: "skipped across the tenant boundary", ReviewBy: storetest.Now,
			TemplateVersion: "1.0", SkippedAt: storetest.Now})
	},
	"ReplaceItemStates.check_run_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		run := b["run:ad-live"]
		return c.ReplaceItemStates(a["revision:ad"], []*store.ItemState{{ItemID: "base.owner", Level: "required",
			Status: "pass", Source: "live", CheckRunID: &run, ConfigHash: "x", UpdatedAt: storetest.Now}})
	},
	"InsertCheckRun.revision_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertCheckRun(&store.CheckRun{ID: store.NewID(), RevisionID: b["revision:ad"], Kind: "validation",
			Status: "completed", ActorID: "a", ConfigHash: "x", StartedAt: storetest.Now})
	},
	"InsertCheckResult.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertCheckResult(&store.CheckResult{RunID: b["run:ad-live"], ItemID: "x.y", CheckID: "z", Status: "pass",
			Observed: "{}", Message: "x", ItemHash: "x"})
	},
	"InsertReconRun.revision_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		return c.InsertReconRun(&store.ReconRun{ID: store.NewID(), RevisionID: b["revision:ad"], ConnectionID: a["connection:ad"],
			Mode: "staging", CheckRunID: a["run:ad-dry"], Status: "running", StartedAt: storetest.Now})
	},
	"InsertReconRun.check_run_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		return c.InsertReconRun(&store.ReconRun{ID: store.NewID(), RevisionID: a["revision:ad"], ConnectionID: a["connection:ad"],
			Mode: "staging", CheckRunID: b["run:ad-dry"], Status: "running", StartedAt: storetest.Now})
	},
	"InsertFinding.run_id": func(c *store.TenantTx, a, b refs, _ int64) error {
		return c.InsertFinding(&store.Finding{ID: store.NewID(), RunID: b["run:ad-dry"], ConnectionID: a["connection:ad"],
			Code: "RF-01", Title: "x", Severity: "low", Samples: "[]", Impact: "{}", Status: "open",
			FirstSeenAt: storetest.Now, LastSeenAt: storetest.Now})
	},
	"RecordScore.connection_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		id := b["connection:ad"]
		return c.RecordScore(&store.ScoreRow{Scope: "connection", ConnectionID: &id, ComputedAt: storetest.Now, Score: 1,
			Band: "x", Breakdown: "{}"})
	},
	"InsertStagedIdentity.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertStagedIdentity(&store.StagedIdentity{RunID: b["run:ad-dry"], ExternalID: "evil", Name: "evil"})
	},
	"InsertStagedAccount.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertStagedAccount(&store.StagedAccount{RunID: b["run:ad-dry"], System: "x", ExternalID: "evil"})
	},
	"InsertStagedGroup.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertStagedGroup(&store.StagedGroup{RunID: b["run:ad-dry"], System: "x", ExternalID: "evil", Name: "evil"})
	},
	"InsertStagedMembership.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertStagedMembership(b["run:ad-dry"], store.StagedMembership{MemberKind: "account", MemberXID: "a", GroupXID: "g"})
	},
	"InsertAttrStat.run_id": func(c *store.TenantTx, _, b refs, _ int64) error {
		return c.InsertAttrStat(b["run:ad-dry"], store.AttrStat{Class: "user", Attribute: "evil", Total: 1})
	},
	"SetStagedCorrelation.identity_id": func(c *store.TenantTx, a, _ refs, bIdentity int64) error {
		return c.SetStagedCorrelation(a["run:ad-dry"], "ad-corp", "S-1", "correlated", 1, &bIdentity, nil)
	},
	"SetStagedCorrelation.proposed_identity_id": func(c *store.TenantTx, a, _ refs, bIdentity int64) error {
		return c.SetStagedCorrelation(a["run:ad-dry"], "ad-corp", "S-1", "proposed", 3, nil, &bIdentity)
	},
}

func TestIsolation_ReadinessCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	beforeA := storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs)
	beforeB := storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs)
	for name, fn := range readinessCrossRefs {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
				return fn(c, f.A.Refs, f.B.Refs, f.B.IDs["alice"])
			})
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
	if storetest.ReadinessDump(t, f.DB, f.A.ID, f.A.Refs) != beforeA {
		t.Error("a refused cross-tenant write changed tenant A")
	}
	if storetest.ReadinessDump(t, f.DB, f.B.ID, f.B.Refs) != beforeB {
		t.Error("a refused cross-tenant write changed tenant B")
	}
}

// readinessCovered lists every readiness repository method with a case above
// (TestIsolation_EveryRepoMethodClassified includes it).
func readinessCovered() map[string]bool {
	out := map[string]bool{}
	for _, m := range []map[string]bool{keys(readinessLists), keys(readinessGets), keys(readinessNaturalKeys),
		keys(readinessCounts), keys(readinessMutations), keys(readinessCrossRefs)} {
		for k := range m {
			out[strings.SplitN(k, ".", 2)[0]] = true
		}
	}
	// Covered by TestIsolation_ReadinessInsertWrongTenantRejected and
	// TestIsolation_ReadinessCountsOnlyOwnRows.
	out["InsertConnection"], out["RunningDryRuns"] = true, true
	for k := range activationCovered() { // TestIsolation_ReadinessTables
		out[k] = true
	}
	return out
}
