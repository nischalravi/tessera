package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// AWS evaluator tables (issue #26, PR-7; design §6.2): a tenant's connectors,
// snapshots, policy documents, attachments, org nodes, entities, findings,
// trust edges, effective permissions and explanations are its own. Another
// tenant's id looks nonexistent, writes that name it fail, and a row that
// references it is refused by the guard triggers.

type awsIDs struct{ conn, snap, doc string }

func awsSeed(t *testing.T, f *storetest.Fixture) map[string]awsIDs {
	t.Helper()
	out := map[string]awsIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := awsIDs{conn: "00000000-0000-4000-8000-00000000000" + tn.Slug[len(tn.Slug)-1:], snap: "snap-" + tn.Slug, doc: "doc-" + tn.Slug}
		arn := "arn:aws:iam::111122223333:policy/" + tn.Slug
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertAWSConnector(&store.AWSConnector{ID: ids.conn, Name: "prod", Config: json.RawMessage(`{"regions":["us-east-1"]}`),
				ExternalID: "ext-" + tn.Slug, CredentialsEnc: []byte("sealed-" + tn.Slug), CreatedBy: "test",
				CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if created, err := c.PutAWSSnapshot(&store.AWSSnapshot{ID: ids.snap, TakenAt: storetest.Now, AccountIDs: []string{"111122223333"},
				CatalogVersion: "2026-10-08", Source: store.AWSSourceConnector, ConnectorID: ids.conn}); err != nil || !created {
				t.Fatalf("PutAWSSnapshot = %v, %v", created, err)
			}
			if err := c.PutAWSPolicyDocument(&store.AWSPolicyDocument{ID: ids.doc, Kind: "identity", SourceARN: arn, VersionID: "v1",
				RawJSON: []byte(`{"Version":"2012-10-17"}`), Normalized: json.RawMessage(`{}`), FetchedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.AddAWSAttachment(&store.AWSAttachment{SnapshotID: ids.snap, PolicyID: ids.doc, TargetARN: "arn:aws:iam::111122223333:role/" + tn.Slug,
				AttachmentType: "managed", Via: []string{"role/" + tn.Slug}}); err != nil {
				return err
			}
			if err := c.AddAWSOrgNode(&store.AWSOrgNode{SnapshotID: ids.snap, ID: "r-" + tn.Slug, Kind: "root", Name: "Root"}); err != nil {
				return err
			}
			if err := c.AddAWSEntity(&store.AWSEntity{SnapshotID: ids.snap, Kind: store.AWSEntityPrincipal, Key: "arn:" + tn.Slug,
				Body: json.RawMessage(`{"arn":"x"}`)}); err != nil {
				return err
			}
			if err := c.AddAWSFinding(&store.AWSFinding{SnapshotID: ids.snap, Kind: store.AWSFindingPolicyUnparseable, SourceARN: arn,
				PolicyKind: "identity", Code: "invalid_json", Detail: "x"}); err != nil {
				return err
			}
			if err := c.AddAWSTrustEdge(&store.AWSTrustEdge{SnapshotID: ids.snap, FromARN: "arn:from:" + tn.Slug, ToRoleARN: "arn:to:" + tn.Slug,
				Mechanism: "assume_role", Outcome: "allow", Residual: json.RawMessage(`{}`), ExplanationID: "x-" + tn.Slug}); err != nil {
				return err
			}
			if err := c.AddAWSEffective(&store.AWSEffective{SnapshotID: ids.snap, PrincipalARN: "arn:p:" + tn.Slug, ActionAtom: 1, ResourceAtom: 2,
				Outcome: "allow", Fidelity: "exact", ExplanationID: "x-" + tn.Slug, EngineVersion: "1", CatalogVersion: "2026-10-08"}); err != nil {
				return err
			}
			return c.PutAWSExplanation(&store.AWSExplanation{ID: "x-" + tn.Slug, Trace: json.RawMessage(`{"steps":[]}`)})
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_AWSTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := awsSeed(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]

	inB(t, f, func(c *store.TenantTx) error {
		// B sees its own
		conns, err := c.AWSConnectors()
		if err != nil || len(conns) != 1 || conns[0].ID != b.conn || string(conns[0].CredentialsEnc) != "sealed-"+f.B.Slug ||
			conns[0].ExternalID != "ext-"+f.B.Slug {
			t.Errorf("AWSConnectors = %v, %v; want B's one", conns, err)
		}
		if got, err := c.AWSConnector(b.conn); err != nil || got.Name != "prod" || got.Status != store.AWSConnectorIdle {
			t.Errorf("AWSConnector(B's) = %+v, %v", got, err)
		}
		snaps, err := c.AWSSnapshots(0)
		if err != nil || len(snaps) != 1 || snaps[0].ID != b.snap || len(snaps[0].AccountIDs) != 1 || snaps[0].ConnectorID != b.conn {
			t.Errorf("AWSSnapshots = %v, %v; want B's one", snaps, err)
		}
		if d, err := c.AWSPolicyDocument(b.doc); err != nil || string(d.RawJSON) != `{"Version":"2012-10-17"}` {
			t.Errorf("AWSPolicyDocument(B's) = %+v, %v", d, err)
		}

		// A's ids look nonexistent
		if _, err := c.AWSConnector(a.conn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AWSConnector(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.AWSSnapshot(a.snap); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AWSSnapshot(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.AWSPolicyDocument(a.doc); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AWSPolicyDocument(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.AWSExplanation("x-" + f.A.Slug); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AWSExplanation(A's) = %v, want ErrNotFound", err)
		}
		if ds, err := c.AWSPolicyDocumentsBySource("arn:aws:iam::111122223333:policy/" + f.A.Slug); err != nil || len(ds) != 0 {
			t.Errorf("AWSPolicyDocumentsBySource(A's) = %d, %v", len(ds), err)
		}
		if as, err := c.AWSAttachments(a.snap); err != nil || len(as) != 0 {
			t.Errorf("AWSAttachments(A's snapshot) = %d, %v", len(as), err)
		}
		if as, err := c.AWSAttachmentsByTarget("arn:aws:iam::111122223333:role/" + f.A.Slug); err != nil || len(as) != 0 {
			t.Errorf("AWSAttachmentsByTarget(A's) = %d, %v", len(as), err)
		}
		if ns, err := c.AWSOrgNodes(a.snap); err != nil || len(ns) != 0 {
			t.Errorf("AWSOrgNodes(A's) = %d, %v", len(ns), err)
		}
		if es, err := c.AWSEntities(a.snap, store.AWSEntityPrincipal); err != nil || len(es) != 0 {
			t.Errorf("AWSEntities(A's) = %d, %v", len(es), err)
		}
		if fs, err := c.AWSFindings(a.snap); err != nil || len(fs) != 0 {
			t.Errorf("AWSFindings(A's) = %d, %v", len(fs), err)
		}
		if ts, err := c.AWSTrustEdges(a.snap); err != nil || len(ts) != 0 {
			t.Errorf("AWSTrustEdges(A's) = %d, %v", len(ts), err)
		}
		if es, err := c.ListAWSEffectiveByPrincipal(a.snap, "arn:p:"+f.A.Slug); err != nil || len(es) != 0 {
			t.Errorf("ListAWSEffectiveByPrincipal(A's) = %d, %v", len(es), err)
		}
		// B's own children are all there
		if as, err := c.AWSAttachments(b.snap); err != nil || len(as) != 1 || as[0].PolicyID != b.doc || len(as[0].Via) != 1 {
			t.Errorf("AWSAttachments(B's) = %v, %v", as, err)
		}
		if ns, err := c.AWSOrgNodes(b.snap); err != nil || len(ns) != 1 {
			t.Errorf("AWSOrgNodes(B's) = %d, %v", len(ns), err)
		}
		if es, err := c.AWSEntities(b.snap, store.AWSEntityPrincipal); err != nil || len(es) != 1 {
			t.Errorf("AWSEntities(B's) = %d, %v", len(es), err)
		}
		if fs, err := c.AWSFindings(b.snap); err != nil || len(fs) != 1 || fs[0].Code != "invalid_json" {
			t.Errorf("AWSFindings(B's) = %v, %v", fs, err)
		}
		if ts, err := c.AWSTrustEdges(b.snap); err != nil || len(ts) != 1 {
			t.Errorf("AWSTrustEdges(B's) = %d, %v", len(ts), err)
		}
		if es, err := c.ListAWSEffectiveByPrincipal(b.snap, "arn:p:"+f.B.Slug); err != nil || len(es) != 1 || es[0].Residual != nil {
			t.Errorf("ListAWSEffectiveByPrincipal(B's) = %v, %v", es, err)
		}
		if x, err := c.AWSExplanation("x-" + f.B.Slug); err != nil || string(x.Trace) != `{"steps":[]}` {
			t.Errorf("AWSExplanation(B's) = %+v, %v", x, err)
		}
		return nil
	})
}

func TestIsolation_AWSWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := awsSeed(t, f)
	a := ids[f.A.Slug]
	later := storetest.Now.Add(time.Hour)

	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		// writes that name A's connector change nothing
		if err := c.SetAWSConnectorRun(a.conn, store.AWSConnectorOK, a.snap, "", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetAWSConnectorRun(A's) = %v, want ErrNotFound", err)
		}
		if err := c.DeleteAWSConnector(a.conn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteAWSConnector(A's) = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// rows that reference A's snapshot or document are refused by the guard triggers
	refused := map[string]func(c *store.TenantTx) error{
		"attachment to A's snapshot": func(c *store.TenantTx) error {
			return c.AddAWSAttachment(&store.AWSAttachment{SnapshotID: a.snap, PolicyID: ids[f.B.Slug].doc, TargetARN: "t", AttachmentType: "managed"})
		},
		"attachment of A's document": func(c *store.TenantTx) error {
			return c.AddAWSAttachment(&store.AWSAttachment{SnapshotID: ids[f.B.Slug].snap, PolicyID: a.doc, TargetARN: "t", AttachmentType: "managed"})
		},
		"org node": func(c *store.TenantTx) error {
			return c.AddAWSOrgNode(&store.AWSOrgNode{SnapshotID: a.snap, ID: "r-x", Kind: "root", Name: "x"})
		},
		"entity": func(c *store.TenantTx) error {
			return c.AddAWSEntity(&store.AWSEntity{SnapshotID: a.snap, Kind: store.AWSEntityResource, Key: "k", Body: json.RawMessage(`{}`)})
		},
		"finding": func(c *store.TenantTx) error {
			return c.AddAWSFinding(&store.AWSFinding{SnapshotID: a.snap, Kind: store.AWSFindingAccountError, SourceARN: "1", Code: "c", Detail: "d"})
		},
		"trust edge": func(c *store.TenantTx) error {
			return c.AddAWSTrustEdge(&store.AWSTrustEdge{SnapshotID: a.snap, FromARN: "f", ToRoleARN: "t", Mechanism: "m", Outcome: "allow", ExplanationID: "x"})
		},
		"effective permission": func(c *store.TenantTx) error {
			return c.AddAWSEffective(&store.AWSEffective{SnapshotID: a.snap, PrincipalARN: "p", Outcome: "allow", Fidelity: "exact",
				ExplanationID: "x", EngineVersion: "1", CatalogVersion: "1"})
		},
	}
	for name, fn := range refused {
		err := f.DB.InTenant(context.Background(), f.B.ID, fn)
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s: err = %v, want ErrCrossTenant", name, err)
		}
	}

	// A's rows are untouched
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.AWSConnector(a.conn)
		if err != nil || got.Status != store.AWSConnectorIdle || got.LastSnapshotID != "" {
			t.Errorf("A's connector = %+v, %v", got, err)
		}
		if as, err := c.AWSAttachments(a.snap); err != nil || len(as) != 1 {
			t.Errorf("A's attachments = %d, %v", len(as), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_AWSContentAddressingIsPerTenant: two tenants that put the
// same snapshot id and the same policy document each get a row of their own,
// so the existence of a row never tells one tenant what another holds.
func TestIsolation_AWSContentAddressingIsPerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			created, err := c.PutAWSSnapshot(&store.AWSSnapshot{ID: "same", TakenAt: storetest.Now, CatalogVersion: "v", Source: store.AWSSourceHarness})
			if err != nil || !created {
				t.Errorf("%s: first PutAWSSnapshot = %v, %v", tn.Slug, created, err)
			}
			// the same content again is a no-op
			if created, err := c.PutAWSSnapshot(&store.AWSSnapshot{ID: "same", TakenAt: storetest.Now.Add(time.Hour), CatalogVersion: "v",
				Source: store.AWSSourceHarness}); err != nil || created {
				t.Errorf("%s: second PutAWSSnapshot = %v, %v; want created=false", tn.Slug, created, err)
			}
			d := &store.AWSPolicyDocument{ID: "samedoc", Kind: "scp", SourceARN: "arn:aws:organizations::1:policy/o-x/p-1", RawJSON: []byte("{}"), FetchedAt: storetest.Now}
			if err := c.PutAWSPolicyDocument(d); err != nil {
				return err
			}
			if err := c.PutAWSPolicyDocument(d); err != nil { // idempotent
				return err
			}
			// the rows that reference them are accepted: the ids are the tenant's own, though another tenant holds the same ones
			if err := c.AddAWSAttachment(&store.AWSAttachment{SnapshotID: "same", PolicyID: "samedoc", TargetARN: "r-1", AttachmentType: "scp"}); err != nil {
				return err
			}
			if err := c.AddAWSOrgNode(&store.AWSOrgNode{SnapshotID: "same", ID: "r-1", Kind: "root", Name: "Root"}); err != nil {
				return err
			}
			return c.AddAWSFinding(&store.AWSFinding{SnapshotID: "same", Kind: store.AWSFindingAccountError, SourceARN: "1", Code: "c", Detail: "d"})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			snaps, err := c.AWSSnapshots(0)
			if err != nil || len(snaps) != 1 {
				t.Errorf("%s: AWSSnapshots = %d, %v; want its own one", tn.Slug, len(snaps), err)
			}
			ds, err := c.AWSPolicyDocumentsBySource("arn:aws:organizations::1:policy/o-x/p-1")
			if err != nil || len(ds) != 1 {
				t.Errorf("%s: documents = %d, %v; want its own one", tn.Slug, len(ds), err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAWSConnectorNamesAreUniquePerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	awsSeed(t, f) // each tenant already has a connector named "prod"
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAWSConnector(&store.AWSConnector{ID: "00000000-0000-4000-8000-0000000000ff", Name: "prod", ExternalID: "e",
			CredentialsEnc: []byte("s"), CreatedBy: "t", CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate name in A = %v, want ErrDuplicate", err)
	}
}

// awsCovered lists the AWS repository methods the cases above exercise
// (TestIsolation_EveryTenantTxMethodCovered).
func awsCovered() map[string]bool {
	return map[string]bool{
		"InsertAWSConnector": true, "AWSConnector": true, "AWSConnectors": true, "DeleteAWSConnector": true,
		"SetAWSConnectorRun": true, "PutAWSSnapshot": true, "AWSSnapshot": true, "AWSSnapshots": true,
		"PutAWSPolicyDocument": true, "AWSPolicyDocument": true, "AWSPolicyDocumentsBySource": true,
		"AddAWSAttachment": true, "AWSAttachments": true, "AWSAttachmentsByTarget": true,
		"AddAWSOrgNode": true, "AWSOrgNodes": true, "AddAWSEntity": true, "AWSEntities": true,
		"AddAWSFinding": true, "AWSFindings": true, "AddAWSTrustEdge": true, "AWSTrustEdges": true,
		"AddAWSEffective": true, "ListAWSEffectiveByPrincipal": true, "PutAWSExplanation": true, "AWSExplanation": true,
		"UpsertEvaluatorEdge": true, "AWSPRCommentSettings": true, "PutAWSPRCommentSettings": true,
		"InsertAWSCollectionRun": true, "AWSCollectionRun": true, "AWSCollectionRuns": true, "ActiveAWSCollectionRun": true,
		"StartAWSCollectionRun": true, "FinishAWSCollectionRun": true, "FailStaleAWSCollectionRuns": true,
	}
}

// The MVP integration tables (issue #30, PR-11; schema/0321): the evaluator's
// fields of a grant edge and the pull request comment settings are a tenant's
// own.
func TestIsolation_AWSIntegrationTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	later := storetest.Now.Add(time.Hour)
	ev := func(slug string) store.EdgeEvaluation {
		return store.EdgeEvaluation{ExplanationID: "x-" + slug, Outcome: "conditional", Fidelity: "approximate"}
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			ok, err := c.UpsertEvaluatorEdge("account:900", "perm:901", "grants", storetest.Now, ev(tn.Slug))
			if err != nil || !ok {
				t.Fatalf("%s: UpsertEvaluatorEdge = %v, %v", tn.Slug, ok, err)
			}
			return c.PutAWSPRCommentSettings(&store.AWSPRCommentSettings{Enabled: true, Repo: "o/" + tn.Slug,
				TokenEnc: []byte("sealed-" + tn.Slug), UpdatedBy: "test"}, later)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			e, err := c.EdgeBetween("account:900", "perm:901")
			if err != nil || e.Source != store.EdgeSourceEvaluator || e.ExplanationID != "x-"+tn.Slug || e.Outcome != "conditional" || e.Fidelity != "approximate" {
				t.Errorf("%s: EdgeBetween = %+v, %v; want its own evaluation", tn.Slug, e, err)
			}
			s, err := c.AWSPRCommentSettings()
			if err != nil || !s.Enabled || s.Repo != "o/"+tn.Slug || string(s.TokenEnc) != "sealed-"+tn.Slug {
				t.Errorf("%s: AWSPRCommentSettings = %+v, %v; want its own", tn.Slug, s, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// B updating its evaluation or settings leaves A's untouched
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.UpsertEvaluatorEdge("account:900", "perm:901", "grants", later,
			store.EdgeEvaluation{ExplanationID: "b-new", Outcome: "allow", Fidelity: "exact"}); err != nil {
			return err
		}
		return c.PutAWSPRCommentSettings(&store.AWSPRCommentSettings{Repo: "o/changed", UpdatedBy: "test"}, later)
	})
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		e, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil || e.ExplanationID != "x-"+f.A.Slug || e.Outcome != "conditional" {
			t.Errorf("A's edge = %+v, %v; B's write changed it", e, err)
		}
		if s, err := c.AWSPRCommentSettings(); err != nil || !s.Enabled || s.Repo != "o/"+f.A.Slug {
			t.Errorf("A's settings = %+v, %v; B's write changed them", s, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// deleting an edge deletes its evaluation, and a manual edge is never taken over
	inA(t, f, func(c *store.TenantTx) error {
		e, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil {
			return err
		}
		if err := c.DeleteEdge(e.ID, time.Now()); err != nil {
			return err
		}
		if _, err := c.InsertEdge(&store.GrantEdge{Src: "account:900", Dst: "perm:901", Relation: "direct_grant", Source: "manual", CreatedAt: storetest.Now}); err != nil {
			return err
		}
		ok, err := c.UpsertEvaluatorEdge("account:900", "perm:901", "grants", later, ev("A"))
		if err != nil || ok {
			t.Errorf("UpsertEvaluatorEdge over a manual edge = %v, %v; want false", ok, err)
		}
		m, err := c.EdgeBetween("account:900", "perm:901")
		if err != nil || m.Source != "manual" || m.Relation != "direct_grant" || m.ExplanationID != "" {
			t.Errorf("manual edge = %+v, %v; want it untouched", m, err)
		}
		return nil
	})
}

// A tenant that never set the pull request comment settings has it off, and
// nothing is stored for it.
func TestAWSPRCommentSettingsDefaultOff(t *testing.T) {
	f := storetest.TwoTenants(t)
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		s, err := c.AWSPRCommentSettings()
		if err != nil || s.Enabled || s.Repo != "" || len(s.TokenEnc) != 0 {
			t.Errorf("default settings = %+v, %v; want off", s, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The collection runs (issue #637; schema/0914): a tenant's runs are its own,
// another tenant's id looks nonexistent, writes that name it change nothing,
// and the one-active-run rule is per tenant and connector.
func TestIsolation_AWSCollectionRuns(t *testing.T) {
	f := storetest.TwoTenants(t)
	const conn = "00000000-0000-4000-8000-0000000000c1" // the same connector id in both tenants
	later := storetest.Now.Add(time.Hour)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.InsertAWSCollectionRun(&store.AWSCollectionRun{ID: "run-" + tn.Slug, ConnectorID: conn, Trigger: store.AWSRunManual,
				Status: store.AWSRunQueued, RequestedBy: "u-" + tn.Slug, QueuedAt: storetest.Now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	inB(t, f, func(c *store.TenantTx) error {
		if r, err := c.AWSCollectionRun("run-" + f.B.Slug); err != nil || r.RequestedBy != "u-"+f.B.Slug || r.Status != store.AWSRunQueued {
			t.Errorf("AWSCollectionRun(B's) = %+v, %v", r, err)
		}
		if _, err := c.AWSCollectionRun("run-" + f.A.Slug); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AWSCollectionRun(A's) = %v, want ErrNotFound", err)
		}
		if rs, err := c.AWSCollectionRuns("", 0); err != nil || len(rs) != 1 || rs[0].ID != "run-"+f.B.Slug {
			t.Errorf("AWSCollectionRuns = %v, %v; want B's one", rs, err)
		}
		if r, err := c.ActiveAWSCollectionRun(conn); err != nil || r.ID != "run-"+f.B.Slug {
			t.Errorf("ActiveAWSCollectionRun = %+v, %v; want B's", r, err)
		}
		// writes that name A's run change nothing
		if err := c.StartAWSCollectionRun("run-"+f.A.Slug, later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("StartAWSCollectionRun(A's) = %v, want ErrNotFound", err)
		}
		if err := c.FinishAWSCollectionRun("run-"+f.A.Slug, store.AWSRunFailed, "", false, nil, "x", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FinishAWSCollectionRun(A's) = %v, want ErrNotFound", err)
		}
		// a second active run of the same connector is refused in this tenant
		err := c.InsertAWSCollectionRun(&store.AWSCollectionRun{ID: "run-b2", ConnectorID: conn, Trigger: store.AWSRunSchedule,
			Status: store.AWSRunQueued, RequestedBy: "x", QueuedAt: later})
		if !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("second active run = %v, want ErrDuplicate", err)
		}
		return nil
	})
	// B failing stale runs leaves A's alone
	inB(t, f, func(c *store.TenantTx) error {
		n, err := c.FailStaleAWSCollectionRuns(later, later, "stale")
		if err != nil || n != 1 {
			t.Errorf("FailStaleAWSCollectionRuns = %d, %v; want B's one", n, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if r, err := c.AWSCollectionRun("run-" + f.A.Slug); err != nil || r.Status != store.AWSRunQueued || r.Error != "" {
			t.Errorf("A's run = %+v, %v; B's writes changed it", r, err)
		}
		// the lifecycle in A: start, finish, then a new run may be queued
		if err := c.StartAWSCollectionRun("run-"+f.A.Slug, later); err != nil {
			t.Fatal(err)
		}
		if err := c.FinishAWSCollectionRun("run-"+f.A.Slug, store.AWSRunSucceeded, "snap", true, json.RawMessage(`{"cells":3}`), "", later); err != nil {
			t.Fatal(err)
		}
		r, err := c.AWSCollectionRun("run-" + f.A.Slug)
		if err != nil || r.Status != store.AWSRunSucceeded || !r.Changed || r.SnapshotID != "snap" || string(r.Result) != `{"cells":3}` ||
			r.StartedAt == nil || r.FinishedAt == nil {
			t.Errorf("finished run = %+v, %v", r, err)
		}
		if _, err := c.ActiveAWSCollectionRun(conn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ActiveAWSCollectionRun after finish = %v, want ErrNotFound", err)
		}
		return c.InsertAWSCollectionRun(&store.AWSCollectionRun{ID: "run-a2", ConnectorID: conn, Trigger: store.AWSRunSchedule,
			Status: store.AWSRunQueued, RequestedBy: "x", QueuedAt: later})
	})
}
