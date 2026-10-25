package awsorg

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func newService(t *testing.T, r *awsreplay.Replay) *Service {
	t.Helper()
	return &Service{Sealer: testSealer(t), Client: testClient(r, nil), CatalogVersion: "2026-10-08-0123456789abcdef",
		Clock: func() time.Time { return testNow }}
}

func createConnector(t *testing.T, s *Service, f *storetest.Fixture) *store.AWSConnector {
	t.Helper()
	var k *store.AWSConnector
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) (err error) {
		k, err = s.CreateConnector(c, CreateInput{Name: "prod", Config: *orgConfig(),
			Credentials: Credentials{AccessKeyID: baseKeyID, SecretAccessKey: baseSecret}}, "admin", testNow)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func auditActions(t *testing.T, f *storetest.Fixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditLog(0)
		for _, e := range evs {
			out[e.Action] += string(e.Detail)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestService_CreateCollectDelete(t *testing.T) {
	f := storetest.TwoTenants(t)
	r := newReplay(t)
	s := newService(t, r)
	k := createConnector(t, s, f)
	if !strings.HasPrefix(k.ExternalID, "tessera-") || len(k.ExternalID) < 30 || strings.Contains(string(k.CredentialsEnc), baseSecret) {
		t.Errorf("connector = %+v", k)
	}
	// the external id the connector sends is its own
	r2 := newReplay(t)
	s.Client = testClient(r2, nil)
	hdr, err := s.Collect(context.Background(), f.DB, f.A.ID, k.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range r2.Requests() {
		if q.Service == "sts" && q.Form.Get("ExternalId") != k.ExternalID {
			t.Errorf("ExternalId = %q, want the connector's %q", q.Form.Get("ExternalId"), k.ExternalID)
		}
	}
	if hdr.Source != store.AWSSourceConnector || hdr.ConnectorID != k.ID || hdr.CatalogVersion != s.CatalogVersion {
		t.Errorf("snapshot = %+v", hdr)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.AWSConnector(k.ID)
		if err != nil || got.Status != store.AWSConnectorOK || got.LastSnapshotID != hdr.ID || got.LastError != "" {
			t.Errorf("connector after run = %+v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// audited, in the same transactions, with no credentials in the detail
	acts := auditActions(t, f)
	for _, a := range []string{"aws.connector.created", "aws.snapshot.collected"} {
		if acts[a] == "" {
			t.Errorf("no %s event", a)
		}
	}
	for a, d := range acts {
		if strings.Contains(d, baseSecret) || strings.Contains(d, baseKeyID) || strings.Contains(d, k.ExternalID) {
			t.Errorf("event %s leaks a credential: %s", a, d)
		}
	}

	// another tenant cannot collect it
	if _, err := s.Collect(context.Background(), f.DB, f.B.ID, k.ID, "x"); err == nil {
		t.Error("tenant B collected A's connector")
	}

	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return s.DeleteConnector(c, k.ID, "admin", testNow)
	}); err != nil {
		t.Fatal(err)
	}
	if auditActions(t, f)["aws.connector.deleted"] == "" {
		t.Error("no delete event")
	}
	if _, err := s.Collect(context.Background(), f.DB, f.A.ID, k.ID, "admin"); err == nil {
		t.Error("collected a deleted connector")
	}
}

func TestService_FailedRunIsRecorded(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := newService(t, newReplay(t))
	k := createConnector(t, s, f)
	r := newReplay(t)
	r.Enqueue("sts/AssumeRole", awsreplay.Response{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`})
	s.Client = testClient(r, nil)
	if _, err := s.Collect(context.Background(), f.DB, f.A.ID, k.ID, "admin"); err == nil {
		t.Fatal("no error")
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, _ := c.AWSConnector(k.ID)
		if got.Status != store.AWSConnectorFailed || !strings.Contains(got.LastError, "AccessDenied") || strings.Contains(got.LastError, baseSecret) {
			t.Errorf("connector = %+v", got)
		}
		snaps, _ := c.AWSSnapshots(0)
		if len(snaps) != 0 {
			t.Errorf("%d snapshots after a failed run", len(snaps))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if auditActions(t, f)["aws.collection.failed"] == "" {
		t.Error("no failure event")
	}
}

func TestService_CreateValidation(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := newService(t, newReplay(t))
	good := CreateInput{Name: "x", Config: *orgConfig(), Credentials: goodCreds}
	for name, mut := range map[string]func(*CreateInput){
		"empty name":      func(in *CreateInput) { in.Name = "" },
		"padded name":     func(in *CreateInput) { in.Name = " x" },
		"control in name": func(in *CreateInput) { in.Name = "a\x00b" },
		"long name":       func(in *CreateInput) { in.Name = strings.Repeat("n", 81) },
		"bad config":      func(in *CreateInput) { in.Config.Regions = nil },
		"bad credentials": func(in *CreateInput) { in.Credentials.SecretAccessKey = "x" },
	} {
		in := good
		in.Config = *orgConfig()
		mut(&in)
		err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			_, err := s.CreateConnector(c, in, "a", testNow)
			return err
		})
		var ie *InputError
		if !errors.As(err, &ie) || ie.Kind != "invalid" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	create := func() error {
		return f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			in := good
			in.Config = *orgConfig()
			_, err := s.CreateConnector(c, in, "a", testNow)
			return err
		})
	}
	if err := create(); err != nil {
		t.Fatal(err)
	}
	var ie *InputError
	if err := create(); !errors.As(err, &ie) || ie.Kind != "conflict" {
		t.Errorf("duplicate name: %v", err)
	}
	// a failed create leaves no audit event for the connector
	if n := strings.Count(auditActions(t, f)["aws.connector.created"], "connector_id"); n != 1 {
		t.Errorf("%d created events, want 1", n)
	}
}

// footprint counts what a collection writes: the snapshot tables, and the
// audit events by action.
type footprint struct {
	snaps, attachments, entities, findings, trust int
	audit                                         map[string]int
}

func takeFootprint(t *testing.T, f *storetest.Fixture) footprint {
	t.Helper()
	var fp footprint
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		snaps, err := c.AWSSnapshots(0)
		if err != nil {
			return err
		}
		fp.snaps = len(snaps)
		for _, s := range snaps {
			as, _ := c.AWSAttachments(s.ID)
			fs, _ := c.AWSFindings(s.ID)
			ts, _ := c.AWSTrustEdges(s.ID)
			fp.attachments, fp.findings, fp.trust = fp.attachments+len(as), fp.findings+len(fs), fp.trust+len(ts)
			for _, kind := range []string{store.AWSEntityPrincipal, store.AWSEntityResource, store.AWSEntityResourcePolicy, store.AWSEntityOrg,
				store.AWSEntityS3Bucket, store.AWSEntityKMSGrant, store.AWSEntityIdentityCenter} {
				es, err := c.AWSEntities(s.ID, kind)
				if err != nil {
					return err
				}
				fp.entities += len(es)
			}
		}
		evs, err := c.AuditLog(0)
		fp.audit = map[string]int{}
		for _, e := range evs {
			fp.audit[e.Action]++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return fp
}

// CollectAndMaterialize collects and evaluates an estate once; the same estate
// again writes nothing (no snapshot rows, no event, no evaluation), a changed
// estate is a new snapshot that is evaluated, and the estate going back to the
// first state is evaluated again because the graph is no longer in step with it.
func TestService_CollectAndMaterializeIsIncremental(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	s := newService(t, newReplay(t))
	s.Eval = evalConfig()
	k := createConnector(t, s, f)
	run := func(edit func(string) string) *CollectResult {
		t.Helper()
		s.Client = testClient(editingDoer{newReplay(t), edit}, nil)
		res, err := s.CollectAndMaterialize(ctx, f.DB, f.A.ID, k.ID, "worker")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	connector := func() *store.AWSConnector {
		var got *store.AWSConnector
		_ = f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) { got, err = c.AWSConnector(k.ID); return err })
		return got
	}

	first := run(nil)
	if !first.Changed || first.Materialized == nil || first.SnapshotID == "" {
		t.Fatalf("first run = %+v, want a changed estate that was evaluated", first)
	}
	after1 := takeFootprint(t, f)
	if after1.snaps != 1 || after1.attachments == 0 || after1.entities == 0 || after1.audit["aws.snapshot.collected"] != 1 || after1.audit["aws.snapshot.materialized"] != 1 {
		t.Fatalf("after the first run: %+v", after1)
	}
	if c := connector(); c.Status != store.AWSConnectorOK || c.LastSnapshotID != first.SnapshotID {
		t.Errorf("connector after the first run = %+v", c)
	}

	// unchanged: nothing is written but the connector's last-run time
	before := connector()
	s.Clock = func() time.Time { return testNow.Add(time.Hour) }
	second := run(nil)
	s.Clock = func() time.Time { return testNow }
	if second.Changed || second.Materialized != nil || second.SnapshotID != first.SnapshotID {
		t.Errorf("second run = %+v, want unchanged and not evaluated", second)
	}
	if after2 := takeFootprint(t, f); !reflect.DeepEqual(after1, after2) {
		t.Errorf("an unchanged estate wrote: before %+v, after %+v", after1, after2)
	}
	if c := connector(); !c.LastRunAt.After(*before.LastRunAt) || c.LastSnapshotID != first.SnapshotID || c.Status != store.AWSConnectorOK {
		t.Errorf("connector after the unchanged run = %+v, want its last-run time moved", c)
	}

	// changed: a new snapshot, evaluated
	tagEdit := func(b string) string { return strings.ReplaceAll(b, "<Value>data</Value>", "<Value>data2</Value>") }
	third := run(tagEdit)
	if !third.Changed || third.SnapshotID == first.SnapshotID || third.Materialized == nil {
		t.Fatalf("third run = %+v, want a new evaluated snapshot", third)
	}
	if fp := takeFootprint(t, f); fp.snaps != 2 || fp.audit["aws.snapshot.materialized"] != 2 {
		t.Errorf("after the change: %+v", fp)
	}

	// back to the first state: the snapshot exists, but it is not the connector's current one
	fourth := run(nil)
	if !fourth.Changed || fourth.SnapshotID != first.SnapshotID || fourth.Materialized == nil {
		t.Errorf("fourth run = %+v, want the first snapshot evaluated again", fourth)
	}
	if fp := takeFootprint(t, f); fp.snaps != 2 || fp.audit["aws.snapshot.materialized"] != 3 {
		t.Errorf("after the return: %+v", fp)
	}
}

// A snapshot that was stored but could not be evaluated is not "unchanged" the
// next time: the connector is failed, and the next run evaluates it.
func TestService_FailedEvaluationIsRetried(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	s := newService(t, newReplay(t))
	s.Eval = evalConfig()
	k := createConnector(t, s, f)
	good := s.Eval.Index
	s.Eval.Index = func(*model.Snapshot) index.Config { return index.Config{} } // no catalog: the index cannot be built
	if _, err := s.CollectAndMaterialize(ctx, f.DB, f.A.ID, k.ID, "worker"); err == nil || !strings.Contains(err.Error(), "was not evaluated") {
		t.Fatalf("err = %v, want the evaluation failure", err)
	}
	var got *store.AWSConnector
	_ = f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) { got, err = c.AWSConnector(k.ID); return err })
	if got.Status != store.AWSConnectorFailed || got.LastSnapshotID == "" || strings.Contains(got.LastError, baseSecret) {
		t.Fatalf("connector = %+v, want failed with its snapshot", got)
	}
	if auditActions(t, f)["aws.collection.failed"] == "" {
		t.Error("no failure event")
	}

	s.Eval.Index = good
	s.Client = testClient(newReplay(t), nil)
	res, err := s.CollectAndMaterialize(ctx, f.DB, f.A.ID, k.ID, "worker")
	if err != nil || !res.Changed || res.Materialized == nil || res.SnapshotID != got.LastSnapshotID {
		t.Fatalf("retry = %+v, %v; want the stored snapshot evaluated", res, err)
	}
	_ = f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) (err error) { got, err = c.AWSConnector(k.ID); return err })
	if got.Status != store.AWSConnectorOK || got.LastError != "" {
		t.Errorf("connector after the retry = %+v", got)
	}
	if fp := takeFootprint(t, f); fp.snaps != 1 {
		t.Errorf("%d snapshots, want the one", fp.snaps)
	}
}

// Without an evaluator the job refuses to run (it would collect and never
// evaluate), and a collection that fails at AWS is the job's error.
func TestService_CollectAndMaterializeRefusals(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := newService(t, newReplay(t))
	k := createConnector(t, s, f)
	if _, err := s.CollectAndMaterialize(context.Background(), f.DB, f.A.ID, k.ID, "w"); err == nil {
		t.Error("ran with no evaluator")
	}
	s.Eval = evalConfig()
	if _, err := s.CollectAndMaterialize(context.Background(), f.DB, f.B.ID, k.ID, "w"); err == nil {
		t.Error("tenant B ran A's connector")
	}
	r := newReplay(t)
	r.Enqueue("sts/AssumeRole", awsreplay.Response{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`})
	s.Client = testClient(r, nil)
	if _, err := s.CollectAndMaterialize(context.Background(), f.DB, f.A.ID, k.ID, "w"); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("err = %v", err)
	}
	if fp := takeFootprint(t, f); fp.snaps != 0 || fp.audit["aws.collection.failed"] != 1 {
		t.Errorf("after a failed run: %+v", fp)
	}
}

// editingDoer rewrites the body of every response, to change the estate the
// recordings describe.
type editingDoer struct {
	inner Doer
	edit  func(string) string
}

func (d editingDoer) Do(req *http.Request) (*http.Response, error) {
	resp, err := d.inner.Do(req)
	if err != nil || d.edit == nil {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	out := d.edit(string(b))
	resp.Body, resp.ContentLength = io.NopCloser(strings.NewReader(out)), int64(len(out))
	resp.Header.Del("Content-Length")
	return resp, nil
}
