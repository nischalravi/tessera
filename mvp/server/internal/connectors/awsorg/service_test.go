package awsorg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func newService(t *testing.T, r *awstest.Replay) *Service {
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
	r.Enqueue("sts/AssumeRole", awstest.Response{Status: 403, Body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>`})
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
