package containment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func newSvc(t *testing.T) *containment.Service {
	t.Helper()
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return &containment.Service{Sealer: s, Clock: func() time.Time { return storetest.Now }}
}

func TestCredentialIsSealedAndBoundToTenantAndConnection(t *testing.T) {
	f := storetest.TwoTenants(t)
	svc := newSvc(t)
	conn := f.A.Refs["connection"]
	in := containment.CredentialInput{Token: "tok-very-secret", BaseURL: "https://larkspur.okta.com"}
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return svc.PutCredential(c, conn, in, "admin", storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	var enc []byte
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		k, err := c.Credential(conn, store.PurposeContainment, "")
		if err != nil {
			return err
		}
		enc = k.Sealed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("tok-very-secret")) || len(enc) == 0 {
		t.Fatal("the token is stored in the clear")
	}
	if _, err := svc.Sealer.Open(enc, seal.AAD(f.A.ID, "connection_credentials", "sealed", conn, "containment")); err != nil {
		t.Errorf("the right AAD does not open: %v", err)
	}
	for name, aad := range map[string][]byte{
		"other tenant":     seal.AAD(f.B.ID, "connection_credentials", "sealed", conn, "containment"),
		"other connection": seal.AAD(f.A.ID, "connection_credentials", "sealed", f.A.Refs["connection:ad"], "containment"),
		"other column":     seal.AAD(f.A.ID, "connection_credentials", "other", conn, "containment"),
		"other purpose":    seal.AAD(f.A.ID, "connection_credentials", "sealed", conn, "bind"),
		"old table":        seal.AAD(f.A.ID, "containment_credentials", "token_enc", conn),
	} {
		if _, err := svc.Sealer.Open(enc, aad); err == nil {
			t.Errorf("a credential opens under the AAD of %s", name)
		}
	}

	// The audit event names the change and never carries the token.
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		found := false
		for _, e := range log {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), "tok-very-secret") {
				t.Errorf("audit event %s carries the token", e.Action)
			}
			found = found || e.Action == "containment.credential_set"
		}
		if !found {
			t.Error("no containment.credential_set event")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// BuildJob unseals it for the identity's okta account, in the same tenant only.
	alice := f.A.IDs["alice"]
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		specs, err := containment.Steps(c, alice, true)
		if err != nil {
			return err
		}
		if len(specs) != 2 || specs[0].Action != containment.ActionRevokeSessions || specs[1].Action != containment.ActionRevokeGrants {
			t.Errorf("specs %+v", specs)
		}
		job, err := svc.BuildJob(c, alice, "manual", specs)
		if err != nil {
			return err
		}
		rep := svc.Run(context.Background(), job) // no HTTP client: refused, not skipped
		if rep.OK || rep.Steps[0].Outcome != containment.OutcomeFailed {
			t.Errorf("run with a credential but no outbound client: %+v", rep.Steps[0])
		}
		if job.Keys()[0] != "revoke_sessions:"+itoa(specs[0].AccountID) {
			t.Errorf("keys %v", job.Keys())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestPutCredentialValidation(t *testing.T) {
	f := storetest.TwoTenants(t)
	svc := newSvc(t)
	okta, ad := f.A.Refs["connection"], f.A.Refs["connection:ad"]
	cases := []struct {
		name, conn string
		in         containment.CredentialInput
		want       string
	}{
		{"unknown connection", "00000000-0000-4000-8000-00000000dead", containment.CredentialInput{Token: "t", BaseURL: "https://x"}, "no such connection"},
		{"another tenant's connection", f.B.Refs["connection"], containment.CredentialInput{Token: "t", BaseURL: "https://x"}, "no such connection"},
		{"unsupported system", ad, containment.CredentialInput{Token: "t", BaseURL: "https://x"}, "not \"ad-corp\""},
		{"no token", okta, containment.CredentialInput{BaseURL: "https://x"}, "token is required"},
		{"okta needs the org url", okta, containment.CredentialInput{Token: "t"}, "base_url"},
		{"bad scheme", okta, containment.CredentialInput{Token: "t", BaseURL: "ftp://x"}, "https URL"},
		{"user info", okta, containment.CredentialInput{Token: "t", BaseURL: "https://u:p@x"}, "https URL"},
	}
	for _, tc := range cases {
		err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
			return svc.PutCredential(c, tc.conn, tc.in, "admin", storetest.Now)
		})
		var ce *containment.Error
		if err == nil || !asError(err, &ce) || !strings.Contains(ce.Msg, tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func asError(err error, target **containment.Error) bool {
	ce, ok := err.(*containment.Error)
	*target = ce
	return ok
}

func TestRecordWritesTimingsToTheLedger(t *testing.T) {
	f := storetest.TwoTenants(t)
	rep := &containment.Report{IdentityID: 7, Identity: "Alice", Trigger: "manual", OK: false,
		StartedAt: "2026-10-14T12:00:00.000000Z", FinishedAt: "2026-10-14T12:00:00.140000Z", DurationMS: 140,
		Providers: []containment.ProviderOutcome{{System: "okta", Outcome: "failed", Steps: 1, Failed: 1, DurationMS: 90}},
		Steps: []containment.StepResult{{Action: "revoke_sessions", System: "okta", Account: "alice", Outcome: "failed",
			Detail: "verification still found 1 active session(s) or refresh token(s)", DurationMS: 90}}}
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return containment.Record(c, storetest.Now, "admin", rep)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		for _, e := range log {
			if e.Action != "containment.run" {
				continue
			}
			var d map[string]any
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"started_at", "finished_at", "duration_ms", "providers", "steps", "ok", "trigger"} {
				if _, ok := d[k]; !ok {
					t.Errorf("detail lacks %s: %s", k, e.Detail)
				}
			}
			if d["ok"] != false || d["duration_ms"] != float64(140) {
				t.Errorf("detail %s", e.Detail)
			}
			return nil
		}
		t.Error("no containment.run event")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
