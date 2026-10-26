package awsorg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The writer's token is signed with the tenant's federation key like the reader's, for a subject of its own: the
// reader role's trust policy (which pins the reader's subject) cannot be satisfied by it, nor the writer's by the
// reader's. A connector of another tenant, or none, is never signed.
func TestWriterToken_HasItsOwnSubject(t *testing.T) {
	e := newFedEnv(t, newReplay(t))
	k := e.create(t, e.f.A, "prod")
	ctx := context.Background()
	reader, err := e.svc.Federation.Source(e.f.A.ID, k.ID)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := e.svc.Federation.WriterSource(e.f.A.ID, k.ID)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	set := e.jwks(t, e.f.A)
	claims := func(raw string) fedClaims {
		t.Helper()
		c, err := verify(t, raw, set)
		if err != nil {
			t.Fatalf("the token is not signed by the tenant's federation key: %v", err)
		}
		return c
	}
	rc, wc := claims(reader), claims(writer)
	if rc.Subject != Subject(e.f.A.ID, k.ID) || wc.Subject != WriterSubject(e.f.A.ID, k.ID) || rc.Subject == wc.Subject {
		t.Errorf("subjects: reader %q, writer %q", rc.Subject, wc.Subject)
	}
	if !strings.Contains(wc.Subject, ":aws-writer:") || wc.Issuer != rc.Issuer || len(wc.Audience) != 1 || wc.Audience[0] != FederationAudience {
		t.Errorf("writer claims = %+v", wc)
	}
	// the trust policy of the writer role pins the writer subject, which the reader's token does not carry
	if tp := string(TrustPolicy(wc.Issuer, wc.Subject)); !strings.Contains(tp, wc.Subject) || strings.Contains(tp, rc.Subject) {
		t.Errorf("trust policy = %s", tp)
	}
	other := e.create(t, e.f.B, "other")
	if _, err := e.svc.Federation.WriterSource(e.f.A.ID, other.ID)(ctx); err == nil {
		t.Error("a token was signed for another tenant's connector")
	}
	if _, err := e.svc.Federation.WriterSource(e.f.A.ID, "nope")(ctx); err == nil {
		t.Error("a token was signed for no connector")
	}
}

// OpenWriteTarget builds the target of a federated connector of the tenant, and nothing else: a stored-key connector,
// another tenant's, an unknown one or a bad role name is refused.
func TestOpenWriteTarget(t *testing.T) {
	e := newFedEnv(t, newReplay(t))
	k := e.create(t, e.f.A, "prod")
	ctx := context.Background()
	open := func(id, role string) error {
		_, err := e.svc.Federation.OpenWriteTarget(ctx, e.f.A.ID, id, role, nil, nil)
		return err
	}
	if c, err := e.svc.Federation.OpenWriteTarget(ctx, e.f.A.ID, k.ID, "", nil, nil); err != nil {
		t.Fatal(err)
	} else if w, ok := c.(*WriteTarget); !ok || w.Config.ManagementAccountID != "111111111111" || w.ReaderToken == nil || w.WriterToken == nil || w.writerRole() != DefaultWriterRoleName {
		t.Errorf("target = %+v", c)
	}
	if err := open(k.ID, "Custom-Writer"); err != nil {
		t.Errorf("a custom writer role: %v", err)
	}
	if err := open(k.ID, "bad role"); err == nil {
		t.Error("a bad role name was accepted")
	}
	if err := open("nope", ""); err == nil {
		t.Error("an unknown connector was accepted")
	}
	if err := e.f.DB.InTenant(ctx, e.f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAWSConnector(&store.AWSConnector{ID: "00000000-0000-4000-8000-0000000000b1", Name: "b", ExternalID: "x", CreatedBy: "t",
			Config: json.RawMessage(`{"regions":["us-east-1"],"account_ids":["111111111111"],"auth":"federated"}`), CreatedAt: testNow, UpdatedAt: testNow})
	}); err != nil {
		t.Fatal(err)
	}
	if err := open("00000000-0000-4000-8000-0000000000b1", ""); err == nil {
		t.Error("another tenant's connector was accepted")
	}
	if err := e.f.DB.InTenant(ctx, e.f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAWSConnector(&store.AWSConnector{ID: "00000000-0000-4000-8000-0000000000a1", Name: "keyed", ExternalID: "x", CreatedBy: "t",
			Config: json.RawMessage(`{"regions":["us-east-1"],"account_ids":["111111111111"]}`), CreatedAt: testNow, UpdatedAt: testNow})
	}); err != nil {
		t.Fatal(err)
	}
	if err := open("00000000-0000-4000-8000-0000000000a1", ""); err == nil || !strings.Contains(err.Error(), "federated") {
		t.Errorf("a stored-key connector: %v", err)
	}
	var nilFed *Federation
	if _, err := nilFed.OpenWriteTarget(ctx, e.f.A.ID, k.ID, "", nil, nil); err == nil {
		t.Error("a nil federation opened a target")
	}
}
