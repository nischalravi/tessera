package provision_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const (
	aliceName = "alice@larkspur.example"
	token     = "target-bearer-token"
)

type env struct {
	t      *testing.T
	f      *storetest.Fixture
	fake   *fake.Server
	srv    *httptest.Server
	eng    *provision.Engine
	sealer *seal.Sealer
	conn   string
	system string
	now    time.Time
}

// setup builds the two-tenant fixture, a fake SCIM target for tenant A's
// connection, and an engine that never waits between attempts.
func setup(t *testing.T, o fake.Options) *env {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &env{t: t, f: f, now: storetest.Now, conn: f.A.Refs["connection:ad"]}
	o.Token = token
	e.fake = fake.New(o)
	e.srv = httptest.NewServer(e.fake.Handler())
	t.Cleanup(e.srv.Close)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if e.sealer, err = seal.New(seal.RandomBytes(seal.KeySize)); err != nil {
		t.Fatal(err)
	}
	e.eng = &provision.Engine{DB: f.DB, Sealer: e.sealer, HTTP: hc, Clock: func() time.Time { return e.now },
		MaxAttempts: 3, MaxVerifies: 3, Backoff: func(int) time.Duration { return 0 }}
	e.inA(func(c *store.TenantTx) error {
		cn, err := c.Connection(e.conn)
		e.system = cn.System
		return err
	})
	e.setTarget(true, provision.Settings{})
	return e
}

func (e *env) inA(fn func(*store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) setTarget(writeBack bool, s provision.Settings) {
	e.t.Helper()
	settings, _ := json.Marshal(s)
	id := store.NewID()
	enc, err := provision.SealToken(e.sealer, e.f.A.ID, id, token)
	if err != nil {
		e.t.Fatal(err)
	}
	e.inA(func(c *store.TenantTx) error {
		if old, err := c.ProvTarget(e.conn); err == nil {
			id = old.ID
			if enc, err = provision.SealToken(e.sealer, e.f.A.ID, id, token); err != nil {
				return err
			}
		}
		return c.UpsertProvTarget(&store.ProvTarget{ID: id, ConnectionID: e.conn, Kind: provision.KindSCIM,
			BaseURL: e.srv.URL + "/scim/v2", Settings: string(settings), CredentialEnc: enc, WriteBack: writeBack, CreatedBy: "admin"}, e.now)
	})
}

// completed counts how many times the test completion ran.
var completed int

func init() {
	provision.RegisterCompletion("test.mark", func(_ *store.TenantTx, _ time.Time, _ json.RawMessage) error {
		completed++
		return nil
	})
}

func (e *env) submit(kind, key string) *store.ProvOp {
	e.t.Helper()
	var op *store.ProvOp
	e.inA(func(c *store.TenantTx) error {
		var routed bool
		var err error
		op, routed, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: kind,
			Account: target.Account{Username: aliceName}, Source: provision.SourceAPI, Key: key, Completion: "test.mark", Data: map[string]int{"n": 1}})
		if err == nil && !routed {
			err = errors.New("not routed")
		}
		return err
	})
	return op
}

func (e *env) op(id string) *store.ProvOp {
	e.t.Helper()
	var op *store.ProvOp
	e.inA(func(c *store.TenantTx) (err error) { op, err = c.ProvOp(id); return })
	return op
}

func (e *env) run() provision.Stats {
	e.t.Helper()
	s, err := e.eng.RunTenant(context.Background(), e.f.A.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) auditActions() []string {
	var out []string
	e.inA(func(c *store.TenantTx) error {
		evs, err := c.AuditLog(-1)
		for _, ev := range evs {
			if strings.HasPrefix(ev.Action, "provision.") {
				out = append([]string{ev.Action}, out...)
			}
		}
		return err
	})
	return out
}

func TestEngine_DisableIsVerifiedByReRead(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	completed = 0
	op := e.submit(target.DisableAccount, "t:disable:1")
	if op.Status != provision.Queued || completed != 0 {
		t.Fatalf("a submitted operation is queued and has not completed: %+v", op)
	}
	st := e.run()
	got := e.op(op.ID)
	if got.Status != provision.Verified || st.Verified != 1 || completed != 1 || got.CompletedAt == nil {
		t.Fatalf("op = %+v stats = %+v completed = %d", got, st, completed)
	}
	if _, active := e.fake.Active(aliceName); active {
		t.Error("the target still shows the user active")
	}
	if want := []string{"provision.enqueued", "provision.sent", "provision.verified"}; strings.Join(e.auditActions(), ",") != strings.Join(want, ",") {
		t.Errorf("audit = %v, want %v", e.auditActions(), want)
	}
	if again := e.run(); again.Processed != 0 {
		t.Errorf("a verified operation ran again: %+v", again)
	}
	for _, k := range e.fake.IdempotencyKeys() {
		if k != "t:disable:1" {
			t.Errorf("Idempotency-Key = %q", k)
		}
	}
}

func TestEngine_SubmitIsIdempotentAndDeclinesWithoutWriteBack(t *testing.T) {
	e := setup(t, fake.Options{})
	a, b := e.submit(target.DisableAccount, "k"), e.submit(target.DisableAccount, "k")
	if a.ID != b.ID {
		t.Errorf("the same key made two operations: %s, %s", a.ID, b.ID)
	}
	e.setTarget(false, provision.Settings{})
	e.inA(func(c *store.TenantTx) error {
		op, routed, err := provision.Submit(c, e.now, provision.Change{System: e.system, Kind: target.DisableAccount,
			Account: target.Account{Username: aliceName}, Key: "k2"})
		if op != nil || routed || err != nil {
			t.Errorf("write-back off: Submit = %v, %v, %v; want it to decline", op, routed, err)
		}
		op, routed, err = provision.Submit(c, e.now, provision.Change{System: "no-such-system", Kind: target.DisableAccount,
			Account: target.Account{Username: aliceName}, Key: "k3"})
		if op != nil || routed || err != nil {
			t.Errorf("no target: Submit = %v, %v, %v; want it to decline", op, routed, err)
		}
		return nil
	})
}

func TestEngine_SubmitValidates(t *testing.T) {
	e := setup(t, fake.Options{})
	for name, ch := range map[string]provision.Change{
		"kind":    {System: e.system, Kind: "nuke", Account: target.Account{Username: "a"}, Key: "k"},
		"account": {System: e.system, Kind: target.DisableAccount, Key: "k"},
		"key":     {System: e.system, Kind: target.DisableAccount, Account: target.Account{Username: "a"}},
		"group":   {System: e.system, Kind: target.AddEntitlement, Account: target.Account{Username: "a"}, Key: "k"},
		"unregistered completion": {System: e.system, Kind: target.DisableAccount, Account: target.Account{Username: "a"}, Key: "k",
			Completion: "nope"},
	} {
		e.inA(func(c *store.TenantTx) error {
			if _, _, err := provision.Submit(c, e.now, ch); err == nil {
				t.Errorf("%s: Submit accepted %+v", name, ch)
			}
			return nil
		})
	}
}

// A failed target write leaves the item open: the completion never runs.
func TestEngine_FailedWriteNeverCompletes(t *testing.T) {
	e := setup(t, fake.Options{Fault: fake.FailWrites})
	e.fake.AddUser(aliceName, "Alice", true)
	completed = 0
	op := e.submit(target.DisableAccount, "t:fail")
	var got *store.ProvOp
	for i := 0; i < 3; i++ { // MaxAttempts
		if st := e.run(); st.Processed != 1 {
			t.Fatalf("pass %d: %+v", i, st)
		}
		got = e.op(op.ID)
		if i < 2 && got.Status != provision.Queued {
			t.Fatalf("pass %d: status = %s, want queued for another attempt", i, got.Status)
		}
	}
	if got.Status != provision.Failed || got.Attempts != 3 || completed != 0 || got.LastError == nil ||
		!strings.Contains(*got.LastError, "503") {
		t.Fatalf("op = %+v completed = %d", got, completed)
	}
	if strings.Contains(*got.LastError, token) {
		t.Error("the error mentions the credential")
	}
	if !strings.Contains(strings.Join(e.auditActions(), ","), "provision.failed") {
		t.Errorf("audit = %v", e.auditActions())
	}
	// The operator fixes the target and retries: the same operation completes.
	e.fake.SetFault("")
	e.inA(func(c *store.TenantTx) error { _, err := provision.Retry(c, e.now, op.ID); return err })
	if st := e.run(); st.Verified != 1 || completed != 1 {
		t.Fatalf("after the retry: stats = %+v completed = %d", st, completed)
	}
}

func TestEngine_BackoffDelaysTheNextAttempt(t *testing.T) {
	e := setup(t, fake.Options{Fault: fake.FailWrites})
	e.fake.AddUser(aliceName, "Alice", true)
	e.eng.Backoff = func(n int) time.Duration { return time.Duration(n) * time.Hour }
	op := e.submit(target.DisableAccount, "t:backoff")
	e.run()
	got := e.op(op.ID)
	if got.Status != provision.Queued || !got.NextAttemptAt.Equal(e.now.Add(time.Hour)) {
		t.Fatalf("op = %+v, want queued with the next attempt an hour out", got)
	}
	if st := e.run(); st.Processed != 0 {
		t.Errorf("an operation ran before its next attempt time: %+v", st)
	}
	e.now = e.now.Add(time.Hour + time.Second)
	if st := e.run(); st.Processed != 1 {
		t.Errorf("an operation did not run after its next attempt time: %+v", st)
	}
}

// The target acknowledges the write but does not apply it: the re-read
// catches it, the operation is a mismatch, a finding is raised, and the
// completion never runs.
func TestEngine_MismatchRaisesFinding(t *testing.T) {
	e := setup(t, fake.Options{Fault: fake.DropWrites})
	e.fake.AddUser(aliceName, "Alice", true)
	completed = 0
	op := e.submit(target.DisableAccount, "t:drop")
	var got *store.ProvOp
	for i := 0; i < 3; i++ { // MaxVerifies disagreeing reads
		e.run()
		got = e.op(op.ID)
	}
	if got.Status != provision.Mismatch || completed != 0 || got.Observed == nil || *got.Observed != "active=true" {
		t.Fatalf("op = %+v completed = %d", got, completed)
	}
	var fs []*store.ProvFinding
	e.inA(func(c *store.TenantTx) (err error) { fs, err = c.ProvFindings("open", ""); return })
	if len(fs) != 1 || fs[0].OpID != op.ID || fs[0].Code != "verify_mismatch" || fs[0].Severity != "high" ||
		fs[0].Expected != "account disabled" || fs[0].Observed != "active=true" {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(strings.Join(e.auditActions(), ","), "provision.mismatch") {
		t.Errorf("audit = %v", e.auditActions())
	}
	// Cancelling closes the finding and never completes.
	e.inA(func(c *store.TenantTx) error {
		_, err := provision.Cancel(c, e.now, op.ID)
		return err
	})
	e.inA(func(c *store.TenantTx) error {
		if fs, _ := c.ProvFindings("open", ""); len(fs) != 0 {
			t.Errorf("open findings after cancel = %d", len(fs))
		}
		return nil
	})
	if e.op(op.ID).Status != provision.Cancelled || completed != 0 {
		t.Errorf("cancelled op = %+v, completed = %d", e.op(op.ID), completed)
	}
}

func TestEngine_RetryAfterFailureCompletes(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	e.setTarget(true, provision.Settings{})
	// Break the target's credential: the sealed token is wrong, so the target answers 401 (permanent).
	e.inA(func(c *store.TenantTx) error {
		old, _ := c.ProvTarget(e.conn)
		enc, err := provision.SealToken(e.sealer, e.f.A.ID, old.ID, "wrong")
		if err != nil {
			return err
		}
		old.CredentialEnc = enc
		return c.UpsertProvTarget(old, e.now)
	})
	completed = 0
	op := e.submit(target.DisableAccount, "t:401")
	e.run()
	got := e.op(op.ID)
	if got.Status != provision.Failed || got.Attempts != 1 {
		t.Fatalf("a refused credential is permanent: %+v", got)
	}
	e.setTarget(true, provision.Settings{}) // the operator fixes the credential
	e.inA(func(c *store.TenantTx) error { _, err := provision.Retry(c, e.now, op.ID); return err })
	if st := e.run(); st.Verified != 1 || completed != 1 {
		t.Fatalf("stats = %+v completed = %d", st, completed)
	}
	// Retrying a verified operation is refused.
	e.inA(func(c *store.TenantTx) error {
		var pe *provision.Error
		if _, err := provision.Retry(c, e.now, op.ID); !errors.As(err, &pe) || pe.Status != 409 {
			t.Errorf("Retry(verified) = %v", err)
		}
		return nil
	})
}

func TestEngine_RetryingTheSameKeyRequeuesAFailedOperation(t *testing.T) {
	e := setup(t, fake.Options{Fault: fake.FailWrites})
	e.fake.AddUser(aliceName, "Alice", true)
	op := e.submit(target.DisableAccount, "t:again")
	for i := 0; i < 3; i++ {
		e.run()
	}
	if e.op(op.ID).Status != provision.Failed {
		t.Fatal("setup: the operation should have failed")
	}
	e.setTarget(true, provision.Settings{}) // same fake; fault stays, so just check the requeue
	again := e.submit(target.DisableAccount, "t:again")
	if again.ID != op.ID || again.Status != provision.Queued || again.Attempts != 0 {
		t.Errorf("resubmitting a failed key = %+v, want the same operation queued again", again)
	}
	var inflight *store.ProvOp
	e.inA(func(c *store.TenantTx) (err error) { inflight, err = provision.InFlight(c, "t:again"); return })
	if inflight == nil {
		t.Error("InFlight = nil for a queued operation")
	}
}

func TestEngine_CredentialIsSealedAndTenantBound(t *testing.T) {
	e := setup(t, fake.Options{})
	var pt *store.ProvTarget
	e.inA(func(c *store.TenantTx) (err error) { pt, err = c.ProvTarget(e.conn); return })
	if bytes.Contains(pt.CredentialEnc, []byte(token)) {
		t.Fatal("the credential is stored in the clear")
	}
	if _, err := e.sealer.Open(pt.CredentialEnc, seal.AAD(e.f.B.ID, "provisioning_targets", "credential_enc", pt.ID)); err == nil {
		t.Error("another tenant's AAD opened the credential")
	}
	if _, err := e.sealer.Open(pt.CredentialEnc, seal.AAD(e.f.A.ID, "provisioning_targets", "credential_enc", "other-row")); err == nil {
		t.Error("another row's AAD opened the credential")
	}
	// The worker really uses it: the fake requires the bearer token.
	e.fake.AddUser(aliceName, "Alice", true)
	op := e.submit(target.DisableAccount, "t:cred")
	e.run()
	if e.op(op.ID).Status != provision.Verified {
		t.Errorf("op = %+v", e.op(op.ID))
	}
}

func TestEngine_OtherTenantsOperationsAreNotRun(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	e.submit(target.DisableAccount, "t:iso")
	st, err := e.eng.RunTenant(context.Background(), e.f.B.ID)
	if err != nil || st.Processed != 0 {
		t.Fatalf("tenant B's pass = %+v, %v", st, err)
	}
}

func TestEngine_StaleSentOperationsAreRequeued(t *testing.T) {
	e := setup(t, fake.Options{})
	e.fake.AddUser(aliceName, "Alice", true)
	op := e.submit(target.DisableAccount, "t:stale")
	// A worker claimed it and stopped.
	e.inA(func(c *store.TenantTx) error {
		return c.SetProvOpState(op.ID, provision.Queued, store.ProvOpState{Status: provision.Sent, Attempts: 1, NextAttemptAt: e.now}, e.now)
	})
	if st := e.run(); st.Processed != 0 {
		t.Fatalf("a recently sent operation was taken: %+v", st)
	}
	e.now = e.now.Add(time.Hour)
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("a stale sent operation was not recovered: %+v", st)
	}
}

func TestEngine_EntitlementOperationsEndToEnd(t *testing.T) {
	e := setup(t, fake.Options{MemberPage: 2})
	uid := e.fake.AddUser(aliceName, "Alice", true)
	var others []string
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		others = append(others, e.fake.AddUser(n+"@larkspur.example", n, true))
	}
	e.fake.AddGroup("engineering", "eng", append(others, uid)...)
	var op *store.ProvOp
	e.inA(func(c *store.TenantTx) (err error) {
		op, _, err = provision.Submit(c, e.now, provision.Change{System: e.system, Kind: target.RemoveEntitlement,
			Account: target.Account{Username: aliceName}, Group: target.Group{ExternalID: "eng", Name: "engineering"},
			Source: provision.SourceReview, Key: "t:rm"})
		return
	})
	if op.TargetRef != aliceName+" / engineering" {
		t.Errorf("target ref = %q", op.TargetRef)
	}
	if st := e.run(); st.Verified != 1 {
		t.Fatalf("stats = %+v, op = %+v", st, e.op(op.ID))
	}
	for _, m := range e.fake.Members("engineering") {
		if m == aliceName {
			t.Error("alice is still in the group")
		}
	}
}
