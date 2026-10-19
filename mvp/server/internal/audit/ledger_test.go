package audit_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/audit_v1.json")

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-00000000a0d1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-00000000b0d2")
	t0      = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
)

type ledgerFixture struct {
	db      *store.DB
	path    string
	sealer  *seal.Sealer
	anchors string
}

// newLedger opens a database with tenants A and B and the platform key.
func newLedger(t *testing.T) *ledgerFixture {
	t.Helper()
	dir := t.TempDir()
	path := store.TestTarget(t)
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	testkit.CreateTenant(t, db, tenantA, "tenant-a")
	testkit.CreateTenant(t, db, tenantB, "tenant-b")
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	s, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.EnsureAll(context.Background(), db, s, t0); err != nil {
		t.Fatal(err)
	}
	return &ledgerFixture{db: db, path: path, sealer: s, anchors: filepath.Join(dir, "var", "audit-anchors.jsonl")}
}

func (f *ledgerFixture) record(t *testing.T, tn tenancy.ID, n int) {
	t.Helper()
	ctx := context.Background()
	if err := f.db.InTenant(ctx, tn, func(tx *store.TenantTx) error {
		for i := range n {
			if _, err := audit.Record(ctx, tx, "test.event", ojson.Object{{Key: "i", Value: i}}, audit.At(t0)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *ledgerFixture) events(t *testing.T, tn tenancy.ID) []*store.AuditEvent {
	t.Helper()
	var out []*store.AuditEvent
	if err := f.db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.AuditEventsRange(1, 0, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestChainLinks: seqs are 1..n, each prev_hash is the previous hash (genesis
// first), each hash recomputes, and the head is the last event.
func TestChainLinks(t *testing.T) {
	f := newLedger(t)
	f.record(t, tenantA, 5)
	f.record(t, tenantB, 2)
	f.record(t, tenantA, 3)
	for tn, want := range map[tenancy.ID]int{tenantA: 8, tenantB: 2} {
		evs := f.events(t, tn)
		if len(evs) != want {
			t.Fatalf("%s: %d events, want %d", tn, len(evs), want)
		}
		prev := audit.Genesis(tn)
		for i, e := range evs {
			if e.Seq != int64(i+1) || e.PrevHash != prev || e.TenantID != tn {
				t.Errorf("event %d: seq %d prev %.8s want %.8s", i, e.Seq, e.PrevHash, prev)
			}
			if h, err := audit.EventHash(e); err != nil || h != e.Hash {
				t.Errorf("seq %d: hash does not recompute (%v)", e.Seq, err)
			}
			prev = e.Hash
		}
		if err := f.db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
			h, err := tx.AuditHead()
			if err == nil && (h.LastSeq != int64(want) || h.LastHash != prev) {
				t.Errorf("head %d %.8s, want %d %.8s", h.LastSeq, h.LastHash, want, prev)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHashReproducibleFromJCS rebuilds an event's hash with nothing but
// encoding/json, the JCS library and SHA-256, following the documented
// recipe (design §13.2), independently of canon.Hash.
func TestHashReproducibleFromJCS(t *testing.T) {
	f := newLedger(t)
	ctx := context.Background()
	var e store.AuditEvent
	if err := f.db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		var err error
		e, err = audit.Record(ctx, tx, "grant.revoke", ojson.Object{{Key: "edge_id", Value: 19},
			{Key: "grant", Value: "workday:emp-1033 → workday:AP Approver"}, {Key: "nested", Value: ojson.Object{{Key: "z", Value: nil}, {Key: "a", Value: []any{true, "x"}}}}},
			audit.At(t0.Add(123456*time.Microsecond)), audit.Target("edge", "19"), audit.PolicyVersion("abc123"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"v": 1, "tenant_id": tenantA.String(), "seq": e.Seq, "id": e.ID.String(),
		"occurred_at": "2026-10-08T09:30:00.123456Z",
		"actor":       map[string]any{"type": "system", "id": "system", "display": "system"},
		"session_id":  nil, "client_id": nil, "authn": nil, "action": "grant.revoke",
		"target":  map[string]any{"type": "edge", "id": "19"},
		"outcome": "success", "request_id": nil, "http": nil, "ip": nil, "ua": nil, "policy_version": "abc123",
		"detail":    json.RawMessage(e.Detail),
		"prev_hash": audit.Genesis(tenantA),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("tessera-audit-v1\x00"), c...))
	if got := hex.EncodeToString(sum[:]); got != e.Hash {
		t.Errorf("independent hash %s, stored %s\ncanonical: %s", got, e.Hash, c)
	}
}

// TestRecordSystemActor: without a request or job context, Record (and the
// MVP helper) attribute the event to the system; a job context names the job.
func TestRecordSystemActor(t *testing.T) {
	f := newLedger(t)
	ctx := context.Background()
	if err := f.db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		if _, err := audit.Record(ctx, tx, "a", nil); err != nil {
			return err
		}
		if err := tx.Audit(t0, "jit.sweeper", "b", nil); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	job := audit.WithSystemActor(ctx, "audit.checkpointer")
	if err := f.db.InTenant(job, tenantA, func(tx *store.TenantTx) error {
		_, err := audit.Record(job, tx, "c", nil, audit.LegacyActor("someone else"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	evs := f.events(t, tenantA)
	want := []string{"system", "jit.sweeper", "audit.checkpointer"}
	for i, e := range evs {
		if e.ActorType != store.ActorSystem || e.ActorID == nil || *e.ActorID != want[i] {
			t.Errorf("event %s: actor %s %v, want system %s", e.Action, e.ActorType, e.ActorID, want[i])
		}
	}
	if string(evs[2].Detail) != "{}" {
		t.Errorf("a job's own actor is not a claim: %s", evs[2].Detail)
	}
}

// TestRollbackLeavesNoEvent: a domain event commits atomically with its
// mutation; a rolled-back transaction leaves no event and no head change.
func TestRollbackLeavesNoEvent(t *testing.T) {
	f := newLedger(t)
	f.record(t, tenantA, 2)
	before := f.events(t, tenantA)
	ctx := context.Background()
	boom := errors.New("revoke failed")
	err := f.db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		if _, err := audit.Record(ctx, tx, "grant.revoke", ojson.Object{{Key: "edge_id", Value: 1}}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	after := f.events(t, tenantA)
	if len(after) != len(before) {
		t.Fatalf("rollback left %d events", len(after)-len(before))
	}
	f.record(t, tenantA, 1)
	if evs := f.events(t, tenantA); evs[2].Seq != 3 || evs[2].PrevHash != before[1].Hash {
		t.Errorf("chain after rollback: seq %d", evs[2].Seq)
	}
}

// TestConcurrentAppendsGapless: 8 goroutines appending to the same tenant
// (and to another) produce gapless, linked chains (run under -race).
func TestConcurrentAppendsGapless(t *testing.T) {
	f := newLedger(t)
	const writers, each = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*2)
	for w := range writers {
		for _, tn := range []tenancy.ID{tenantA, tenantB} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := context.Background()
				for i := range each {
					if err := f.db.InTenant(ctx, tn, func(tx *store.TenantTx) error {
						_, err := audit.Record(ctx, tx, "concurrent", ojson.Object{{Key: "w", Value: w}, {Key: "i", Value: i}})
						return err
					}); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		evs := f.events(t, tn)
		if len(evs) != writers*each {
			t.Fatalf("%d events, want %d", len(evs), writers*each)
		}
		var rep audit.Report
		if err := f.db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
			var err error
			rep, err = audit.Verify(tx, "x", audit.VerifyOptions{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if rep.ExitCode != 0 || rep.LastSeq != writers*each || rep.FirstSeq != 1 {
			t.Errorf("verify after concurrent appends: %+v", rep)
		}
	}
}

// ---------------------------------------------------------------- golden vector

const goldenPath = "../../testdata/golden/audit_v1.json"

type goldenEvent struct {
	Record    json.RawMessage `json:"record"`
	Canonical string          `json:"canonical"`
	Hash      string          `json:"hash"`
}

type golden struct {
	Description string        `json:"description"`
	Algorithm   string        `json:"algorithm"`
	Genesis     string        `json:"genesis_algorithm"`
	TenantID    string        `json:"tenant_id"`
	GenesisHash string        `json:"genesis_hash"`
	Events      []goldenEvent `json:"events"`
}

func sp(s string) *string { return &s }

// goldenEvents are fixed events covering every field type of the v1 body.
func goldenEvents() []store.AuditEvent {
	aal, phr, age := 2, true, int64(312)
	authn, _ := json.Marshal(store.AuditAuthn{CtxID: sp("ctx-1"), AAL: &aal, Phr: &phr, ACR: sp("phr"),
		AuthTime: sp("2026-10-08T09:24:48.000000Z"), AuthAgeS: &age})
	route := "/api/identities/{identity_id}"
	httpj, _ := json.Marshal(store.AuditHTTP{Method: "GET", Route: &route, PathParams: map[string]string{"identity_id": "42"},
		QueryKeys: []string{"include", "limit"}, Status: 200, LatencyMS: 7})
	d1, _ := canon.Detail(ojson.Object{{Key: "request_id", Value: 4}, {Key: "group", Value: "ProdAdmin"}, {Key: "hours", Value: "1.5"}})
	d2, _ := canon.Detail(ojson.Object{{Key: "anonymous_reason", Value: "authentication_not_enabled"}}) // a literal: the golden vector is fixed
	d3, _ := canon.Detail(ojson.Object{{Key: "€uro", Value: "</script> ö 😂 →"}, {Key: "max", Value: int64(canon.MaxSafeInt)},
		{Key: "min", Value: int64(-canon.MaxSafeInt)}, {Key: "empty", Value: ojson.Object{}}, {Key: "null", Value: nil},
		{Key: "list", Value: []any{true, false, "", int64(0)}}, {Key: "line\nbreak", Value: "tab\there"}})
	return []store.AuditEvent{
		{ID: uuid.MustParse("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"), OccurredAt: t0, ActorType: store.ActorSystem,
			ActorID: sp("Wren Okafor"), ActorDisplay: sp("Wren Okafor"), Action: "jit.request", Outcome: store.OutcomeSuccess, Detail: d1},
		{ID: uuid.MustParse("7a2b3c4d-5e6f-4a01-9b2c-3d4e5f6a7b8c"), OccurredAt: t0.Add(1500 * time.Microsecond),
			ActorType: store.ActorAnonymous, Action: store.ActionHTTPRequest, Outcome: store.OutcomeSuccess,
			TargetType: sp("identity"), TargetID: sp("42"), RequestID: sp("0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b"), HTTP: httpj,
			IP: sp("127.0.0.1"), UserAgentSHA256: sp("a1b1c1d1e1f1a2b2c2d2e2f2a3b3c3d3e3f3a4b4c4d4e4f4a5b5c5d5e5f5a6b6"), Detail: d2},
		{ID: uuid.MustParse("8b3c4d5e-6f7a-4b12-8c3d-4e5f6a7b8c9d"), OccurredAt: t0.Add(time.Second + 999999*time.Microsecond),
			ActorType: store.ActorUser, ActorID: sp("u-123"), ActorDisplay: sp("Ingrid Lindqvist"), SessionID: sp("s-9"),
			ClientID: sp("tessera-cli"), Authn: authn, Action: "jit.approve", Outcome: store.OutcomeDenied,
			TargetType: sp("access_request"), TargetID: sp("4"), PolicyVersion: sp("4b825dc642cb6eb9a060e54bf8d69288fbee4904"), Detail: d3},
	}
}

// TestGoldenVector checks testdata/golden/audit_v1.json, the cross-language
// contract (design §13.2): the store reproduces every hash from the same
// inputs, and every record's hash follows from its canonical form alone.
// Regenerate with: go test ./internal/audit -run TestGoldenVector -update
func TestGoldenVector(t *testing.T) {
	f := newLedger(t)
	ctx := context.Background()
	var appended []store.AuditEvent
	if err := f.db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		for _, e := range goldenEvents() {
			got, err := audit.Append(ctx, tx, e)
			if err != nil {
				return err
			}
			appended = append(appended, got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	g := golden{
		Description: "Tessera audit ledger hash v1 test vector. Each record is the hashed body plus \"hash\". " +
			"Remove \"hash\", canonicalize the rest with RFC 8785 (JCS), and hash = lower-hex SHA-256 of the bytes " +
			"\"tessera-audit-v1\" 0x00 followed by the canonical form. prev_hash of seq 1 is the genesis hash.",
		Algorithm:   `sha256("tessera-audit-v1" || 0x00 || RFC8785(record without "hash"))`,
		Genesis:     `sha256("tessera-audit-genesis-v1:" || tenant_id)`,
		TenantID:    tenantA.String(),
		GenesisHash: audit.Genesis(tenantA),
	}
	for i := range appended {
		e := &appended[i]
		rec, err := audit.ExportRecord(e)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ojson.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		c, err := canon.Canonical(e.Body())
		if err != nil {
			t.Fatal(err)
		}
		g.Events = append(g.Events, goldenEvent{Record: raw, Canonical: string(c), Hash: e.Hash})
	}
	if *update {
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (regenerate with -update)", err)
	}
	var want golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want.GenesisHash != g.GenesisHash || len(want.Events) != len(g.Events) {
		t.Fatalf("golden genesis or length differs")
	}
	gen := sha256.Sum256([]byte("tessera-audit-genesis-v1:" + want.TenantID))
	if hex.EncodeToString(gen[:]) != want.GenesisHash {
		t.Error("golden genesis does not follow from its algorithm")
	}
	prev := want.GenesisHash
	for i, we := range want.Events {
		if we.Hash != g.Events[i].Hash || we.Canonical != g.Events[i].Canonical {
			t.Errorf("event %d: the store no longer reproduces the golden hash\n want %s\n got  %s", i, we.Hash, g.Events[i].Hash)
		}
		// independent of our code: SHA-256 over the separator and the canonical text
		sum := sha256.Sum256(append([]byte("tessera-audit-v1\x00"), we.Canonical...))
		if hex.EncodeToString(sum[:]) != we.Hash {
			t.Errorf("event %d: hash does not follow from its canonical form", i)
		}
		// the record, minus hash, canonicalizes to the canonical form
		if ok, got, err := audit.VerifyRecord(we.Record); err != nil || !ok {
			t.Errorf("event %d: record does not verify: %s %v", i, got, err)
		}
		var link struct {
			PrevHash string `json:"prev_hash"`
		}
		if err := json.Unmarshal(we.Record, &link); err != nil || link.PrevHash != prev {
			t.Errorf("event %d: prev_hash does not link", i)
		}
		prev = we.Hash
	}
}

// FuzzEventHash: hashing never panics and is deterministic, and a valid
// detail survives re-encoding with the same hash.
func FuzzEventHash(f *testing.F) {
	f.Add("jit.request", `{"request_id":4,"group":"ProdAdmin"}`, int64(1), "system", "Wren Okafor")
	f.Add("x", `{"a":{"b":[1,"two",null,true]}}`, int64(9007199254740991), "anonymous", "")
	f.Add("unicode →", `{"€":"😂","</script>":""}`, int64(42), "user", "Ingrid")
	f.Add("", `{"f":1.5}`, int64(-1), "", "\x00")
	f.Fuzz(func(t *testing.T, action, detail string, seq int64, actorType, actor string) {
		d, err := canon.DetailJSON([]byte(detail))
		if err != nil {
			return
		}
		e := store.AuditEvent{ID: uuid.MustParse("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"), TenantID: tenantA, Seq: seq,
			OccurredAt: t0, ActorType: actorType, ActorID: &actor, Action: action, Outcome: "success", Detail: d,
			PrevHash: audit.Genesis(tenantA)}
		h1, err1 := audit.EventHash(&e)
		h2, err2 := audit.EventHash(&e)
		if (err1 == nil) != (err2 == nil) || h1 != h2 {
			t.Fatalf("not deterministic: %s %v / %s %v", h1, err1, h2, err2)
		}
		if err1 != nil {
			return
		}
		e.Detail = json.RawMessage(detail) // the original spelling
		if h3, err := audit.EventHash(&e); err != nil || h3 != h1 {
			t.Fatalf("re-encoding the detail changed the hash: %s vs %s (%v)", h3, h1, err)
		}
		if !canon.IsHash(h1) {
			t.Fatalf("hash %q", h1)
		}
	})
}

func ExampleGenesis() {
	fmt.Println(len(audit.Genesis(tenancy.Platform)))
	// Output: 64
}
