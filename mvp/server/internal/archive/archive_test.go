package archive_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var (
	tenantT = tenancy.MustParse("00000000-0000-4000-8000-0000000000d1")
	// the records are from 2022; the archive runs in late 2026, past every default retention
	old = time.Date(2022, 3, 1, 9, 0, 0, 0, time.UTC)
	now = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
)

// flaky wraps a BlobStore so a test can break a write, a read or the bytes read.
type flaky struct {
	archive.BlobStore
	putErr error
	gets   int
	// onGet, when set, sees the n-th read (1-based) and may fail it or alter the bytes.
	onGet func(n int, data []byte) ([]byte, error)
}

func (f *flaky) Put(ctx context.Context, key string, data []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.BlobStore.Put(ctx, key, data)
}

func (f *flaky) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := f.BlobStore.Get(ctx, key)
	f.gets++
	if err != nil || f.onGet == nil {
		return b, err
	}
	return f.onGet(f.gets, append([]byte(nil), b...))
}

type env struct {
	t      *testing.T
	db     *store.DB
	dir    string
	sealer *seal.Sealer
	blobs  *flaky
	svc    *archive.Service
	events []*store.AuditEvent // a copy of the chain before anything was archived
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantT, "acme")
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.EnsureAll(context.Background(), db, sealer, old); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	local, err := archive.NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, dir: dir, sealer: sealer, blobs: &flaky{BlobStore: local}}
	e.svc = &archive.Service{DB: db, Sealer: sealer, Store: e.blobs, Clock: func() time.Time { return now }, AuditBatch: 15}
	return e
}

func (e *env) write(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.db.InTenant(context.Background(), tenantT, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(fn func(tx *store.TenantTx) error) {
	e.t.Helper()
	if err := e.db.ReadTenant(context.Background(), tenantT, fn); err != nil {
		e.t.Fatal(err)
	}
}

// events appends n audit events from at, a minute apart.
func (e *env) record(n int, at time.Time) {
	e.t.Helper()
	e.write(func(tx *store.TenantTx) error {
		for i := range n {
			if _, err := audit.Record(context.Background(), tx, "test.event", ojson.Object{{Key: "i", Value: i}},
				audit.At(at.Add(time.Duration(i)*time.Minute))); err != nil {
				return err
			}
		}
		return nil
	})
}

// seed writes records of every class, old ones past every retention and recent ones that are not.
// 40 old audit events with a signed checkpoint among them, then 5 recent ones.
func (e *env) seed() {
	e.t.Helper()
	e.record(25, old)
	cp := &audit.Checkpointer{DB: e.db, Sealer: e.sealer, Sink: &audit.FileSink{Path: filepath.Join(e.dir, "anchors.jsonl")},
		Clock: timeutil.Frozen(old.Add(time.Hour)), Issuer: "http://localhost:5173", Every: time.Minute, EveryEvents: 1000}
	if res, err := cp.Run(context.Background(), true); err != nil || res.Created != 1 {
		e.t.Fatalf("checkpoint: %+v, %v", res, err)
	}
	e.record(15, old.Add(2*time.Hour))
	e.record(5, now.Add(-5*24*time.Hour))
	e.write(func(tx *store.TenantTx) error {
		for i := range 4 {
			fin := old.Add(time.Duration(i) * time.Hour)
			if err := tx.InsertJobRun(&store.JobRun{ID: fmt.Sprintf("run-old-%d", i), Kind: "sync", Trigger: "schedule", Status: "succeeded",
				Actor: "x", StartedAt: old.Add(time.Duration(i) * time.Hour), FinishedAt: &fin}); err != nil {
				return err
			}
		}
		// a run still running, and a recent one, stay online
		if err := tx.InsertJobRun(&store.JobRun{ID: "run-running", Kind: "sync", Trigger: "schedule", Status: "running", Actor: "x", StartedAt: old}); err != nil {
			return err
		}
		if err := tx.InsertJobRun(&store.JobRun{ID: "run-recent", Kind: "sync", Trigger: "schedule", Status: "succeeded", Actor: "x", StartedAt: now.Add(-time.Hour)}); err != nil {
			return err
		}
		em := "a@example.com"
		for i := range 3 {
			if _, err := tx.InsertNotification(&store.Notification{ID: fmt.Sprintf("note-old-%d", i), Email: &em, Kind: "k", Subject: "s", Body: "b",
				DedupeKey: fmt.Sprintf("d-old-%d", i), CreatedAt: old, Delivery: "sent"}); err != nil {
				return err
			}
		}
		// a pending delivery is not done, however old
		if _, err := tx.InsertNotification(&store.Notification{ID: "note-pending", Email: &em, Kind: "k", Subject: "s", Body: "b",
			DedupeKey: "d-pending", CreatedAt: old, Delivery: "pending"}); err != nil {
			return err
		}
		for i, status := range []string{"completed", "completed", "open"} {
			id, err := tx.InsertCampaign(&store.ReviewCampaign{TenantID: tenantT, Name: fmt.Sprintf("c%d", i), CreatedAt: old, Status: status})
			if err != nil {
				return err
			}
			_ = id
		}
		_, err := tx.InsertCampaign(&store.ReviewCampaign{TenantID: tenantT, Name: "recent", CreatedAt: now.Add(-24 * time.Hour), Status: "completed"})
		return err
	})
	e.read(func(tx *store.TenantTx) error {
		var err error
		e.events, err = tx.AuditEventsRange(1, 0, 0)
		return err
	})
}

func (e *env) verify(src audit.ArchiveSource) audit.Report {
	e.t.Helper()
	ctx := context.Background()
	pub, err := audit.PlatformPublicKeys(ctx, e.db)
	if err != nil {
		e.t.Fatal(err)
	}
	var rep audit.Report
	e.read(func(tx *store.TenantTx) error {
		var err error
		rep, err = audit.Verify(tx, "acme", audit.VerifyOptions{Keys: pub, Archive: src, Now: now})
		return err
	})
	return rep
}

func (e *env) segments() []*store.ArchiveSegment {
	e.t.Helper()
	var out []*store.ArchiveSegment
	e.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.ArchiveSegments(store.ArchiveSegmentFilter{Limit: 500})
		return err
	})
	slices.Reverse(out) // oldest first
	return out
}

func (e *env) auditSegments() []*store.ArchiveSegment {
	e.t.Helper()
	var out []*store.ArchiveSegment
	e.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.AuditArchiveSegments()
		return err
	})
	return out
}

func kinds(r audit.Report) []string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, p.Kind)
	}
	return out
}

func (e *env) online() (jobs, campaigns []string, firstSeq int64) {
	e.t.Helper()
	e.read(func(tx *store.TenantTx) error {
		rs, err := tx.JobRuns(store.JobRunFilter{Limit: 100})
		if err != nil {
			return err
		}
		for _, r := range rs {
			jobs = append(jobs, r.ID)
		}
		cs, err := tx.CampaignsNewestFirst()
		if err != nil {
			return err
		}
		for _, c := range cs {
			campaigns = append(campaigns, c.Name)
		}
		evs, err := tx.AuditEventsRange(1, 0, 1)
		if err == nil && len(evs) > 0 {
			firstSeq = evs[0].Seq
		}
		return err
	})
	slices.Sort(jobs)
	slices.Sort(campaigns)
	return
}

// The whole job: records past their retention go to sealed segments and leave
// the online store, recent and unfinished ones stay, and the audit chain
// verifies end to end, archived range included.
func TestRunArchivesPurgesAndKeepsTheChainVerifiable(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if rep := e.verify(nil); rep.Result != "ok" {
		t.Fatalf("the seeded chain does not verify: %+v", rep)
	}
	res, err := e.svc.RunTenant(context.Background(), tenantT)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Classes[store.ClassAudit]; got.Purged != 3 || got.Failed != 0 { // 41 old events in batches of 15: 15, 15, 11
		t.Errorf("audit result = %+v", got)
	}
	if got := res.Classes[store.ClassJobRuns]; got.Purged != 1 || got.Records != 4 {
		t.Errorf("job runs result = %+v", got)
	}
	if got := res.Classes[store.ClassOutbox]; got.Purged != 1 || got.Records != 3 {
		t.Errorf("outbox result = %+v", got)
	}
	if got := res.Classes[store.ClassCampaigns]; got.Purged != 1 || got.Records != 2 {
		t.Errorf("campaigns result = %+v", got)
	}
	jobs, campaigns, first := e.online()
	if !slices.Equal(jobs, []string{"run-recent", "run-running"}) {
		t.Errorf("job runs online = %v", jobs)
	}
	if !slices.Equal(campaigns, []string{"c2", "recent"}) {
		t.Errorf("campaigns online = %v", campaigns)
	}
	segs := e.auditSegments()
	if len(segs) != 3 {
		t.Fatalf("audit segments = %d", len(segs))
	}
	last := segs[len(segs)-1]
	if first != last.SeqTo+1 {
		t.Errorf("the online chain starts at %d, the archive ends at %d", first, last.SeqTo)
	}
	for _, g := range e.segments() {
		if g.Status != store.SegmentPurged || g.VerifiedAt == nil || g.PurgedAt == nil {
			t.Errorf("segment %s is %s", g.ID, g.Status)
		}
	}
	// the chain: online plus archived, end to end
	rep := e.verify(e.svc)
	if rep.Result != "ok" || rep.ExitCode != 0 || len(rep.Problems) != 0 {
		t.Fatalf("verify with the archive: %+v", rep)
	}
	if rep.ArchivedThrough != last.SeqTo || rep.ArchivedSegments != 3 || rep.ArchivedEvents != last.SeqTo || rep.Checkpoints < 1 {
		t.Errorf("report = %+v", rep)
	}
	// without the archive the range is reported as unchecked, never as ok
	rep = e.verify(nil)
	if rep.Result != "warning" || rep.ExitCode != 0 || !slices.Contains(kinds(rep), "archive_unchecked") || rep.ArchivedEvents != 0 {
		t.Errorf("verify without the archive: %+v", rep)
	}
	// the anchor is in the chain, naming the range and the last hash
	var anchors []*store.AuditEvent
	e.read(func(tx *store.TenantTx) error {
		var err error
		anchors, err = tx.AuditEvents(store.AuditFilter{Action: audit.ActionArchived, Limit: 10})
		return err
	})
	if len(anchors) != 3 {
		t.Fatalf("anchor events = %d", len(anchors))
	}
	if !strings.Contains(string(anchors[0].Detail), last.LastHash) && !strings.Contains(string(anchors[2].Detail), last.LastHash) {
		t.Errorf("no anchor names the last archived hash %s", last.LastHash)
	}
	// nothing is left to do
	if res, err := e.svc.RunTenant(context.Background(), tenantT); err != nil || res.Total() != 0 {
		t.Errorf("second run = %+v, %v", res, err)
	}
	// the blobs are ciphertext: no record text in them
	entries, _ := os.ReadDir(filepath.Join(e.dir, tenantT.String(), store.ClassAudit))
	if len(entries) != 3 {
		t.Fatalf("audit blobs = %d", len(entries))
	}
	b, _ := os.ReadFile(filepath.Join(e.dir, tenantT.String(), store.ClassAudit, entries[0].Name()))
	if bytes.Contains(b, []byte("test.event")) || bytes.Contains(b, []byte(tenantT.String())) {
		t.Error("a segment holds plaintext")
	}
}

// The retention setting decides what is due.
func TestRetentionSettingDecidesWhatIsArchived(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.write(func(tx *store.TenantTx) error {
		if err := tx.SetRetentionPolicy(store.ClassAudit, 3650, now, ""); err != nil {
			return err
		}
		return tx.SetRetentionPolicy(store.ClassJobRuns, 3650, now, "")
	})
	res, err := e.svc.RunTenant(context.Background(), tenantT)
	if err != nil {
		t.Fatal(err)
	}
	if res.Classes[store.ClassAudit].Purged != 0 || res.Classes[store.ClassJobRuns].Purged != 0 {
		t.Errorf("records inside their retention were archived: %+v", res.Classes)
	}
	if res.Classes[store.ClassOutbox].Purged != 1 {
		t.Errorf("the outbox was not archived: %+v", res.Classes[store.ClassOutbox])
	}
	// no KEK, no archive: the job does nothing at all
	off := &archive.Service{DB: e.db, Store: e.blobs, Clock: func() time.Time { return now }}
	if res, err := off.RunTenant(context.Background(), tenantT); err != nil || res.Total() != 0 {
		t.Errorf("a service without a sealer ran: %+v, %v", res, err)
	}
}

// Deleting happens only after the segment is written and verified, and a crash
// or an outage at any point loses nothing and is picked up by the next run.
func TestCrashSafeOrder(t *testing.T) {
	boom := errors.New("store unreachable")
	// how many of the seeded events (seq 1..46) are still online: the job's own events come after them
	onlineCount := func(e *env) int {
		var n int64
		e.read(func(tx *store.TenantTx) error {
			var err error
			n, _, _, err = tx.AuditEventStats(1, int64(len(e.events)))
			return err
		})
		return int(n)
	}

	t.Run("the write fails: nothing catalogued, nothing deleted", func(t *testing.T) {
		e := newEnv(t)
		e.seed()
		total := onlineCount(e)
		e.blobs.putErr = boom
		if _, err := e.svc.RunTenant(context.Background(), tenantT); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if n := len(e.segments()); n != 0 {
			t.Errorf("%d segments catalogued after a failed write", n)
		}
		if onlineCount(e) != total {
			t.Error("events were deleted")
		}
		e.blobs.putErr = nil
		if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
			t.Fatal(err)
		}
		if rep := e.verify(e.svc); rep.Result != "ok" {
			t.Errorf("verify after the retry: %+v", rep)
		}
	})

	t.Run("the read-back fails: written, nothing deleted, finished next run", func(t *testing.T) {
		e := newEnv(t)
		e.seed()
		total := onlineCount(e)
		e.blobs.onGet = func(int, []byte) ([]byte, error) { return nil, boom }
		if _, err := e.svc.RunTenant(context.Background(), tenantT); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		segs := e.auditSegments()
		if len(segs) == 0 || segs[0].Status != store.SegmentWritten {
			t.Fatalf("segments = %+v", segs)
		}
		if onlineCount(e) != total {
			t.Error("events were deleted before the segment was verified")
		}
		e.blobs.onGet = nil
		if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
			t.Fatal(err)
		}
		if rep := e.verify(e.svc); rep.Result != "ok" || rep.ArchivedEvents == 0 {
			t.Errorf("verify after the retry: %+v", rep)
		}
		for _, g := range e.segments() {
			if g.Status != store.SegmentPurged {
				t.Errorf("segment %s is %s", g.ID, g.Status)
			}
		}
	})

	t.Run("a crash after verify, before the purge: verified, nothing deleted, purged next run", func(t *testing.T) {
		e := newEnv(t)
		e.seed()
		total := onlineCount(e)
		// the second read of the first segment is the purge's check right before the delete
		e.blobs.onGet = func(n int, b []byte) ([]byte, error) {
			if n == 2 {
				return nil, boom
			}
			return b, nil
		}
		if _, err := e.svc.RunTenant(context.Background(), tenantT); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		segs := e.auditSegments()
		if len(segs) != 1 || segs[0].Status != store.SegmentVerified {
			t.Fatalf("segments = %+v", segs)
		}
		if onlineCount(e) != total {
			t.Error("events were deleted before the purge")
		}
		e.blobs.onGet = nil
		if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
			t.Fatal(err)
		}
		if rep := e.verify(e.svc); rep.Result != "ok" {
			t.Errorf("verify after the retry: %+v", rep)
		}
	})

	t.Run("a blob that is altered before it is verified is given up and nothing is deleted", func(t *testing.T) {
		e := newEnv(t)
		e.seed()
		total := onlineCount(e)
		e.blobs.onGet = func(n int, b []byte) ([]byte, error) {
			b[len(b)/2] ^= 0xff
			return b, nil
		}
		_, err := e.svc.RunTenant(context.Background(), tenantT)
		if err == nil || !archive.IsContent(errors.Unwrap(errors.Unwrap(err))) && !strings.Contains(err.Error(), "failed verification") {
			t.Fatalf("err = %v", err)
		}
		var failed int
		for _, g := range e.segments() {
			if g.Status == store.SegmentFailed {
				failed++
			}
			if g.Status == store.SegmentPurged {
				t.Errorf("segment %s was purged from a bad blob", g.ID)
			}
		}
		if failed == 0 {
			t.Error("no segment was marked failed")
		}
		if onlineCount(e) != total {
			t.Error("events were deleted although the archive was bad")
		}
		// the next run, with a good store, archives the same records again
		e.blobs.onGet = nil
		if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
			t.Fatal(err)
		}
		if rep := e.verify(e.svc); rep.Result != "ok" || rep.ArchivedEvents == 0 {
			t.Errorf("verify after the retry: %+v", rep)
		}
	})

	t.Run("the schema refuses a delete before the segment is verified", func(t *testing.T) {
		e := newEnv(t)
		e.seed()
		err := e.db.InTenant(context.Background(), tenantT, func(tx *store.TenantTx) error { return tx.PurgeArchivedAudit(3) })
		if err == nil {
			t.Fatal("audit events were deleted with no segment")
		}
		// even with a written (not yet verified) segment row
		e.write(func(tx *store.TenantTx) error {
			return tx.InsertArchiveSegment(&store.ArchiveSegment{ID: "00000000-0000-4000-8000-0000000000e1", Class: store.ClassAudit, SeqFrom: 1, SeqTo: 5,
				RangeFrom: "a", RangeTo: "b", Count: 5, Location: store.LocationLocal, ObjectKey: "k", Size: 1,
				SHA256: strings.Repeat("0", 64), CreatedAt: now})
		})
		err = e.db.InTenant(context.Background(), tenantT, func(tx *store.TenantTx) error { return tx.PurgeArchivedAudit(3) })
		if err == nil {
			t.Fatal("audit events were deleted with a segment that is only written")
		}
		// and a segment cannot skip a step
		err = e.db.InTenant(context.Background(), tenantT, func(tx *store.TenantTx) error {
			return tx.MarkArchivePurged("00000000-0000-4000-8000-0000000000e1", now)
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a written segment was purged: %v", err)
		}
	})
}

// A tampered archived segment is caught by the segment check, by the chain
// check, and never opens as another range's or tenant's.
func TestTamperedSegment(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
		t.Fatal(err)
	}
	if rep := e.verify(e.svc); rep.Result != "ok" {
		t.Fatalf("verify: %+v", rep)
	}
	segs := e.auditSegments()
	mid := segs[1]
	ctx := context.Background()

	// a good segment verifies and exports
	chk, err := e.svc.Verify(ctx, tenantT, mid)
	if err != nil || !chk.OK || chk.Records != mid.Count {
		t.Fatalf("Verify = %+v, %v", chk, err)
	}

	t.Run("a byte flipped in the stored blob", func(t *testing.T) {
		p := filepath.Join(e.dir, filepath.FromSlash(mid.ObjectKey))
		orig, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(p, orig, 0o600)
		bad := append([]byte(nil), orig...)
		bad[len(bad)/2] ^= 0x01
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		chk, err := e.svc.Verify(ctx, tenantT, mid)
		if err != nil || chk.OK || !strings.Contains(chk.Problem, "checksum") {
			t.Errorf("Verify = %+v, %v", chk, err)
		}
		rep := e.verify(e.svc)
		if rep.Result != "failed" || rep.ExitCode != audit.ExitHashMismatch || !slices.Contains(kinds(rep), "archive_corrupt") {
			t.Errorf("chain verify = %+v", rep)
		}
		var sink bytes.Buffer
		if _, err := e.svc.Export(ctx, tenantT, mid, &sink); err == nil || sink.Len() != 0 {
			t.Errorf("a tampered segment was exported: %v, %d bytes", err, sink.Len())
		}
	})

	t.Run("the blob is gone", func(t *testing.T) {
		p := filepath.Join(e.dir, filepath.FromSlash(mid.ObjectKey))
		orig, _ := os.ReadFile(p)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(p, orig, 0o600)
		chk, err := e.svc.Verify(ctx, tenantT, mid)
		if err != nil || chk.OK || !strings.Contains(chk.Problem, "no object") {
			t.Errorf("Verify = %+v, %v", chk, err)
		}
		if rep := e.verify(e.svc); rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_corrupt") {
			t.Errorf("chain verify = %+v", rep)
		}
	})

	t.Run("a segment swapped for another range's blob", func(t *testing.T) {
		// the other segment's blob is intact and has its own checksum: the catalogue entry refuses it
		other := segs[0]
		p := filepath.Join(e.dir, filepath.FromSlash(mid.ObjectKey))
		orig, _ := os.ReadFile(p)
		swap, _ := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(other.ObjectKey)))
		defer os.WriteFile(p, orig, 0o600)
		if err := os.WriteFile(p, swap, 0o600); err != nil {
			t.Fatal(err)
		}
		if chk, err := e.svc.Verify(ctx, tenantT, mid); err != nil || chk.OK {
			t.Errorf("Verify = %+v, %v", chk, err)
		}
	})

	// The seal alone binds a segment to its tenant, class and range: a blob the
	// KEK holder re-sealed for one range does not open as another.
	t.Run("the seal binds tenant, class and range", func(t *testing.T) {
		g := *mid
		for name, other := range map[string]func(*store.ArchiveSegment) (tenancy.ID, *store.ArchiveSegment){
			"another tenant": func(g *store.ArchiveSegment) (tenancy.ID, *store.ArchiveSegment) {
				return tenancy.MustParse("00000000-0000-4000-8000-0000000000d2"), g
			},
			"another class": func(g *store.ArchiveSegment) (tenancy.ID, *store.ArchiveSegment) {
				c := *g
				c.Class = store.ClassRequests
				return tenantT, &c
			},
			"another range": func(g *store.ArchiveSegment) (tenancy.ID, *store.ArchiveSegment) {
				c := *g
				c.SeqTo++
				return tenantT, &c
			},
			"another id": func(g *store.ArchiveSegment) (tenancy.ID, *store.ArchiveSegment) {
				c := *g
				c.ID = "00000000-0000-4000-8000-0000000000ff"
				return tenantT, &c
			},
		} {
			tn, c := other(&g)
			if archive.SealedFor(e.sealer, tenantT, &g, tn, c) {
				t.Errorf("%s: a segment sealed for one binding opened under another", name)
			}
		}
		if !archive.SealedFor(e.sealer, tenantT, &g, tenantT, &g) {
			t.Error("a segment does not open under its own binding")
		}
	})

	t.Run("the chain verifier catches an event altered inside a segment", func(t *testing.T) {
		lines, err := e.svc.OpenAuditSegment(tenantT, mid)
		if err != nil {
			t.Fatal(err)
		}
		// 1. one event edited, its hash left as it was
		edited := cloneLines(lines)
		edited[3] = bytes.Replace(edited[3], []byte(`"action":"test.event"`), []byte(`"action":"grant.revoke"`), 1)
		if bytes.Equal(edited[3], lines[3]) {
			t.Fatal("the edit changed nothing")
		}
		rep := e.verify(fakeSource{mid.ID: edited}.with(e))
		if rep.Result != "failed" || rep.ExitCode != audit.ExitHashMismatch || !slices.Contains(kinds(rep), "archive_hash_mismatch") {
			t.Errorf("edited event: %+v", rep)
		}
		// 2. an event dropped
		dropped := slices.Delete(cloneLines(lines), 4, 5)
		rep = e.verify(fakeSource{mid.ID: dropped}.with(e))
		if rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_count") {
			t.Errorf("dropped event: %+v", rep)
		}
		// 3. events swapped
		swapped := cloneLines(lines)
		swapped[2], swapped[3] = swapped[3], swapped[2]
		rep = e.verify(fakeSource{mid.ID: swapped}.with(e))
		if rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_seq_gap") {
			t.Errorf("swapped events: %+v", rep)
		}
		// 4. an event edited and its hash recomputed: the next link breaks
		forged := cloneLines(lines)
		forged[5] = e.reforge(mid, 5)
		rep = e.verify(fakeSource{mid.ID: forged}.with(e))
		if rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_broken_link") {
			t.Errorf("forged event: %+v", rep)
		}
		// 5. the last event of the segment forged, its hash recomputed: the catalogue and the anchor disagree
		forged = cloneLines(lines)
		forged[len(forged)-1] = e.reforge(mid, len(forged)-1)
		rep = e.verify(fakeSource{mid.ID: forged}.with(e))
		if rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_ends") {
			t.Errorf("forged last event: %+v", rep)
		}
	})
}

func cloneLines(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, l := range in {
		out[i] = append([]byte(nil), l...)
	}
	return out
}

// fakeSource serves chosen content for chosen segments and the real one for the rest.
type fakeSource map[string][][]byte

type withReal struct {
	fake fakeSource
	real audit.ArchiveSource
}

func (f fakeSource) with(e *env) audit.ArchiveSource { return withReal{f, e.svc} }

func (w withReal) OpenAuditSegment(t tenancy.ID, g *store.ArchiveSegment) ([][]byte, error) {
	if lines, ok := w.fake[g.ID]; ok {
		return lines, nil
	}
	return w.real.OpenAuditSegment(t, g)
}

// reforge returns the export line of the i-th event of segment g (from the copy of the chain taken
// before the archive ran) with its action changed and its hash recomputed.
func (e *env) reforge(g *store.ArchiveSegment, i int) []byte {
	e.t.Helper()
	ev := *e.events[int(g.SeqFrom)-1+i]
	ev.Action = "grant.revoke"
	h, err := audit.EventHash(&ev)
	if err != nil {
		e.t.Fatal(err)
	}
	ev.Hash = h
	rec, err := audit.ExportRecord(&ev)
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := ojson.Marshal(rec)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// A forged catalogue row, or a segment with no anchor in the chain, cannot pass:
// the anchor event is part of the hash chain, which the database owner cannot rewrite.
func TestForgedSegmentRowHasNoAnchor(t *testing.T) {
	e := newEnv(t)
	e.seed()
	// build a segment's content the honest way, then catalogue it as purged without the anchor event
	good := newEnv(t)
	good.seed()
	if _, err := good.svc.RunTenant(context.Background(), tenantT); err != nil {
		t.Fatal(err)
	}
	segs := good.auditSegments()
	first := segs[0]
	lines, err := good.svc.OpenAuditSegment(tenantT, first)
	if err != nil {
		t.Fatal(err)
	}
	// in e, register the same range as written, verified and purged, with no events deleted and no anchor
	e.write(func(tx *store.TenantTx) error {
		g := *first
		g.ID = "00000000-0000-4000-8000-0000000000f1"
		if err := tx.InsertArchiveSegment(&g); err != nil {
			return err
		}
		if err := tx.MarkArchiveVerified(g.ID, now); err != nil {
			return err
		}
		return tx.MarkArchivePurged(g.ID, now)
	})
	rep := e.verify(fakeSource{"00000000-0000-4000-8000-0000000000f1": lines}.with(e))
	if rep.Result != "failed" || !slices.Contains(kinds(rep), "archive_anchor_missing") {
		t.Errorf("a forged segment row passed: %+v", rep)
	}
}

// Export is the read-only restore: it checks the segment and streams its
// records. An audit segment exports portable events that verify offline.
func TestExport(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if _, err := e.svc.RunTenant(context.Background(), tenantT); err != nil {
		t.Fatal(err)
	}
	var total int
	prev := ""
	for _, g := range e.auditSegments() {
		var buf bytes.Buffer
		n, err := e.svc.Export(context.Background(), tenantT, g, &buf)
		if err != nil || int64(n) != g.Count {
			t.Fatalf("Export = %d, %v", n, err)
		}
		for _, ln := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
			ok, h, err := audit.VerifyRecord(ln)
			if err != nil || !ok {
				t.Fatalf("exported record does not verify: %v %v", ok, err)
			}
			total++
			prev = h
		}
	}
	if int64(total) != e.auditSegments()[len(e.auditSegments())-1].SeqTo || prev != e.auditSegments()[len(e.auditSegments())-1].LastHash {
		t.Errorf("exported %d events ending at %.12s", total, prev)
	}
	for _, g := range e.segments() {
		if g.Class == store.ClassJobRuns {
			var buf bytes.Buffer
			if n, err := e.svc.Export(context.Background(), tenantT, g, &buf); err != nil || n != 4 || !strings.Contains(buf.String(), `"run-old-0"`) {
				t.Errorf("job run export = %d, %v: %.200s", n, err, buf.String())
			}
		}
	}
}
