package backup_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/backup"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var (
	t0      = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-00000000b0a1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-00000000b0b2")
)

type fixture struct {
	db      *store.DB
	dir     string
	sealer  *seal.Sealer
	anchors string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	testkit.CreateTenant(t, db, tenantA, "tenant-a")
	testkit.CreateTenant(t, db, tenantB, "tenant-b")
	s, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.EnsureAll(context.Background(), db, s, t0); err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: db, dir: dir, sealer: s, anchors: filepath.Join(dir, "anchors.jsonl")}
	f.record(t, tenantA, 5)
	f.record(t, tenantB, 3)
	f.checkpoint(t, t0)
	return f
}

func (f *fixture) record(t *testing.T, tn tenancy.ID, n int) {
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

func (f *fixture) checkpoint(t *testing.T, now time.Time) {
	t.Helper()
	ck := &audit.Checkpointer{DB: f.db, Sealer: f.sealer, Sink: &audit.FileSink{Path: f.anchors},
		Clock: timeutil.Frozen(now), Issuer: "http://localhost:5173", Every: time.Nanosecond, EveryEvents: 1}
	if _, err := ck.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) backup(t *testing.T) *backup.Created {
	t.Helper()
	c, err := backup.Create(context.Background(), f.db, f.sealer, backup.CreateOptions{Dir: filepath.Join(f.dir, "backups"), Env: "test", Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) anchorSet(t *testing.T) *audit.AnchorSet {
	t.Helper()
	a, err := audit.ReadAnchors(f.anchors)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func code(err error) string {
	var be *backup.Error
	if errors.As(err, &be) {
		return be.Code
	}
	return ""
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	if fi, err := os.Stat(c.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file %v %v", fi, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(f.dir, "backups", ".snapshot-*")); len(matches) != 0 {
		t.Errorf("plaintext snapshot left behind: %v", matches)
	}
	raw, _ := os.ReadFile(c.Path)
	if bytes.Contains(raw, []byte("SQLite format 3")) || bytes.Contains(raw, []byte("test.event")) {
		t.Fatal("backup is not encrypted")
	}
	m, err := backup.ReadManifest(c.Path)
	if err != nil || m.ID != c.Manifest.ID || len(m.Tenants) != 3 { // _platform, tenant-a, tenant-b
		t.Fatalf("manifest %+v %v", m, err)
	}

	target := filepath.Join(f.dir, "restored.db")
	res, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Target: target, Anchors: f.anchorSet(t), Now: t0})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, tr := range res.Tenants {
		if tr.Report.Result == "failed" || tr.LostAfterBackup != 0 {
			t.Errorf("%s: %+v", tr.Slug, tr)
		}
	}
	got, err := backup.Heads(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range got {
		if h != m.Tenants[i] {
			t.Errorf("head %s: %+v, backup had %+v", h.Slug, h, m.Tenants[i])
		}
	}
}

// TestRestore_OlderBackupAgainstNewerAnchors: anchors written after the
// backup do not read as truncation; the report says what the restore loses.
func TestRestore_OlderBackupAgainstNewerAnchors(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	f.record(t, tenantA, 4)
	f.checkpoint(t, t0.Add(time.Minute))
	res, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Anchors: f.anchorSet(t), Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res.Tenants {
		if tr.Slug == "tenant-a" && tr.LostAfterBackup < 4 {
			t.Errorf("lost window %d, want >= 4", tr.LostAfterBackup)
		}
	}
}

func TestTamperedBackupRefused(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	raw, err := os.ReadFile(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.IndexByte(raw[len("TESSERA-BACKUP v1\n"):], '\n') + len("TESSERA-BACKUP v1\n") + 1
	cases := map[string]func([]byte) []byte{
		"flipped chunk byte": func(b []byte) []byte { b[len(b)-20] ^= 1; return b },
		"edited manifest":    func(b []byte) []byte { return bytes.Replace(b, []byte(`"env":"test"`), []byte(`"env":"prod"`), 1) },
		"truncated":          func(b []byte) []byte { return b[:len(b)-100] },
		"appended":           func(b []byte) []byte { return append(b, 0, 0, 0, 1, 7) },
		"no chunks":          func(b []byte) []byte { return b[:body] },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(f.dir, strings.ReplaceAll(name, " ", "-")+".tbak")
			if err := os.WriteFile(p, mut(append([]byte(nil), raw...)), 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(f.dir, name+".db")
			_, err := backup.Restore(context.Background(), p, f.sealer, backup.RestoreOptions{Target: target, Now: t0})
			if code(err) != "tampered_backup" {
				t.Fatalf("got %v", err)
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Error("a refused backup was installed")
			}
		})
	}
	other, _ := seal.New(seal.RandomBytes(seal.KeySize))
	if _, err := backup.Restore(context.Background(), c.Path, other, backup.RestoreOptions{Now: t0}); code(err) != "wrong_kek" {
		t.Errorf("wrong KEK: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "x.tbak"), []byte("hello"), 0o600); err == nil {
		if _, err := backup.Restore(context.Background(), filepath.Join(f.dir, "x.tbak"), f.sealer, backup.RestoreOptions{Now: t0}); code(err) != "not_a_backup" {
			t.Errorf("not a backup: %v", err)
		}
	}
}

// TestRestore_RefusesBrokenChain: a database whose audit chain was edited
// before the backup was taken decrypts fine but is refused, and the target
// is left alone.
func TestRestore_RefusesBrokenChain(t *testing.T) {
	f := newFixture(t)
	tp, err := f.db.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.DropTriggers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tp.EditDetail(context.Background(), tenantA, 2, `{"i":99}`); err != nil {
		t.Fatal(err)
	}
	c := f.backup(t)
	target := filepath.Join(f.dir, "existing.db")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Target: target, Force: true, Now: t0})
	if code(err) != "verification_failed" {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep me" {
		t.Error("the target was replaced by a backup that failed verification")
	}
	if res == nil || len(res.Tenants) == 0 {
		t.Error("no report for the refused backup")
	}
}

func TestRestore_AnchorMismatchRefused(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	// A different anchor source (another instance's) vouches for nothing.
	g := newFixture(t)
	_, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Anchors: g.anchorSet(t), Now: t0})
	if code(err) != "verification_failed" {
		t.Fatalf("got %v", err)
	}
}

func TestRestore_TargetExists(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	target := filepath.Join(f.dir, "live2.db")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Target: target, Now: t0}); code(err) != "target_exists" {
		t.Fatalf("got %v", err)
	}
	res, err := backup.Restore(context.Background(), c.Path, f.sealer, backup.RestoreOptions{Target: target, Force: true, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(res.Previous); string(b) != "old" {
		t.Errorf("previous database not kept at %s", res.Previous)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"tessera-20261001T000000Z-a.tbak", "tessera-20261002T000000Z-b.tbak", "tessera-20261003T000000Z-c.tbak", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := backup.Prune(dir, 2)
	if err != nil || len(removed) != 1 || !strings.HasSuffix(removed[0], "-a.tbak") {
		t.Fatalf("removed %v %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Error("prune touched a file that is not a backup")
	}
}

func TestUpload(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	client, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Upload(context.Background(), client, srv.URL+"/bucket/b.tbak", c.Path); err != nil {
		t.Fatal(err)
	}
	if want, _ := os.ReadFile(c.Path); !bytes.Equal(got, want) {
		t.Error("uploaded bytes differ")
	}
	guarded, _ := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err := backup.Upload(context.Background(), guarded, srv.URL+"/x", c.Path); err == nil {
		t.Error("the SSRF guard let a prod upload reach loopback")
	}
}
