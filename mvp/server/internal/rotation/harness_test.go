package rotation

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// harness is a rotation service and engine over tenant B of the two-tenant
// fixture, with a clock the test moves.
type harness struct {
	t      *testing.T
	db     *store.DB
	dbPath string
	tenant tenancy.ID
	acct   int64 // the aws service account that owns the test secrets
	svc    *Service
	eng    *Engine
	sealer *seal.Sealer
	http   *http.Client
	mu     sync.Mutex
	now    time.Time
	notes  *recordingNotifier
}

type recordingNotifier struct {
	mu   sync.Mutex
	list []Notification
}

func (r *recordingNotifier) Notify(ctx context.Context, tx *store.TenantTx, n Notification) error {
	r.mu.Lock()
	r.list = append(r.list, n)
	r.mu.Unlock()
	return AuditNotifier{}.Notify(ctx, tx, n)
}

func (r *recordingNotifier) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, n := range r.list {
		out = append(out, n.Event)
	}
	return out
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	client, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "rotation.db")
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := &harness{t: t, db: db, dbPath: dbPath, tenant: tenancy.MustParse("00000000-0000-4000-8000-0000000000c3"), sealer: sealer, http: client,
		now: storetest.Now, notes: &recordingNotifier{}}
	if err := db.InSystem(context.Background(), "rotation test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: h.tenant, Slug: "rotation-test", Name: "rotation-test", CreatedAt: storetest.Now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.write(func(tx *store.TenantTx, now time.Time) error {
		if _, err := ingest.Sync(tx, now, []connectors.Connector{connectors.Tiny{Now: now}}, nil); err != nil {
			return err
		}
		aws := "aws"
		accts, err := tx.AccountsBySystemUsername(&aws)
		for _, a := range accts {
			if a.Username == "svc-etl" {
				h.acct = a.ID
			}
		}
		return err
	})
	h.svc = &Service{Sealer: sealer, Env: config.Dev, AllowFake: true, Notifier: h.notes}
	clock := func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	}
	h.eng = &Engine{DB: h.db, Service: h.svc, Clock: clock, Sleep: func(context.Context, time.Duration) {},
		Factory: &Factory{HTTP: client, Sealer: sealer, Now: clock, AllowFake: true},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil))}
	return h
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) ctx() context.Context { return audit.WithSystemActor(context.Background(), "test") }

func (h *harness) write(fn func(tx *store.TenantTx, now time.Time) error) {
	h.t.Helper()
	if err := h.db.InTenant(h.ctx(), h.tenant, func(tx *store.TenantTx) error { return fn(tx, h.clock()) }); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) read(fn func(tx *store.TenantTx, now time.Time) error) {
	h.t.Helper()
	if err := h.db.ReadTenant(h.ctx(), h.tenant, func(tx *store.TenantTx) error { return fn(tx, h.clock()) }); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) putAdapter(in AdapterInput) *AdapterView {
	h.t.Helper()
	var v *AdapterView
	h.write(func(tx *store.TenantTx, now time.Time) error {
		var err error
		v, _, err = h.svc.PutAdapter(tx, in, "tester", now)
		return err
	})
	return v
}

func (h *harness) putPolicy(in PolicyInput) *PolicyView {
	h.t.Helper()
	var v *PolicyView
	h.write(func(tx *store.TenantTx, now time.Time) error {
		var err error
		v, _, err = h.svc.PutPolicy(tx, in, "tester", now)
		return err
	})
	return v
}

// addSecret records an active secret on tenant B's aws service account.
func (h *harness) addSecret(system, kind, name, externalID string, age time.Duration) int64 {
	h.t.Helper()
	var id int64
	h.write(func(tx *store.TenantTx, now time.Time) error {
		acct := h.acct
		if err := tx.UpsertSecret(&store.Secret{TenantID: h.tenant, System: system, ExternalID: externalID, Kind: kind, Name: name,
			CreatedAt: now.Add(-age)}, &acct); err != nil {
			return err
		}
		all, err := tx.Secrets()
		for _, s := range all {
			if s.ExternalID == externalID && s.System == system {
				id = s.ID
			}
		}
		return err
	})
	return id
}

// startRotation queues a rotation of the secret and returns the job id.
func (h *harness) startRotation(secretID int64) string {
	h.t.Helper()
	var id string
	h.write(func(tx *store.TenantTx, now time.Time) error {
		j, err := h.svc.StartRotation(tx, secretID, "tester", now)
		if err == nil {
			id = j.ID
		}
		return err
	})
	return id
}

// tick runs the engine once for tenant B.
func (h *harness) tick() int {
	h.t.Helper()
	n, err := h.eng.RunTenant(h.ctx(), h.tenant)
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *harness) job(id string) *store.RotationJob {
	h.t.Helper()
	var j *store.RotationJob
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		var err error
		j, err = tx.RotationJob(id)
		return err
	})
	return j
}

func (h *harness) secret(id int64) *store.Secret {
	h.t.Helper()
	var s *store.Secret
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		var err error
		s, err = tx.SecretByID(id)
		return err
	})
	return s
}

// actions lists the audit actions of tenant B that start with prefix, oldest first.
func (h *harness) actions(prefix string) []string {
	h.t.Helper()
	var out []string
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		evs, err := tx.AuditLog(-1)
		for i := len(evs) - 1; i >= 0; i-- {
			if strings.HasPrefix(evs[i].Action, prefix) {
				out = append(out, evs[i].Action)
			}
		}
		return err
	})
	return out
}

// auditText is every audit event's detail of tenant B as one string, to check what must not be in it.
func (h *harness) auditText() string {
	h.t.Helper()
	var b strings.Builder
	h.read(func(tx *store.TenantTx, _ time.Time) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			b.WriteString(e.Action + " " + string(e.Detail) + "\n")
		}
		return err
	})
	return b.String()
}

var _ = timeutil.System

func storetestNow() time.Time { return storetest.Now }

// fileHas reports whether the database files (main and write-ahead log) hold needle.
func (h *harness) fileHas(needle string) bool {
	h.t.Helper()
	if err := h.db.Checkpoint(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	for _, p := range []string{h.dbPath, h.dbPath + "-wal"} {
		b, err := os.ReadFile(p) // #nosec G304 -- the test's own temp database
		if err != nil {
			continue
		}
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}
