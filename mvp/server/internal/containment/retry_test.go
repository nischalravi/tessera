package containment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type retryEnv struct {
	t    *testing.T
	f    *storetest.Fixture
	svc  *Service
	now  time.Time
	fail atomic.Bool
}

func newRetryEnv(t *testing.T) *retryEnv {
	t.Helper()
	e := &retryEnv{t: t, f: storetest.TwoTenants(t), now: storetest.Now}
	e.fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	e.svc = &Service{HTTP: hc, Sealer: sl, Clock: func() time.Time { return e.now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	e.write(func(c *store.TenantTx) error {
		return e.svc.PutCredential(c, e.f.A.Refs["connection"], CredentialInput{Token: "tok", BaseURL: srv.URL}, "admin", e.now)
	})
	// the leaver's first failed run queues the retries
	e.write(func(c *store.TenantTx) error {
		specs, err := Steps(c, e.f.A.IDs["alice"], true)
		if err != nil {
			return err
		}
		job, err := e.svc.BuildJob(c, e.f.A.IDs["alice"], "leaver", specs)
		if err != nil {
			return err
		}
		rep := e.svc.Run(context.Background(), job)
		if rep.OK {
			t.Fatal("the failing provider passed")
		}
		rows, err := EnqueueRetries(c, e.now, job, rep)
		if len(rows) != 2 {
			t.Fatalf("retries = %d", len(rows))
		}
		return err
	})
	return e
}

func (e *retryEnv) write(fn func(*store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *retryEnv) rows() (out []*store.ContainmentRetry) {
	e.t.Helper()
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		var err error
		out, err = c.ContainmentRetriesFor(e.f.A.IDs["alice"])
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *retryEnv) actions() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{})
		for _, ev := range evs {
			out[ev.Action]++
		}
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *retryEnv) sweep() []*store.ContainmentRetry {
	e.t.Helper()
	rows, err := e.svc.RunRetries(context.Background(), e.f.DB, e.f.A.ID, "containment.sweeper", "")
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour, time.Hour}
	for i, w := range want {
		if got := Backoff(i); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i, got, w)
		}
	}
}

func TestRetrySweeperBacksOffThenSucceeds(t *testing.T) {
	e := newRetryEnv(t)
	for _, r := range e.rows() {
		if r.Status != store.RetryPending || r.Attempts != 0 || !r.NextAttemptAt.Equal(e.now.Add(time.Minute)) || r.LastError == "" {
			t.Fatalf("queued row %+v", r)
		}
	}
	if got := e.sweep(); len(got) != 0 {
		t.Fatalf("a task ran before it was due: %v", got)
	}
	var delays []time.Duration
	for i := 0; i < 3; i++ { // 1m, 5m, 15m
		e.now = e.rows()[0].NextAttemptAt
		before := e.now
		if got := e.sweep(); len(got) != 2 {
			t.Fatalf("round %d ran %d tasks", i, len(got))
		}
		r := e.rows()[0]
		delays = append(delays, r.NextAttemptAt.Sub(before))
		if r.Status != store.RetryPending || r.Attempts != i+1 {
			t.Fatalf("after round %d: %+v", i, r)
		}
	}
	if delays[0] != 5*time.Minute || delays[1] != 15*time.Minute || delays[2] != time.Hour {
		t.Errorf("backoff delays %v", delays)
	}
	// the provider recovers: the next attempt passes its re-read and settles the tasks
	e.fail.Store(false)
	e.now = e.rows()[0].NextAttemptAt
	e.sweep()
	for _, r := range e.rows() {
		if r.Status != store.RetrySucceeded || r.Attempts != 4 || r.LastError != "" {
			t.Errorf("not succeeded: %+v", r)
		}
	}
	a := e.actions()
	if a["containment.retry_succeeded"] != 2 || a["containment.retry_attempt"] != 8 || a["containment.retry_scheduled"] != 2 ||
		a["containment.run"] < 8 || a["containment.retry_gave_up"] != 0 {
		t.Errorf("audit %v", a)
	}
	if got := e.sweep(); len(got) != 0 {
		t.Errorf("a succeeded task ran again: %v", got)
	}
}

func TestRetryGivesUpAfterADay(t *testing.T) {
	e := newRetryEnv(t)
	start := e.now
	attempts := 0
	for ; attempts < 100; attempts++ {
		rows := e.rows()
		if rows[0].Status != store.RetryPending {
			break
		}
		e.now = rows[0].NextAttemptAt
		e.sweep()
	}
	for _, r := range e.rows() {
		if r.Status != store.RetryGaveUp || r.Attempts < 5 || r.LastError == "" {
			t.Fatalf("not given up: %+v", r)
		}
		v := ViewRetry(r)
		if v.ManualAction == "" || v.NextAttemptAt != nil {
			t.Errorf("a given-up task must carry its manual task: %+v", v)
		}
	}
	if e.now.Sub(start) > MaxRetryAge+time.Hour || e.now.Sub(start) < 20*time.Hour {
		t.Errorf("gave up after %v", e.now.Sub(start))
	}
	if a := e.actions(); a["containment.retry_gave_up"] != 2 || a["containment.retry_succeeded"] != 0 {
		t.Errorf("audit %v", a)
	}
	e.now = e.now.Add(48 * time.Hour)
	if got := e.sweep(); len(got) != 0 {
		t.Errorf("a given-up task ran again: %v", got)
	}
}

// retry-now runs one pending task whatever its schedule, and refuses a settled one.
func TestRetryNow(t *testing.T) {
	e := newRetryEnv(t)
	e.fail.Store(false)
	id := e.rows()[0].ID
	rows, err := e.svc.RunRetries(context.Background(), e.f.DB, e.f.A.ID, "admin", id)
	if err != nil || len(rows) != 1 || rows[0].Status != store.RetrySucceeded {
		t.Fatalf("retry-now: %v %v", rows, err)
	}
	if _, err := e.svc.RunRetries(context.Background(), e.f.DB, e.f.A.ID, "admin", id); err == nil {
		t.Error("a settled task was retried")
	}
	if _, err := e.svc.RunRetries(context.Background(), e.f.DB, e.f.B.ID, "admin", id); err == nil {
		t.Error("tenant B reached tenant A's task")
	}
}
