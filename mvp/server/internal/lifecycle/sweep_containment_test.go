package lifecycle_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// containmentEnv is tenant A (alice has an okta account on a live
// connection) with alice's term due, and a fake Okta that counts calls.
type containmentEnv struct {
	t       *testing.T
	f       *storetest.Fixture
	svc     *containment.Service
	now     time.Time
	fail    atomic.Bool
	deletes atomic.Int32
}

func newContainmentEnv(t *testing.T, credential bool) *containmentEnv {
	t.Helper()
	e := &containmentEnv{t: t, f: storetest.TwoTenants(t), now: storetest.Now}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodDelete {
			e.deletes.Add(1)
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
	e.svc = &containment.Service{HTTP: hc, Sealer: sl, Clock: func() time.Time { return e.now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	e.write(func(c *store.TenantTx) error {
		if credential {
			if err := e.svc.PutCredential(c, e.f.A.Refs["connection"],
				containment.CredentialInput{Token: "tok", BaseURL: srv.URL}, "admin", e.now); err != nil {
				return err
			}
		}
		ends := e.now.Add(-time.Hour)
		carol := e.f.A.IDs["carol"]
		return c.PutLifecycle(&store.Lifecycle{IdentityID: e.f.A.IDs["alice"], WorkerType: store.WorkerContractor,
			SponsorID: &carol, EndsAt: &ends, Source: "manual", UpdatedAt: e.now.Add(-48 * time.Hour)})
	})
	return e
}

func (e *containmentEnv) write(fn func(*store.TenantTx) error) {
	e.t.Helper()
	if err := e.f.DB.InTenant(context.Background(), e.f.A.ID, fn); err != nil {
		e.t.Fatal(err)
	}
}

type scopeA struct{ e *containmentEnv }

func (s scopeA) Read(ctx context.Context, fn func(*store.TenantTx) error) error {
	return s.e.f.DB.ReadTenant(ctx, s.e.f.A.ID, fn)
}

func (s scopeA) Write(ctx context.Context, fn func(*store.TenantTx) error) error {
	return s.e.f.DB.InTenant(ctx, s.e.f.A.ID, fn)
}

func (e *containmentEnv) sweep(svc *containment.Service) lifecycle.SweepResult {
	e.t.Helper()
	res, err := lifecycle.SweepTenant(context.Background(), scopeA{e}, svc, e.now)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// state returns alice's status, the audit actions and her retry rows.
func (e *containmentEnv) state() (status string, actions map[string]int, retries []*store.ContainmentRetry) {
	e.t.Helper()
	actions = map[string]int{}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		p, err := c.Identity(e.f.A.IDs["alice"])
		if err != nil {
			return err
		}
		status = p.Status
		evs, err := c.AuditEvents(store.AuditFilter{})
		if err != nil {
			return err
		}
		for _, ev := range evs {
			actions[ev.Action]++
		}
		retries, err = c.ContainmentRetriesFor(p.ID)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return
}

func TestSweepTenant_ContainsThenEnds(t *testing.T) {
	e := newContainmentEnv(t, true)
	if r := e.sweep(e.svc); r.Ended != 1 {
		t.Fatalf("result = %+v", r)
	}
	status, actions, retries := e.state()
	if status != "terminated" {
		t.Errorf("status = %s", status)
	}
	if e.deletes.Load() == 0 {
		t.Error("no session was revoked at the provider")
	}
	if actions["containment.run"] != 1 || actions["lifecycle.end"] != 1 {
		t.Errorf("audit = %v", actions)
	}
	if len(retries) != 0 {
		t.Errorf("retries = %d", len(retries))
	}
}

func TestSweepTenant_FailureStillEndsAndQueuesRetries(t *testing.T) {
	e := newContainmentEnv(t, true)
	e.fail.Store(true)
	if r := e.sweep(e.svc); r.Ended != 1 {
		t.Fatalf("result = %+v", r)
	}
	status, actions, retries := e.state()
	if status != "terminated" {
		t.Errorf("status = %s", status)
	}
	if len(retries) == 0 || retries[0].Trigger != "lifecycle" {
		t.Errorf("retries = %+v", retries)
	}
	if actions["containment.run"] != 1 || actions["containment.retry_scheduled"] != len(retries) {
		t.Errorf("audit = %v", actions)
	}
}

func TestSweepTenant_NoCredentialIsManualAndStillEnds(t *testing.T) {
	for name, svc := range map[string]func(e *containmentEnv) *containment.Service{
		"no credential": func(e *containmentEnv) *containment.Service { return e.svc },
		"nil service":   func(*containmentEnv) *containment.Service { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			e := newContainmentEnv(t, false)
			if r := e.sweep(svc(e)); r.Ended != 1 {
				t.Fatalf("result = %+v", r)
			}
			status, actions, retries := e.state()
			if status != "terminated" || len(retries) != 0 {
				t.Errorf("status = %s, retries = %d", status, len(retries))
			}
			if e.deletes.Load() != 0 {
				t.Error("the provider was called with no credential")
			}
			if actions["containment.run"] != 1 {
				t.Errorf("audit = %v", actions)
			}
		})
	}
}

func TestSweepTenant_SpentDeadlineLeavesThemDue(t *testing.T) {
	e := newContainmentEnv(t, true)
	spent := *e.svc
	spent.SweepBudget = time.Nanosecond
	if r := e.sweep(&spent); r.Ended != 0 {
		t.Fatalf("ended without containment: %+v", r)
	}
	status, actions, _ := e.state()
	if status != "active" || actions["lifecycle.end"] != 0 || actions["containment.run"] != 0 || e.deletes.Load() != 0 {
		t.Fatalf("status = %s, audit = %v, deletes = %d", status, actions, e.deletes.Load())
	}
	if r := e.sweep(e.svc); r.Ended != 1 {
		t.Fatalf("next pass = %+v", r)
	}
	status, actions, _ = e.state()
	if status != "terminated" || actions["containment.run"] != 1 || e.deletes.Load() == 0 {
		t.Errorf("status = %s, audit = %v", status, actions)
	}
}
