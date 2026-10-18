package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func newChecker(t *testing.T) (*Checker, *obs.Loops, *time.Time) {
	t.Helper()
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	loops := obs.NewLoops(func() time.Time { return now })
	loops.Register("sweeper", 30*time.Second, true)
	loops.Done("sweeper", now, nil)
	c := New(f.DB, sealer, loops, 5*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return now }
	return c, loops, &now
}

func TestReady_AllOK(t *testing.T) {
	c, _, _ := newChecker(t)
	r := c.Ready(context.Background())
	if !r.Ready() || r.Status != "ok" {
		t.Fatalf("not ready: %+v", r)
	}
	for _, n := range checkNames {
		if !r.OK(n) {
			t.Errorf("check %s: %q", n, r.Checks[n])
		}
	}
}

// Readiness fails closed on each dependency, and only that check says "fail".
func TestReady_FailsClosedOnEachDependency(t *testing.T) {
	boom := errors.New("boom: /secret/path password=hunter2")
	cases := []struct {
		name   string
		break_ func(c *Checker, loops *obs.Loops, now *time.Time)
		want   []string // failing checks
	}{
		{"database", func(c *Checker, _ *obs.Loops, _ *time.Time) { c.Database = func(context.Context) error { return boom } }, []string{CheckDatabase}},
		{"audit chain", func(c *Checker, _ *obs.Loops, _ *time.Time) {
			c.AuditChain = func(context.Context) error { return boom }
		}, []string{CheckAuditChain}},
		{"kek missing", func(c *Checker, _ *obs.Loops, _ *time.Time) { c.Sealer = nil }, []string{CheckKEK}},
		{"kek broken", func(c *Checker, _ *obs.Loops, _ *time.Time) { c.KEK = func(context.Context) error { return boom } }, []string{CheckKEK}},
		{"loop lagging", func(_ *Checker, _ *obs.Loops, now *time.Time) { *now = now.Add(6 * time.Minute) }, []string{CheckLoops}},
		{"loop failing", func(_ *Checker, l *obs.Loops, now *time.Time) {
			*now = now.Add(6 * time.Minute)
			l.Done("sweeper", *now, errors.New("x")) // a failed run is not a success
		}, []string{CheckLoops}},
		{"panicking probe", func(c *Checker, _ *obs.Loops, _ *time.Time) { c.Database = func(context.Context) error { panic("x") } }, []string{CheckDatabase}},
		{"no database", func(c *Checker, _ *obs.Loops, _ *time.Time) { c.DB = nil }, []string{CheckDatabase, CheckAuditChain}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, loops, now := newChecker(t)
			tc.break_(c, loops, now)
			r := c.Ready(context.Background())
			if r.Ready() || r.Status != "unavailable" {
				t.Fatalf("ready despite %s: %+v", tc.name, r)
			}
			for _, n := range checkNames {
				failing := false
				for _, w := range tc.want {
					failing = failing || w == n
				}
				if r.OK(n) == failing {
					t.Errorf("check %s ok=%v, want failing=%v", n, r.OK(n), failing)
				}
			}
			// constant shape, no error text
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "secret") || strings.Contains(string(b), "boom") {
				t.Errorf("error text leaked: %s", b)
			}
		})
	}
}

func TestReady_ClosedDatabaseFailsClosed(t *testing.T) {
	c, _, _ := newChecker(t)
	if err := c.DB.Close(); err != nil {
		t.Fatal(err)
	}
	r := c.Ready(context.Background())
	if r.Ready() || r.OK(CheckDatabase) || r.OK(CheckAuditChain) {
		t.Errorf("closed database: %+v", r)
	}
}

func TestReady_ShapeIsConstant(t *testing.T) {
	c, _, _ := newChecker(t)
	ok, _ := json.Marshal(c.Ready(context.Background()))
	c2, _, _ := newChecker(t)
	c2.Database = func(context.Context) error { return errors.New("x") }
	bad, _ := json.Marshal(c2.Ready(context.Background()))
	if string(ok) != `{"status":"ok","checks":{"audit_chain":"ok","database":"ok","kek":"ok","loops":"ok"}}` {
		t.Errorf("ok body: %s", ok)
	}
	if string(bad) != `{"status":"unavailable","checks":{"audit_chain":"ok","database":"fail","kek":"ok","loops":"ok"}}` {
		t.Errorf("failing body: %s", bad)
	}
}

// The unauthenticated probe is bounded: a result is reused for a short time.
func TestReady_CachesBriefly(t *testing.T) {
	c, _, now := newChecker(t)
	calls := 0
	c.Database = func(context.Context) error { calls++; return nil }
	c.Ready(context.Background())
	c.Ready(context.Background())
	if calls != 1 {
		t.Errorf("probe ran %d times within the TTL", calls)
	}
	*now = now.Add(3 * time.Second)
	c.Ready(context.Background())
	if calls != 2 {
		t.Errorf("probe ran %d times after the TTL", calls)
	}
}

func TestSummary_NoSecretsAndShape(t *testing.T) {
	c, _, now := newChecker(t)
	s := c.Summary(context.Background())
	if s.Status != "ok" || len(s.Checks) != 4 || len(s.Loops) != 1 || !s.Loops[0].Healthy || s.Loops[0].LastSuccessAt == nil {
		t.Fatalf("summary: %+v", s)
	}
	b, _ := json.Marshal(s)
	for _, bad := range []string{"password", "secret", "token", "kek\":\"", "tenant"} {
		if strings.Contains(strings.ToLower(string(b)), bad) {
			t.Errorf("summary mentions %q: %s", bad, b)
		}
	}
	c.Loops.Register("late", time.Second, true)
	*now = now.Add(time.Hour)
	if s := c.Summary(context.Background()); s.Status != "degraded" {
		t.Errorf("lagging loops must degrade the summary: %+v", s)
	}
}
