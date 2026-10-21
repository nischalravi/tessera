package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func oauthFakeConfig(t *testing.T, url string) *config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"TESSERA_ENV": "dev", "TESSERA_DEV_OAUTH_FAKE_URL": url}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The dev seed points the four provider connections at the served fakes, and a
// sync then finds apps and grants, among them a high-risk app.
func TestDevOAuthFakesSeedAndSync(t *testing.T) {
	addr := freePort(t)
	cfg := oauthFakeConfig(t, "http://"+addr)
	stop, err := startOAuthFakes(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	f := storetest.TwoTenants(t)
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return storetest.Now }
	if err := seedOAuthFakeDemo(context.Background(), f.DB, cfg, sealer, f.A.ID, now); err != nil {
		t.Fatal(err)
	}
	// the seeded connections must also render in the Connections list (GET /api/connections)
	reg, err := template.Default()
	if err != nil {
		t.Fatal(err)
	}
	rs := readiness.NewService(reg, "dev")
	err = f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		conns, err := tx.Connections()
		if err != nil || len(conns) < len(oauthapps.Providers) {
			t.Errorf("connections: %d, %v", len(conns), err)
		}
		for _, c := range conns {
			if _, _, err := rs.View(tx, c.ID, storetest.Now); err != nil {
				t.Errorf("view of %s: %v", c.Name, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := &oauthapps.Service{Containment: &containment.Service{HTTP: hc, Sealer: sealer, Clock: now}, Clock: now}
	rep, err := svc.Sync(context.Background(), f.DB, f.A.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	apps, grants := 0, 0
	for _, p := range rep.Providers {
		if p.Status != oauthapps.SyncOK {
			t.Errorf("%s: %s %s", p.Provider, p.Status, p.Error)
		}
		apps += p.Apps
		grants += p.Grants
	}
	if apps < 6 || grants < 8 {
		t.Errorf("synced %d apps and %d grants", apps, grants)
	}
}

func TestDevOAuthFakeURLMustBeLoopback(t *testing.T) {
	for _, u := range []string{"https://127.0.0.1:9", "http://example.com:9", "http://127.0.0.1", "http://127.0.0.1:9/x"} {
		if _, err := devOAuthListenAddr(oauthFakeConfig(t, u)); err == nil || !strings.Contains(err.Error(), "TESSERA_DEV_OAUTH_FAKE_URL") {
			t.Errorf("%s accepted: %v", u, err)
		}
	}
}
