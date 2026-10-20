package api

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// A server built the way cmd/tessera builds it (a groups engine, no device
// signal source) must still default the signal source; a nil source panicked
// every sign-in that evaluated conditional access.
func TestNewDefaultsDeviceSignals(t *testing.T) {
	f := storetest.TwoTenants(t)
	for name, eng := range map[string]*engine.Engine{"no engine": nil, "with engine": engine.New(0)} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{
				Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
				Connectors: func(now time.Time) ([]connectors.Connector, error) {
					return []connectors.Connector{connectors.Tiny{Now: now}}, nil
				},
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", GroupsEngine: eng,
			})
			if s.signals == nil {
				t.Fatal("device signal source is nil")
			}
		})
	}
}
