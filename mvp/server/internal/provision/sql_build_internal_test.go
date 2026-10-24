package provision

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
)

// The database target builds in every runtime the server and the worker hand it: the
// worker passes connsync.RuntimeFromConfig, the API may carry a "test" environment, and a
// zero Runtime is the production rules. Only dev may turn TLS off.
func TestBuildSQL_Runtimes(t *testing.T) {
	verified := &Settings{SQL: &sqldb.Config{Engine: sqldb.Postgres, Host: "db.example.com", Username: "u", Mode: sqldb.ModeNative}}
	insecure := &Settings{SQL: &sqldb.Config{Engine: sqldb.Postgres, Host: "db.example.com", Username: "u", Mode: sqldb.ModeNative, TLS: sqldb.TLSDisable}}
	tests := []struct {
		name string
		rt   connsync.Runtime
		s    *Settings
		ok   bool
	}{
		{"zero runtime, verified TLS", connsync.Runtime{}, verified, true},
		{"test environment, verified TLS", connsync.Runtime{Env: "test"}, verified, true},
		{"prod, verified TLS", connsync.Runtime{Env: "prod"}, verified, true},
		{"dev, verified TLS", connsync.Runtime{Env: "dev", AllowLoopback: true}, verified, true},
		{"dev may disable TLS", connsync.Runtime{Env: "dev", AllowLoopback: true}, insecure, true},
		{"test may not disable TLS", connsync.Runtime{Env: "test"}, insecure, false},
		{"prod may not disable TLS", connsync.Runtime{Env: "prod"}, insecure, false},
		{"zero runtime may not disable TLS", connsync.Runtime{}, insecure, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{Runtime: tt.rt}
			c, err := e.buildSQL("pw", *tt.s)
			if (err == nil) != tt.ok || (err == nil && c == nil) {
				t.Fatalf("err = %v, connector %v; want ok=%v", err, c, tt.ok)
			}
		})
	}
	if _, err := (&Engine{}).buildSQL("pw", Settings{}); err == nil {
		t.Error("missing sql settings were accepted")
	}
}
