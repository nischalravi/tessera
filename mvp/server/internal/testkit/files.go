package testkit

import (
	"os"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func makeTempDir() (string, error) { return os.MkdirTemp("", "tessera-testkit-") }

// Main runs the tests and removes the shared demo database afterwards. Use
// it from TestMain in packages that call Demo. It sets TESSERA_ENV=test, the
// only environment in which the test-only session helper
// internal/auth/authtest runs (a test binary is a test environment, whatever
// the developer's shell exports).
func Main(m *testing.M) {
	_ = os.Setenv("TESSERA_ENV", "test")
	code := m.Run()
	if demoDir != "" {
		_ = os.RemoveAll(demoDir)
	}
	store.DropSharedTargets()
	os.Exit(code)
}
