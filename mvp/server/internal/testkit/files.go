package testkit

import (
	"io"
	"os"
	"testing"
)

func makeTempDir() (string, error) { return os.MkdirTemp("", "tessera-testkit-") }

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- path created by this package
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- test temp dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Main runs the tests and removes the shared demo database afterwards. Use
// it from TestMain in packages that call Demo. It sets TESSERA_ENV=test
// (unless the environment already names one), the only environment in which
// the test-only session helper internal/auth/authtest runs.
func Main(m *testing.M) {
	if os.Getenv("TESSERA_ENV") == "" {
		_ = os.Setenv("TESSERA_ENV", "test")
	}
	code := m.Run()
	if demoDir != "" {
		_ = os.RemoveAll(demoDir)
	}
	os.Exit(code)
}
