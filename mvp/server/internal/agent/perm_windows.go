//go:build windows

package agent

import (
	"fmt"
	"os"
)

func isWindows() bool { return true }

// requirePrivate on Windows only checks that the path exists: POSIX mode bits
// mean nothing there. Access to the credential directory is the NTFS ACL
// (grant it to the agent's service account only), and every value is wrapped
// with DPAPI as well (store_windows.go).
func requirePrivate(path string, _ bool) error {
	_, err := os.Stat(path)
	return err
}

// requireAdminOwned on Windows checks that the file exists and is regular;
// the install guide has the administrator restrict its ACL.
func requireAdminOwned(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("agent: %s is not a regular file", path)
	}
	return nil
}
