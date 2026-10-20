//go:build !windows

package agent

import (
	"fmt"
	"os"
	"syscall"
)

func isWindows() bool { return false }

// requirePrivate refuses a path that group or others can access, or that is
// owned by another user: a secret in such a place is not private.
func requirePrivate(path string, dir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	want := "0600"
	if dir {
		want = "0700"
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("agent: %s has permissions %04o; it must be %s (owner only)", path, fi.Mode().Perm(), want)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("agent: %s is not owned by the user running the agent", path)
	}
	return nil
}

// requireAdminOwned refuses a configuration file that group or others can
// write, or that is owned by neither root nor the user running the agent:
// the allowlist in it must be editable only by a local administrator.
func requireAdminOwned(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("agent: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("agent: %s is writable by group or others (mode %04o); only a local administrator may edit it",
			path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("agent: %s is owned by neither root nor the agent's user", path)
	}
	return nil
}
