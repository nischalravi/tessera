//go:build unix

package config

import (
	"fmt"
	"os"
	"syscall"
)

// checkKEKOwner accepts a KEK file owned by this process's user or by root.
func checkKEKOwner(fi os.FileInfo, path string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := int(st.Uid); uid != os.Geteuid() && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not by this process (uid %d) or root", path, uid, os.Geteuid())
	}
	return nil
}
