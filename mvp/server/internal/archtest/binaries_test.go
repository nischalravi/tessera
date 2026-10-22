package archtest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// isExecutable says whether the first bytes are those of a compiled executable (ELF, Mach-O, PE).
func isExecutable(head []byte) bool {
	for _, m := range [][]byte{{0x7f, 'E', 'L', 'F'}, {0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}, {'M', 'Z', 0x90, 0x00}} {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// TestNoCommittedExecutables refuses a compiled binary in the repository (#469): it cannot be reviewed
// against the source and bloats every clone. Build output goes to mvp/server/bin/ (ignored).
func TestNoCommittedExecutables(t *testing.T) {
	if !isExecutable([]byte{0x7f, 'E', 'L', 'F', 2}) || isExecutable([]byte("package main")) {
		t.Fatal("the executable check is wrong")
	}
	root := filepath.Join(moduleRoot(t), "..", "..")
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skip("not a git checkout: " + err.Error())
	}
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" {
			continue
		}
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			continue // a tracked file removed in the working tree
		}
		head := make([]byte, 4)
		n, _ := f.Read(head)
		f.Close()
		if isExecutable(head[:n]) {
			t.Errorf("%s is a compiled executable; do not commit binaries (build to mvp/server/bin/)", name)
		}
	}
}
