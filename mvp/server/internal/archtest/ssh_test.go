package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// sshDir is the only package (module-relative) allowed to open SSH sessions or request subsystems,
// and to import the SSH library: the Unix connector sends fixed commands only (issue #558) and the
// SFTP file drop reaches the host through unixssh.Connector.SFTP, never through a raw client.
const sshDir = "internal/connectors/unixssh"

const sshPath = "golang.org/x/crypto/ssh"

// sshMethods are the calls that run something on a host: a method named like one is banned
// outside sshDir even when the SSH library is reached through a helper.
var sshMethods = map[string]bool{"NewSession": true, "RequestSubsystem": true}

// checkSSHUse reports, for a non-test file outside sshDir, an import of the SSH library and any
// call of NewSession or RequestSubsystem.
func checkSSHUse(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == sshPath {
			out = append(out, fset.Position(imp.Pos()).String()+": imports "+sshPath+" outside "+sshDir+" (use unixssh.Connector.SFTP)")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sshMethods[sel.Sel.Name] {
			out = append(out, fset.Position(sel.Pos()).String()+": "+sel.Sel.Name+" outside "+sshDir+" (only the fixed commands of unixssh may run on a host)")
		}
		return true
	})
	return out
}

// TestSSHSessionsOnlyInUnixSSH: no non-test file outside internal/connectors/unixssh imports the SSH
// library or calls NewSession or RequestSubsystem, so a command cannot be run on a host except by
// unixssh's fixed commands.
func TestSSHSessionsOnlyInUnixSSH(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := mustRel(t, root, path)
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.ToSlash(filepath.Dir(rel)) == sshDir {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, v := range checkSSHUse(fset, f) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("scanned %d files; the walk is not covering the module", files)
	}
}

// TestSSHRuleCatchesViolations is the positive control.
func TestSSHRuleCatchesViolations(t *testing.T) {
	src := `package bad

import "golang.org/x/crypto/ssh"

func f(cl *ssh.Client) {
	sn, _ := cl.NewSession()
	_ = sn.Run("id")
	_ = sn.RequestSubsystem("sftp")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "bad.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkSSHUse(fset, f); len(got) != 3 {
		t.Errorf("%d violations, want 3 (the import, NewSession, RequestSubsystem):\n%s", len(got), strings.Join(got, "\n"))
	}
}
