package main

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updatePolicyGolden = flag.Bool("update-policy-golden", false, "rewrite cmd/tessera/testdata/policy/*.golden")

const goodRepo = "../../internal/policybundle/testdata/good"

// repoCopy copies the good repository into a temp directory and applies edits
// (path -> content; "\x00" deletes).
func repoCopy(t *testing.T, edits map[string]string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(goodRepo, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(goodRepo, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, c := range edits {
		p := filepath.Join(dst, filepath.FromSlash(rel))
		if c == "\x00" {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestPolicyCLI(t *testing.T) {
	badInvariant := "@id(\"x\")\nforbid (principal, action == Tessera::Action::\"reach\", resource) when { principal.nope == 1 };\n"
	failingTest := strings.Replace(mustRead(t, goodRepo+"/tests/birthright.yaml"), "expect: deny", "expect: allow", 1)
	cases := []struct {
		name   string
		args   func(dir string) []string
		edits  map[string]string
		code   int // exit status
		golden string
	}{
		{"validate ok", func(d string) []string { return []string{"policy", "validate", "-dir", d} }, nil, 0, "validate_ok"},
		{"test ok", func(d string) []string { return []string{"policy", "test", "-dir", d} }, nil, 0, "test_ok"},
		{"validate findings", func(d string) []string { return []string{"policy", "validate", "-dir", d} },
			map[string]string{"invariants/bad.cedar": badInvariant, "roles/payments-analyst.yaml": "schema: tessera.role/v1\nkey: payments-analyst\nname: P\nrisk: extreme\n"}, 1, "validate_findings"},
		{"test failing", func(d string) []string { return []string{"policy", "test", "-dir", d} },
			map[string]string{"tests/birthright.yaml": failingTest}, 1, "test_failing"},
		{"test with findings runs nothing", func(d string) []string { return []string{"policy", "test", "-dir", d} },
			map[string]string{"invariants/bad.cedar": badInvariant}, 1, "test_findings"},
		{"schema", func(string) []string { return []string{"policy", "schema", "-attrs", "cost_center"} }, nil, 0, "schema"},
		{"no subcommand", func(string) []string { return []string{"policy"} }, nil, 2, ""},
		{"unknown subcommand", func(string) []string { return []string{"policy", "apply"} }, nil, 2, ""},
		{"extra argument", func(d string) []string { return []string{"policy", "validate", "-dir", d, "more"} }, nil, 2, ""},
		{"bad flag", func(string) []string { return []string{"policy", "validate", "-nope"} }, nil, 2, ""},
		{"missing directory", func(d string) []string { return []string{"policy", "validate", "-dir", filepath.Join(d, "none")} }, nil, 2, ""},
		{"not a repository", func(string) []string { return []string{"policy", "validate", "-dir", t.TempDir()} }, nil, 2, ""},
		{"bad attrs", func(string) []string { return []string{"policy", "schema", "-attrs", "not valid"} }, nil, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := repoCopy(t, c.edits)
			var out, errb bytes.Buffer
			err := run(t.Context(), c.args(dir), &out, &errb)
			got := 0
			if err != nil {
				var ee *exitError
				if !errors.As(err, &ee) {
					t.Fatalf("error %v is not an exitError", err)
				}
				got = ee.code
			}
			if got != c.code {
				t.Fatalf("exit %d, want %d (%v)\n%s", got, c.code, err, out.String())
			}
			if c.golden == "" {
				return
			}
			text := out.String()
			if err != nil {
				text += "error: " + err.Error() + "\n"
			}
			text = strings.ReplaceAll(text, dir, "<dir>")
			path := filepath.Join("testdata", "policy", c.golden+".golden")
			if *updatePolicyGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if want := mustRead(t, path); text != want {
				t.Errorf("output differs from %s (rerun with -update-policy-golden):\n--- got\n%s--- want\n%s", path, text, want)
			}
		})
	}
}

func TestPolicyCLIRefusesSymlinksAndOversize(t *testing.T) {
	dir := repoCopy(t, nil)
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "roles", "link.yaml")); err != nil {
		t.Skip("no symlinks:", err)
	}
	var out, errb bytes.Buffer
	err := run(t.Context(), []string{"policy", "validate", "-dir", dir}, &out, &errb)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %v", err)
	}
	dir = repoCopy(t, map[string]string{"invariants/huge.cedar": strings.Repeat(" ", 300<<10)})
	err = run(t.Context(), []string{"policy", "validate", "-dir", dir}, &out, &errb)
	if !errors.As(err, &ee) || ee.code != 2 || !strings.Contains(err.Error(), "at most") {
		t.Errorf("oversize: %v", err)
	}
	// folders outside the bundle (a .git directory, the groups/ policy groups) are not read
	dir = repoCopy(t, map[string]string{"groups/app/x.cedar": "not cedar at all (", ".git/config": "x", "README.md": "x"})
	if err := run(t.Context(), []string{"policy", "validate", "-dir", dir}, &out, &errb); err != nil {
		t.Errorf("unrelated files read: %v", err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
