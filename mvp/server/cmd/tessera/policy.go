package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/cedarx"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
)

// Exit codes of `tessera policy`.
const (
	exitPolicyFindings = 1 // validate found a finding, or a test failed
	exitPolicyUsage    = 2 // bad arguments, or the directory could not be read
)

const policyUsage = `usage:
  tessera policy validate [-dir path] [-attrs a,b]   check the policy repository offline
  tessera policy test     [-dir path] [-attrs a,b]   validate, then run tests/*.yaml
  tessera policy schema   [-attrs a,b]               print the generated Cedar schema
exit status: 0 ok, 1 findings or failing tests, 2 usage or unreadable directory`

// policyCmd is the offline half of access as code (AC-2, design
// access-as-code-repo.md): it needs no tenant, credential, network or database.
// Diff and apply are API calls (AC-3 on).
func policyCmd(args []string, stdout, stderr io.Writer) error {
	usage := func() error { return &exitError{exitPolicyUsage, policyUsage} }
	if len(args) == 0 {
		return usage()
	}
	sub := args[0]
	if sub != "validate" && sub != "test" && sub != "schema" {
		return usage()
	}
	fset := flag.NewFlagSet("tessera policy "+sub, flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the checked-out policy repository")
	attrs := fset.String("attrs", "", "comma-separated identity attribute names for the generated schema (when the repository has no schema file)")
	if err := fset.Parse(args[1:]); err != nil {
		return &exitError{exitPolicyUsage, "policy " + sub + ": bad arguments"}
	}
	if fset.NArg() > 0 {
		return usage()
	}
	var names []string
	for _, a := range strings.Split(*attrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			names = append(names, a)
		}
	}
	if sub == "schema" {
		s, err := cedarx.Generate(cedarx.Facts{IdentityAttrs: names})
		if err != nil {
			return &exitError{exitPolicyUsage, "policy schema: " + err.Error()}
		}
		_, err = stdout.Write(s.Text())
		return err
	}
	files, err := readBundleDir(*dir)
	if err != nil {
		return &exitError{exitPolicyUsage, "policy " + sub + ": " + err.Error()}
	}
	b, diags := policybundle.Load(files, names)
	for _, d := range diags {
		fmt.Fprintln(stdout, d)
	}
	if len(diags) > 0 {
		return &exitError{exitPolicyFindings, fmt.Sprintf("policy %s: %d finding(s)", sub, len(diags))}
	}
	if sub == "validate" {
		fmt.Fprintf(stdout, "%d roles, %d jit eligibilities, %d sod rulesets, %d birthright, %d agent scope, %d invariant files, %d test files\npolicy bundle OK\n",
			len(b.Roles), len(b.Jit), len(b.Sod), len(b.Birthright), len(b.Agents)+len(b.AgentScopes), len(b.Invariants), len(b.Tests))
		return nil
	}
	failed := 0
	results := b.RunTests()
	for _, r := range results {
		fmt.Fprintln(stdout, r)
		if !r.OK() {
			failed++
		}
	}
	if failed > 0 {
		return &exitError{exitPolicyFindings, fmt.Sprintf("policy test: %d of %d failed", failed, len(results))}
	}
	fmt.Fprintf(stdout, "%d tests passed\n", len(results))
	return nil
}

// readBundleDir reads the files a bundle consists of: tessera.yaml, the schema
// file and the files under the bundle folders. It follows no symbolic link, skips
// other folders (such as .git and groups/), and enforces the bundle limits before
// reading a file.
func readBundleDir(dir string) (policybundle.Files, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() { // #nosec G703 -- the operator's own policy repo on the operator's host; no API route calls this command
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	want := map[string]bool{policybundle.ConfigFile: true, policybundle.SchemaFile: true}
	folders := map[string]bool{"schema": true}
	for _, d := range []string{policybundle.DirRoles, policybundle.DirBirthright, policybundle.DirJit, policybundle.DirSod,
		policybundle.DirAgents, policybundle.DirInvariants, policybundle.DirTests} {
		folders[d] = true
	}
	files := policybundle.Files{}
	total := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { // #nosec G703 -- operator-chosen -dir; the walk follows no symbolic link and reads only bundle files
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		top, _, nested := strings.Cut(rel, "/")
		if d.Type()&fs.ModeSymlink != 0 {
			if want[rel] || folders[top] {
				return fmt.Errorf("%s is a symbolic link; the bundle follows none", rel)
			}
			return nil
		}
		if d.IsDir() {
			if !folders[top] {
				return fs.SkipDir
			}
			return nil
		}
		if !want[rel] && !(nested && folders[top] && top != "schema") {
			return nil
		}
		if len(files) >= policybundle.MaxFiles {
			return fmt.Errorf("more than %d files in the bundle", policybundle.MaxFiles)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		if info.Size() > cedarx.MaxFileBytes {
			return fmt.Errorf("%s is %d bytes; a file is at most %d", rel, info.Size(), cedarx.MaxFileBytes)
		}
		if total += int(info.Size()); total > policybundle.MaxBytes {
			return fmt.Errorf("the bundle is more than %d bytes", policybundle.MaxBytes)
		}
		data, err := os.ReadFile(p) // #nosec G304 G122 -- a regular file under the directory the operator named
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no policy files found; run it in the policy repository (tessera.yaml at its root) or pass -dir")
	}
	return files, nil
}
