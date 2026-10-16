package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/policygroups"
)

// groupsCmd runs `tessera groups policy validate [-dir path]`: it reads the
// policy group files (*.cedar) under the directory (default: the current one) and
// checks them offline against the default schema: the Cedar fragment of design
// §8.2, attribute types and guards, and that no condition is unbounded. It does
// not know the tenant's groups, so it cannot say that a referenced group exists:
// POST /api/groups/policy/validate does. Diff and apply are API calls (see
// docs/design/groups-policy-repo-example.md), because they need a tenant and a
// credential. The exit status is non-zero when there is any finding.
func groupsCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "policy" || args[1] != "validate" {
		return errors.New("usage: tessera groups policy validate [-dir path]")
	}
	fset := flag.NewFlagSet("tessera groups policy validate", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the checked-out policy repository")
	if err := fset.Parse(args[2:]); err != nil {
		return err
	}
	files, err := policygroups.ReadDir(*dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no *.cedar files under %s", *dir)
	}
	schema := policygroups.DefaultSchema()
	fs, diags := policygroups.ParseAll(schema, files)
	if len(diags) == 0 {
		c := policygroups.NewCompiler()
		for _, f := range fs {
			// groups are not resolved offline: every name stands for itself
			if _, ds := c.Compile(f, func(name string) (string, error) { return name, nil }); len(ds) > 0 {
				diags = append(diags, ds...)
			}
		}
	}
	for _, d := range diags {
		fmt.Fprintln(stdout, d)
	}
	if len(diags) > 0 {
		return fmt.Errorf("%d finding(s) in %d file(s)", len(diags), len(files))
	}
	for _, f := range fs {
		fmt.Fprintf(stdout, "%s: group %s, %d policies\n", f.Path, f.Group, len(f.Policies))
	}
	fmt.Fprintln(stdout, "policy files OK")
	return nil
}
