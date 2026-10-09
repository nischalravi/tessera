package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/templates"
)

// readinessCmd runs `tessera readiness lint [-dir path]`: it lints the
// embedded checklist templates (or the YAML files in -dir, for template
// authors) and prints the per-template item counts.
func readinessCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "lint" {
		return errors.New("usage: tessera readiness lint [-dir path]")
	}
	fset := flag.NewFlagSet("tessera readiness lint", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", "", "lint the templates in this directory instead of the built-in ones")
	if err := fset.Parse(args[1:]); err != nil {
		return err
	}
	var fsys fs.FS = templates.FS
	if *dir != "" {
		fsys = os.DirFS(*dir)
	}
	probs, err := template.LintFS(fsys)
	if err != nil {
		return err
	}
	for _, p := range probs {
		fmt.Fprintln(stdout, p)
	}
	if len(probs) > 0 {
		return fmt.Errorf("%d template problem(s)", len(probs))
	}
	reg, err := template.Load(fsys)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%-9s %-8s %5s %8s %11s %8s\n", "template", "version", "items", "required", "recommended", "optional")
	for _, id := range reg.IDs() {
		r, _ := reg.Get(id)
		c := r.Count()
		fmt.Fprintf(stdout, "%-9s %-8s %5d %8d %11d %8d\n", id, r.Version, c.Items, c.Required, c.Recommended, c.Optional)
	}
	fmt.Fprintln(stdout, "templates OK")
	return nil
}
