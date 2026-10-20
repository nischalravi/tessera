package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/nischalravi/tessera/mvp/server/internal/migration"
)

// This offline command intentionally dispatches before config/database setup.
func migrationCmd(args []string, _ io.Writer, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "assess" {
		return errors.New("migration: want assess")
	}
	f := flag.NewFlagSet("tessera migration assess", flag.ContinueOnError)
	f.SetOutput(stderr)
	var o migration.Options
	var file, out string
	var force bool
	f.StringVar(&o.Tenant, "tenant", "", "explicit tenant label (no database lookup)")
	f.StringVar(&o.Product, "product", "", "sailpoint-iiq, sailpoint-isc or saviynt")
	f.StringVar(&o.Instance, "instance", "", "source installation label")
	f.StringVar(&o.Format, "format", "normalized-json", "normalized-json or iiq-xml")
	f.StringVar(&file, "file", "", "local export file")
	f.StringVar(&out, "out", "", "assessment JSON output file (required)")
	f.BoolVar(&force, "force", false, "replace an existing output file; never replace the input")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || file == "" || out == "" {
		return errors.New("migration: --file and --out required; positional arguments refused")
	}
	input, err := os.Open(file) // #nosec G304 G703 -- CLI operator intentionally selects an arbitrary local export; no API route calls this command.
	if err != nil {
		return errors.New("migration: cannot open export file")
	}
	defer input.Close()
	r, err := migration.Assess(o, input)
	if err != nil {
		return err
	}
	info, err := input.Stat()
	if err != nil {
		return errors.New("migration: cannot inspect input")
	}
	// Do not overwrite an input through its original name, a symlink or a hard
	// link even when --force is given. Output publication replaces a directory
	// entry atomically; it never follows an output symlink to truncate its target.
	existing, err := os.Stat(out) // #nosec G304 G703 -- explicit CLI operator output path; no API exposure.
	if err == nil && os.SameFile(info, existing) {
		return errors.New("migration: output must not replace the input")
	}
	if err != nil && !os.IsNotExist(err) {
		return errors.New("migration: cannot inspect output")
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".tessera-migration-*")
	if err != nil {
		return errors.New("migration: cannot create output")
	}
	defer os.Remove(tmp.Name())
	if err := migration.WriteReport(tmp, r); err != nil {
		_ = tmp.Close()
		return errors.New("migration: cannot write report")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("migration: cannot close report")
	}
	if force {
		err = os.Rename(tmp.Name(), out) // #nosec G703 -- operator-authorized atomic replacement of CLI output.
	} else {
		// Link creation is exclusive even if the destination appeared since Stat.
		err = os.Link(tmp.Name(), out) // #nosec G703 -- explicit CLI output; exclusive publication avoids clobbering files.
	}
	if err != nil {
		return errors.New("migration: cannot publish output (existing files require --force)")
	}
	return nil
}
