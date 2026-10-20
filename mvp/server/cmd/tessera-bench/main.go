// Command tessera-bench measures Tessera against the performance targets of its
// designs.
//
//	tessera-bench groups [-percent 10] [-seed 1] [-samples 500] [-loader 50000]
//	                     [-db FILE] [-json FILE] [-md FILE] [-enforce]
//
// groups builds the synthetic "large university" tenant of the groups design
// (docs/design/groups-grouper-parity.md section 6.7, GR-17) at -percent of its
// size in a scratch SQLite database (or -db), runs every target of the table
// against it and prints the results. -enforce makes a missed target exit 1
// (the nightly gate); without it the numbers are only reported. The design's
// SQLite numbers apply to tenants up to 10%; 100% is the Postgres target, and the
// generator has only been run on SQLite, so a Postgres -db is refused.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/benchgen"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "groups" {
		fmt.Fprintln(os.Stderr, "usage: tessera-bench groups [flags]")
		os.Exit(2)
	}
	if err := groups(os.Args[2:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tessera-bench:", err)
		os.Exit(1)
	}
}

func groups(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("groups", flag.ContinueOnError)
	fs.SetOutput(stderr)
	percent := fs.Float64("percent", 10, "percent of the reference tenant (100 is 150,000 groups and 600,000 identities)")
	seed := fs.Int64("seed", 1, "seed of the tenant's shape")
	samples := fs.Int("samples", 500, "latency samples per operation")
	loader := fs.Int("loader", 50000, "membership changes in the loader run")
	dbPath := fs.String("db", "", "SQLite file to build the tenant in (default: a scratch file, removed afterwards)")
	jsonOut := fs.String("json", "", "write the results as JSON to this file")
	mdOut := fs.String("md", "", "write the results as a Markdown table to this file")
	enforce := fs.Bool("enforce", false, "exit 1 when a target is missed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if store.IsPostgresDSN(*dbPath) {
		return fmt.Errorf("the groups scale gate has only been run on SQLite (docs/design/groups-scale-gate.md): use a SQLite file")
	}
	if *percent <= 0 || *percent > 100 {
		return fmt.Errorf("-percent is above 0 and at most 100")
	}
	ctx := context.Background()
	path := *dbPath
	if path == "" {
		dir, err := os.MkdirTemp("", "tessera-bench-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path = filepath.Join(dir, "bench.db")
	}
	db, err := store.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	id := tenancy.MustParse("00000000-0000-4000-8000-0000000000b7")
	if err := benchgen.CreateTenant(ctx, db, id, "bench"); err != nil {
		return err
	}
	begin := time.Now()
	logf := func(format string, a ...any) {
		fmt.Fprintf(stderr, "%s  %s\n", time.Since(begin).Round(time.Second), fmt.Sprintf(format, a...))
	}
	spec := benchgen.Spec{Percent: *percent, Seed: *seed, Samples: *samples, Loader: *loader, DBPath: path, Log: logf}
	t, err := benchgen.Generate(ctx, db, id, spec)
	if err != nil {
		return err
	}
	rep, err := benchgen.Measure(ctx, t)
	if err != nil {
		return err
	}
	if err := rep.Markdown(stdout); err != nil {
		return err
	}
	for path, write := range map[string]func(io.Writer) error{*jsonOut: rep.JSON, *mdOut: rep.Markdown} {
		if path == "" {
			continue
		}
		if err := writeFile(path, write); err != nil {
			return err
		}
	}
	if failed := rep.Failed(); len(failed) > 0 && *enforce {
		return fmt.Errorf("%d targets missed", len(failed))
	}
	return nil
}

func writeFile(path string, write func(io.Writer) error) (err error) {
	f, err := os.Create(path) // #nosec G304 -- the operator's own output path
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return write(f)
}
