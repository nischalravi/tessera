package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const genRLSUsage = `usage: tessera admin gen-rls [-out path] [-check]

Renders the row-level-security file (design §14.3) from the Postgres schema.
Without -out it prints to stdout. With -check it compares the rendered text
with the embedded internal/store/schema/postgres/rls.sql and fails if they
differ (run it after changing a Postgres migration, then regenerate with
-out internal/store/schema/postgres/rls.sql). It needs no database.`

// genRLS is `tessera admin gen-rls`: it renders store.GenerateRLS to stdout or
// a file, or checks the embedded rls.sql is current.
func genRLS(args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("tessera admin gen-rls", flag.ContinueOnError)
	fset.SetOutput(stderr)
	out := fset.String("out", "", "write the file here instead of stdout")
	check := fset.Bool("check", false, "fail if the embedded rls.sql is out of date")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 {
		return errors.New(genRLSUsage)
	}
	want, err := store.GenerateRLS()
	if err != nil {
		return fmt.Errorf("gen-rls: %w", err)
	}
	switch {
	case *check:
		have, err := store.PostgresRLSFile()
		if err != nil {
			return fmt.Errorf("gen-rls: %w", err)
		}
		if !bytes.Equal(have, want) {
			return errors.New("gen-rls: internal/store/schema/postgres/rls.sql is out of date; regenerate it with `tessera admin gen-rls -out internal/store/schema/postgres/rls.sql`")
		}
		fmt.Fprintln(stdout, "rls.sql is up to date")
	case *out != "":
		if err := os.WriteFile(*out, want, 0o600); err != nil {
			return fmt.Errorf("gen-rls: %w", err)
		}
		fmt.Fprintf(stdout, "wrote %s (%d bytes)\n", *out, len(want))
	default:
		_, err = stdout.Write(want)
		return err
	}
	return nil
}
