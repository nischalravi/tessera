package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
)

const archiveUsage = `usage:
  tessera archive seal-token [-db path]   read the archive object store's bearer token from standard input and print it
                                          sealed under the KEK, for TESSERA_ARCHIVE_TOKEN_SEALED (never read in clear)`

// archiveCmd runs `tessera archive seal-token`.
func archiveCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "seal-token" {
		fmt.Fprintln(stderr, archiveUsage)
		return errors.New("archive: missing or unknown subcommand")
	}
	fs := flag.NewFlagSet("tessera archive seal-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path (locates the dev KEK)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	sealer, err := loadSealer(context.Background(), cfg, config.DevKEKPath(*db))
	if err != nil {
		return err
	}
	tok, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	out, err := archive.SealToken(sealer, strings.TrimSpace(tok))
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, out)
	return nil
}
