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

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
)

// stdin is where `tessera notify seal-password` reads the password (tests replace it).
var stdin io.Reader = os.Stdin

const notifyUsage = `usage:
  tessera notify seal-password [-db path]   read an SMTP password from standard input and print it sealed under the KEK,
                                            for TESSERA_SMTP_PASSWORD_SEALED (the password is never read from the environment)`

// notifyCmd runs `tessera notify seal-password`: it seals the SMTP password
// under the same KEK as every other secret, so the settings never hold it in
// clear.
func notifyCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "seal-password" {
		fmt.Fprintln(stderr, notifyUsage)
		return errors.New("notify: missing or unknown subcommand")
	}
	fs := flag.NewFlagSet("tessera notify seal-password", flag.ContinueOnError)
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
	pw, err := bufio.NewReader(io.LimitReader(stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	out, err := notify.SealPassword(sealer, strings.TrimRight(pw, "\r\n"))
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, out)
	return nil
}
