// Package sftpdrop is the read connector for flat-file feeds dropped on an SFTP server (issue #563):
// legacy systems that can only export files write an accounts CSV (and optionally an entitlements
// CSV) to a directory, and each sync reads them with the same column mapping, validation and
// normalisation as the flat-file apps pipeline (internal/flatfile). A file with any invalid row
// fails the sync as a whole and nothing is ingested, as an invalid upload changes nothing.
//
// Safety rules, each tested:
//
//   - The connection is opened by the Unix/SSH connector's code (unixssh.Connector.Client): the
//     socket goes through safehttp's address policy, the host key is pinned (never trusted on first
//     use) and sign-in is by key. Only the "sftp" subsystem is used: no command is run.
//   - Only the two configured file names are read, from the configured absolute directory. A name
//     is a plain file name (no separator, no ".."); the directory is compared with its real path on
//     the server so a symbolic link in the directory path is refused, and each file must be a regular
//     file, not a link. lstat, a real-path check after open and an fstat whose size, time and mode
//     must match the lstat narrow a link-swap race but cannot close it (SFTP v3 has no O_NOFOLLOW):
//     a read-only, chrooted login is the real control.
//   - A file larger than flatfile.MaxBytes is refused, and reading stops one byte past the limit
//     whatever the server claims. Row and column counts are capped by flatfile.Parse.
//   - Errors have fixed text: no path, file content, server message or cell value is echoed.
//
// The credential is the connection's sealed private key (or a vault reference, as for every
// governed connection). The connector is read-only: nothing is written, moved or deleted on the server.
package sftpdrop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "sftp"

// ReadTimeout bounds one read of the drop (connect, list and both files).
const ReadTimeout = 90 * time.Second

var (
	// ErrDirectory: the configured directory is not a real directory on the host (missing, a link, or reached through one).
	ErrDirectory = errors.New("sftpdrop: the directory is missing or is not a real directory on the host")
	// ErrFile: a configured file is missing, is not a regular file, or is a link.
	ErrFile = errors.New("sftpdrop: a configured file is missing or is not a regular file")
	// ErrTooLarge: a file is over the size limit.
	ErrTooLarge = errors.New("sftpdrop: a file is over the size limit")
	// ErrInvalid: a file did not pass the flat-file validation (a bad row, header or column).
	ErrInvalid = errors.New("sftpdrop: a file is not a valid flat file for the column mapping")
	// ErrProtocol: the SFTP session failed.
	ErrProtocol = errors.New("sftpdrop: the SFTP session failed")
	// ErrEmpty: the accounts file has a header but no rows. A stuck or failed
	// export is refused rather than read as "every account was removed".
	ErrEmpty = errors.New("sftpdrop: the accounts file has no rows")

	dirRE  = regexp.MustCompile(`^/[A-Za-z0-9._~@+/-]{0,500}$`)
	fileRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)
)

// Config configures one drop.
type Config struct {
	SSH              unixssh.Config // host, port, login, pinned host key and key
	Directory        string         // absolute, as the SFTP server reports it
	AccountsFile     string         // the accounts file name in Directory
	EntitlementsFile string         // optional
	Mapping          flatfile.Mapping
}

// ValidateDirectory checks the directory setting: absolute, no "." or ".." element, no double slash.
func ValidateDirectory(d string) error {
	if !dirRE.MatchString(d) || d != path.Clean(d) {
		return errors.New("sftpdrop: the directory must be an absolute path without . or .. elements")
	}
	return nil
}

// ValidateFileName checks a file setting: a plain file name.
func ValidateFileName(n string) error {
	if !fileRE.MatchString(n) || strings.Contains(n, "..") {
		return errors.New("sftpdrop: a file must be a plain file name (letters, digits, . _ -)")
	}
	return nil
}

// Connector implements connectors.Connector.
type Connector struct {
	cfg Config
	ssh *unixssh.Connector
}

// New builds a connector. dial replaces the guarded dialer (tests only: nil in production).
func New(cfg Config, rt connsync.Runtime, dial safehttp.DialFunc) (*Connector, error) {
	if err := ValidateDirectory(cfg.Directory); err != nil {
		return nil, err
	}
	if err := ValidateFileName(cfg.AccountsFile); err != nil {
		return nil, err
	}
	if cfg.EntitlementsFile != "" {
		if err := ValidateFileName(cfg.EntitlementsFile); err != nil {
			return nil, err
		}
		if cfg.EntitlementsFile == cfg.AccountsFile {
			return nil, errors.New("sftpdrop: the accounts and entitlements files must differ")
		}
		if cfg.Mapping.Entitlements == nil {
			return nil, errors.New("sftpdrop: an entitlements file needs the entitlement column settings")
		}
	} else {
		cfg.Mapping.Entitlements = nil
	}
	cfg.Mapping.System = System
	if cfg.Mapping.Name == "" {
		cfg.Mapping.Name = "SFTP file drop"
	}
	if err := cfg.Mapping.Validate(); err != nil {
		return nil, err // a FieldError names the setting, never a value of a file
	}
	s, err := unixssh.New(cfg.SSH, rt, dial)
	if err != nil {
		return nil, err
	}
	return &Connector{cfg: cfg, ssh: s}, nil
}

func (c *Connector) System() string      { return System }
func (c *Connector) DisplayName() string { return "SFTP file drop" }
func (c *Connector) TypeName() string    { return "SFTPDropConnector" }

// Identity is the SSH login of the connection.
func (c *Connector) Identity() string { return c.cfg.SSH.Username }

// StreamEvents: a file drop reports no usage.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// Snapshot is what one read found: the validated records of each file.
type Snapshot struct {
	Accounts     []flatfile.Record
	Entitlements []flatfile.Record
}

// Read connects, reads the configured files and validates them with the mapping.
func (c *Connector) Read(ctx context.Context) (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	cl, err := c.ssh.Client(ctx)
	if err != nil {
		return nil, err // unixssh's errors are fixed text and say what failed (host key, key, dial)
	}
	defer cl.Close()
	stop := context.AfterFunc(ctx, func() { _ = cl.Close() })
	defer stop()
	sc, err := sftp.NewClient(cl)
	if err != nil {
		return nil, ErrProtocol
	}
	defer sc.Close()

	dir, err := sc.RealPath(c.cfg.Directory)
	if err != nil || dir != c.cfg.Directory {
		return nil, ErrDirectory
	}
	if st, err := sc.Lstat(dir); err != nil || !st.IsDir() {
		return nil, ErrDirectory
	}
	snap := &Snapshot{}
	raw, err := readFile(sc, dir, c.cfg.AccountsFile)
	if err != nil {
		return nil, ctxOr(ctx, err)
	}
	tbl, errs := flatfile.Parse(raw)
	if len(errs) > 0 {
		return nil, ErrInvalid
	}
	if snap.Accounts, errs = c.cfg.Mapping.AccountRecords(tbl); len(errs) > 0 {
		return nil, ErrInvalid
	}
	if len(snap.Accounts) == 0 {
		return nil, ErrEmpty
	}
	if c.cfg.EntitlementsFile != "" {
		if raw, err = readFile(sc, dir, c.cfg.EntitlementsFile); err != nil {
			return nil, ctxOr(ctx, err)
		}
		if tbl, errs = flatfile.Parse(raw); len(errs) > 0 {
			return nil, ErrInvalid
		}
		known := make(map[string]bool, len(snap.Accounts))
		for _, a := range snap.Accounts {
			known[a.Key] = true
		}
		if snap.Entitlements, errs = c.cfg.Mapping.EntitlementRecords(tbl, known); len(errs) > 0 {
			return nil, ErrInvalid
		}
	}
	return snap, nil
}

// ctxOr reports the context's error when the read was cut short by it.
func ctxOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("sftpdrop: the read was cancelled or timed out: %w", ctx.Err())
	}
	return err
}

// readFile reads one file of the (already verified, real) directory. name is a validated plain
// name, so the joined path cannot leave dir; the file is refused unless it is a regular file that
// is not a link, by lstat before and by fstat on the open handle, and at most flatfile.MaxBytes.
func readFile(sc *sftp.Client, dir, name string) ([]byte, error) {
	full := path.Join(dir, name)
	st, err := sc.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return nil, ErrFile
	}
	if st.Size() > flatfile.MaxBytes {
		return nil, ErrTooLarge
	}
	f, err := sc.Open(full)
	if err != nil {
		return nil, ErrFile
	}
	defer f.Close()
	if real, err := sc.RealPath(full); err != nil || real != full { // swapped for a link after the lstat
		return nil, ErrFile
	}
	// fstat follows nothing, so it cannot see a link; a file that differs from the one lstat
	// saw (a swap and swap back) is refused
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() || fst.Mode() != st.Mode() ||
		fst.Size() != st.Size() || !fst.ModTime().Equal(st.ModTime()) {
		return nil, ErrFile
	}
	// the server's size is not trusted: stop one byte over the limit
	raw, err := io.ReadAll(io.LimitReader(f, flatfile.MaxBytes+1))
	if err != nil {
		return nil, ErrProtocol
	}
	if len(raw) > flatfile.MaxBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// Discover reads the drop and maps it as the flat-file pipeline does.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	snap, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	m := c.cfg.Mapping
	res := flatfile.Discovery(&m, snap.Accounts, snap.Entitlements)
	res.System = System
	return res, nil
}
