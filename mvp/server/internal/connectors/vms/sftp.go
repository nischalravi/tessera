package vms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// SFTP drops for contractor feeds (issue #961). A CSV source whose settings carry an SFTPSettings
// reads its file from an SFTP server on each sync, with the CSV parser of csvfeed.go.
//
// The connection is opened by unixssh.Connector.SFTP, so the rules of that package hold: the socket
// goes through safehttp's address policy (no loopback, private, link-local or metadata target in
// production, only the configured port), the host key is pinned (there is no trust on first use and
// no way to skip the check), and only the "sftp" subsystem runs: no command. The credential, a
// password or an unencrypted private key, is the source's sealed credential; it is never part of
// an error or a result.
//
// Only the one configured file is read. Its path is absolute with no "." or ".." element; the
// directory must equal its real path on the server and the file must be a regular file, not a link
// (lstat, then the real path and fstat of the open handle). A file over MaxCSVBytes is refused, and
// reading stops one byte over the limit whatever the server reports. Errors have fixed text.

// SFTP auth methods: the credential is a password or a private key.
const (
	SFTPPassword = "password"
	SFTPKey      = "key"
)

// SFTPReadTimeout bounds one fetch (connect, stat and read).
const SFTPReadTimeout = 90 * time.Second

// Errors of an SFTP fetch. Their text is fixed: no path, server message or file content is echoed.
var (
	ErrSFTPFile     = errors.New("vms: the SFTP file is missing or is not a regular file")
	ErrSFTPTooLarge = errors.New("vms: the SFTP file is over the size limit")
	ErrSFTPSession  = errors.New("vms: the SFTP session failed")

	sftpUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	sftpPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~@+/-]{0,500}$`)
	sftpNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.[cC][sS][vV]$`)
)

// SFTPSettings locate the file. They hold no secret: the host key is public.
type SFTPSettings struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"` // 0 is 22
	// Path is the absolute path of the CSV file on the server.
	Path     string `json:"path"`
	Username string `json:"username"`
	// HostKey pins the server: "SHA256:<base64>" or a public key line. It is required.
	HostKey string `json:"host_key"`
	// Auth says what the source's credential is: "password" or "key" (an unencrypted SSH private key).
	Auth string `json:"auth"`
}

// Validate checks the settings.
func (s *SFTPSettings) Validate() error {
	if err := unixssh.CheckHost(s.Host); err != nil {
		return errors.New("sftp.host must be a host name or an IP address that is not a cloud metadata service")
	}
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("sftp.port is between 1 and 65535")
	}
	if !sftpUserRE.MatchString(s.Username) {
		return errors.New("sftp.username is not a valid account name")
	}
	if strings.TrimSpace(s.HostKey) == "" {
		return errors.New("sftp.host_key is required: pin the server's host key (SHA256:... or a public key line)")
	}
	if _, err := unixssh.New(unixssh.Config{Host: s.Host, Port: s.Port, Username: s.Username, HostKey: s.HostKey,
		Password: connsync.NewSecret("x")}, connsync.Runtime{}, noDial); err != nil {
		return errors.New("sftp.host_key is not a SHA256 fingerprint or a public key line of an allowed type")
	}
	if err := ValidateSFTPPath(s.Path); err != nil {
		return err
	}
	if s.Auth != SFTPPassword && s.Auth != SFTPKey {
		return errors.New("sftp.auth is password or key")
	}
	return nil
}

// noDial stands in for the dialer when settings are only validated: nothing is dialled.
func noDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("vms: validation only")
}

// ValidateSFTPPath checks the file path: absolute, plain characters, no "." or ".." element, no
// double slash, and a .csv file name.
func ValidateSFTPPath(p string) error {
	if !sftpPathRE.MatchString(p) || p != path.Clean(p) || !sftpNameRE.MatchString(path.Base(p)) || path.Dir(p) == "." {
		return errors.New("sftp.path must be an absolute path to a .csv file, with no . or .. element")
	}
	return nil
}

// CheckCredential checks that cred is usable as the credential of these settings: a password of a
// sensible length, or an unencrypted private key. The text never quotes it.
func (s *SFTPSettings) CheckCredential(cred string) error {
	cfg := unixssh.Config{Host: s.Host, Port: s.Port, Username: s.Username, HostKey: s.HostKey}
	if s.Auth == SFTPKey {
		cfg.Key = connsync.NewSecret(cred)
	} else {
		cfg.Password = connsync.NewSecret(cred)
	}
	if _, err := unixssh.New(cfg, connsync.Runtime{}, noDial); err != nil {
		return errors.New("the credential must be the password, or an unencrypted SSH private key (PEM or OpenSSH) when sftp.auth is key")
	}
	return nil
}

// SameServer reports whether a and b reach the same login on the same server, which is what a
// stored credential is bound to: a change needs a new credential.
func (s *SFTPSettings) SameServer(o *SFTPSettings) bool {
	if s == nil || o == nil {
		return s == o
	}
	return strings.EqualFold(s.Host, o.Host) && s.Port == o.Port && s.Username == o.Username && s.Auth == o.Auth &&
		strings.TrimSpace(s.HostKey) == strings.TrimSpace(o.HostKey)
}

// SFTPFetcher reads a CSV feed from an SFTP server.
type SFTPFetcher struct {
	SFTP       SFTPSettings
	Credential connsync.Secret // the password or the private key, per SFTP.Auth
	RT         connsync.Runtime
	Settings   Settings
	Now        func() time.Time
	// Dial replaces the guarded dialer (tests only: nil in production).
	Dial safehttp.DialFunc
}

// Fetch connects, reads the file and parses it.
func (f *SFTPFetcher) Fetch(ctx context.Context) (*CSVResult, error) {
	cfg := unixssh.Config{Host: f.SFTP.Host, Port: f.SFTP.Port, Username: f.SFTP.Username, HostKey: f.SFTP.HostKey}
	switch f.SFTP.Auth {
	case SFTPPassword:
		cfg.Password = f.Credential
	case SFTPKey:
		cfg.Key = f.Credential
	default:
		return nil, errors.New("vms: sftp.auth is password or key")
	}
	if f.Credential.Empty() {
		return nil, errors.New("vms: the SFTP source has no stored credential")
	}
	if err := ValidateSFTPPath(f.SFTP.Path); err != nil {
		return nil, err
	}
	c, err := unixssh.New(cfg, f.RT, f.Dial)
	if err != nil {
		return nil, err // fixed text: it never quotes the credential
	}
	ctx, cancel := context.WithTimeout(ctx, SFTPReadTimeout)
	defer cancel()
	sc, err := c.SFTP(ctx)
	if errors.Is(err, unixssh.ErrSFTP) {
		return nil, ErrSFTPSession
	}
	if err != nil {
		return nil, err
	}
	defer sc.Close()

	dir, name := path.Dir(f.SFTP.Path), path.Base(f.SFTP.Path)
	if real, err := sc.RealPath(dir); err != nil || real != dir { // a link, or a path through one
		return nil, ErrSFTPFile
	}
	if st, err := sc.Lstat(dir); err != nil || !st.IsDir() {
		return nil, ErrSFTPFile
	}
	full := path.Join(dir, name)
	st, err := sc.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return nil, ErrSFTPFile
	}
	if st.Size() > MaxCSVBytes {
		return nil, ErrSFTPTooLarge
	}
	h, err := sc.Open(full)
	if err != nil {
		return nil, ErrSFTPFile
	}
	defer h.Close()
	if real, err := sc.RealPath(full); err != nil || real != full { // swapped for a link after the lstat
		return nil, ErrSFTPFile
	}
	if fst, err := h.Stat(); err != nil || !fst.Mode().IsRegular() || fst.Mode() != st.Mode() ||
		fst.Size() != st.Size() || !fst.ModTime().Equal(st.ModTime()) {
		return nil, ErrSFTPFile
	}
	raw, err := io.ReadAll(io.LimitReader(h, MaxCSVBytes+1)) // the server's size is not trusted
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("vms: the SFTP read was cancelled or timed out: %w", ctx.Err())
		}
		return nil, ErrSFTPSession
	}
	if len(raw) > MaxCSVBytes {
		return nil, ErrSFTPTooLarge
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	return ParseCSV(bytes.NewReader(raw), f.Settings, now())
}

// SFTPConnector adapts an SFTP fetch to the connector interface and keeps the digest of the file
// it read, for the audit event.
type SFTPConnector struct {
	F      *SFTPFetcher
	Digest string
	Size   int
}

// VmsRecords reads the file and yields its records.
func (c *SFTPConnector) VmsRecords(ctx context.Context, _ *time.Time, yield func(*connectors.VmsRecord) error) error {
	res, err := c.F.Fetch(ctx)
	if err != nil {
		return err
	}
	c.Digest, c.Size = res.Digest, res.Size
	for _, r := range res.Records {
		if err := yield(r); err != nil {
			return err
		}
	}
	return nil
}

// FileDigest is the SHA-256 (hex) and size of the file read, empty before a successful read.
func (c *SFTPConnector) FileDigest() (string, int) { return c.Digest, c.Size }
