// Package unixssh is the read connector for Unix and Linux hosts over SSH (issue #558): the local
// accounts (`getent passwd`), groups and their members (`getent group`), the sudoers rules
// (/etc/sudoers and /etc/sudoers.d) and, where `lastlog` exists, the last login of each account.
// It is read-only. Write-back (create, lock, delete) is not part of this connector.
//
// Safety rules, each tested:
//
//   - Only the fixed command strings below are ever sent. No tenant or remote data is placed in a
//     command, and no file name, user name or setting reaches a shell.
//   - The host key is pinned (a SHA256 fingerprint or the public key in the settings). There is no
//     callback that skips the check: a connection whose host key differs is refused before authentication.
//   - Authentication is by key only. The private key is the connection's sealed credential.
//   - The socket is opened through the same address policy as safehttp (safehttp.NewDialer): a
//     loopback (dev runtime with the loopback exception only), private, link-local or cloud
//     metadata address is refused, and only the configured port is dialled.
//   - Dial, handshake and every command have a timeout; every command's output has a size limit and
//     is parsed strictly (parse.go).
//
// Mapping onto Tessera's model (names are qualified with the host, so one connection per host):
//
//	host                          -> resource (kind unix_host)
//	passwd entry                  -> account <user>@<host> (kind user, or service for system uids)
//	group                         -> group <group>@<host> (kind unix_group)
//	group member, primary gid     -> account -member_of-> group
//	uid 0                         -> account -direct_grant-> permission "uid 0 (root)" (privileged)
//	sudoers rule                  -> permission on the host (privileged), granted to the user or
//	                                 group it names (aliases expanded)
package unixssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "unix"

// The commands. They are constants: nothing is ever formatted into them.
const (
	cmdPasswd  = "getent passwd" // #nosec G101 -- a fixed command line, not a credential
	cmdGroup   = "getent group"
	cmdLastlog = "lastlog"
	// cmdSudoers reads the sudoers file and the files of sudoers.d that sudo itself reads (no dot and no
	// trailing tilde in the name). Most hosts allow it only to root: UseSudo runs it through sudo -n,
	// which needs a NOPASSWD rule for exactly this command (README).
	cmdSudoers     = `cat /etc/sudoers && find /etc/sudoers.d -maxdepth 1 -type f ! -name "*.*" ! -name "*~" -exec cat {} +`
	cmdSudoersSudo = `sudo -n sh -c 'cat /etc/sudoers && find /etc/sudoers.d -maxdepth 1 -type f ! -name "*.*" ! -name "*~" -exec cat {} +'`
)

// Timeouts and size limits.
const (
	DialTimeout      = 10 * time.Second
	HandshakeTimeout = 15 * time.Second
	CommandTimeout   = 30 * time.Second
	maxPasswd        = 16 << 20
	maxGroupOut      = 16 << 20
	maxSudoers       = 2 << 20
	maxLastlog       = 8 << 20
)

var (
	// ErrRefused: the host refused the connection: a different host key than the pinned one, or the key
	// was not accepted for the user.
	ErrRefused = errors.New("unixssh: the host refused the connection")
	// ErrHostKey is the host key mismatch (it is also ErrRefused).
	ErrHostKey = fmt.Errorf("%w: the host key is not the pinned one", ErrRefused)
	// ErrTooLarge: a command wrote more than its limit.
	ErrTooLarge = errors.New("unixssh: command output is over the size limit")
	// ErrTimeout: a command did not finish in CommandTimeout.
	ErrTimeout = errors.New("unixssh: the command timed out")

	hostRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	userRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
)

// Config configures one host.
type Config struct {
	Host     string // a host name or an IP address
	Port     int    // 0 is 22
	Username string // the SSH login
	// HostKey pins the host: "SHA256:<base64>" (as ssh-keygen -lf prints) or the public key in
	// authorized_keys form ("ssh-ed25519 AAAA..."). A known_hosts line without markers is accepted too.
	HostKey string
	// Key is the private key (PEM or OpenSSH format, not passphrase protected).
	Key connsync.Secret
	// UseSudo reads the sudoers files through `sudo -n`.
	UseSudo bool
}

// EffectivePort is the port, 22 by default.
func (c Config) EffectivePort() int {
	if c.Port == 0 {
		return 22
	}
	return c.Port
}

// ValidateHost checks a host name or IP address (no scheme, port or path; no IPv6 zone).
func ValidateHost(h string) error {
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return errors.New("unixssh: an IPv6 zone is not allowed")
		}
		return nil
	}
	if !hostRE.MatchString(h) {
		return errors.New("unixssh: the host must be a host name or an IP address")
	}
	return nil
}

// Connector implements connectors.Connector.
type Connector struct {
	cfg    Config
	signer ssh.Signer
	pin    pin
	dial   safehttp.DialFunc
	host   string // lower case, the qualifier of every external id
}

// New builds a connector. rt carries the environment and the loopback exception exactly as for the
// HTTP connectors. dial replaces the guarded dialer (tests only: nil in production).
func New(cfg Config, rt connsync.Runtime, dial safehttp.DialFunc) (*Connector, error) {
	if err := ValidateHost(cfg.Host); err != nil {
		return nil, err
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, errors.New("unixssh: the port is between 1 and 65535")
	}
	if !userRE.MatchString(cfg.Username) {
		return nil, errors.New("unixssh: the SSH user is not a valid account name")
	}
	p, err := parsePin(cfg.HostKey)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(cfg.Key.Reveal()))
	if err != nil { // never include err: it can quote the key's header
		return nil, errors.New("unixssh: the credential must be an unencrypted SSH private key (PEM or OpenSSH)")
	}
	if dial == nil {
		dial, err = safehttp.NewDialer(safehttp.Options{Env: rt.Env, AllowLoopback: rt.AllowLoopback,
			AllowedPorts: []int{cfg.EffectivePort()}, Timeout: DialTimeout})
		if err != nil {
			return nil, err
		}
	}
	return &Connector{cfg: cfg, signer: signer, pin: p, dial: dial, host: strings.ToLower(cfg.Host)}, nil
}

func (c *Connector) System() string      { return System }
func (c *Connector) DisplayName() string { return "Unix/Linux (SSH)" }
func (c *Connector) TypeName() string    { return "UnixSSHConnector" }

// Identity is the SSH login of the connection.
func (c *Connector) Identity() string { return c.cfg.Username }

// StreamEvents: the host reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// pin is the pinned host key: a fingerprint, a key, or both.
type pin struct {
	fingerprint string
	key         ssh.PublicKey
}

func parsePin(v string) (pin, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 4096 || strings.ContainsAny(v, "\r\n") {
		return pin{}, errors.New("unixssh: the host key is a SHA256 fingerprint or one public key line")
	}
	if rest, ok := strings.CutPrefix(v, "SHA256:"); ok {
		if len(rest) != 43 || strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") != "" {
			return pin{}, errors.New("unixssh: the SHA256 fingerprint is not valid (43 base64 characters, as ssh-keygen -lf prints)")
		}
		return pin{fingerprint: v}, nil
	}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v)); err == nil {
		return pin{key: k}, nil
	}
	if marker, _, k, _, _, err := ssh.ParseKnownHosts([]byte(v)); err == nil && marker == "" {
		return pin{key: k}, nil
	}
	return pin{}, errors.New("unixssh: the host key is a SHA256 fingerprint or one public key line")
}

func (p pin) matches(k ssh.PublicKey) bool {
	if p.key != nil {
		return bytes.Equal(p.key.Marshal(), k.Marshal())
	}
	return ssh.FingerprintSHA256(k) == p.fingerprint
}

// session is one authenticated connection.
type session struct{ cl *ssh.Client }

// open dials through the guarded dialer, verifies the host key against the pin and signs in with the
// key. The handshake has its own deadline.
func (c *Connector) open(ctx context.Context) (*session, error) {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.EffectivePort()))
	conn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("unixssh: cannot connect to %s: %w", addr, err)
	}
	mismatch := false
	conf := &ssh.ClientConfig{
		User: c.cfg.Username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(c.signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if c.pin.matches(k) {
				return nil
			}
			mismatch = true
			return ErrHostKey
		},
		Timeout: HandshakeTimeout,
	}
	if c.pin.key != nil { // offer only the pinned key's algorithms
		conf.HostKeyAlgorithms = hostKeyAlgorithms(c.pin.key)
	}
	deadline := time.Now().Add(HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, conf)
	if err != nil {
		_ = conn.Close()
		switch {
		case mismatch:
			return nil, ErrHostKey
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, fmt.Errorf("%w: the key was not accepted for %s", ErrRefused, c.cfg.Username)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("unixssh: handshake with %s failed", addr)
	}
	_ = conn.SetDeadline(time.Time{})
	return &session{cl: ssh.NewClient(sc, chans, reqs)}, nil
}

func hostKeyAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA { // an RSA key signs with SHA-2 only
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}

func (s *session) close() { _ = s.cl.Close() }

// limitBuf collects at most max bytes and refuses more.
type limitBuf struct {
	b   bytes.Buffer
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		return 0, ErrTooLarge
	}
	return l.b.Write(p)
}

// run executes one of the fixed commands. A non-zero exit status is returned as *ssh.ExitError with
// whatever the command wrote.
func (s *session) run(ctx context.Context, cmd string, max int) ([]byte, error) {
	sn, err := s.cl.NewSession()
	if err != nil {
		return nil, errors.New("unixssh: cannot open a session")
	}
	defer sn.Close()
	var out limitBuf
	out.max = max
	sn.Stdout, sn.Stderr = &out, io.Discard
	done := make(chan error, 1)
	go func() { done <- sn.Run(cmd) }()
	t := time.NewTimer(CommandTimeout)
	defer t.Stop()
	select {
	case err = <-done:
	case <-t.C:
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if errors.Is(err, ErrTooLarge) {
		return nil, ErrTooLarge
	}
	return out.b.Bytes(), err
}

// Snapshot is what one read found.
type Snapshot struct {
	Accounts []Account
	Groups   []Group
	Rules    []Rule
	// Bad counts passwd and group lines dropped by the strict parser: the read is then partial.
	Bad int
	// SudoersRead is false when the sudoers files could not be read (not root, no sudo rule).
	SudoersRead bool
	// SudoersSkipped counts sudoers lines that could not be read.
	SudoersSkipped int
	LastLogin      map[string]time.Time
}

// Read runs the fixed commands and parses their output.
func (c *Connector) Read(ctx context.Context) (*Snapshot, error) {
	s, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	snap := &Snapshot{}
	pw, err := s.run(ctx, cmdPasswd, maxPasswd)
	if err != nil {
		return nil, commandError("getent passwd", err)
	}
	gr, err := s.run(ctx, cmdGroup, maxGroupOut)
	if err != nil {
		return nil, commandError("getent group", err)
	}
	var bad1, bad2 int
	snap.Accounts, bad1 = ParsePasswd(pw)
	snap.Groups, bad2 = ParseGroup(gr)
	snap.Bad = bad1 + bad2
	if len(snap.Accounts) == 0 {
		return nil, errors.New("unixssh: getent passwd returned no account")
	}
	cmd := cmdSudoers
	if c.cfg.UseSudo {
		cmd = cmdSudoersSudo
	}
	// A host where the sudoers files are not readable (the login is not root and has no sudo rule) is
	// still read: its accounts and groups are valid, its rules are unknown (SudoersRead false). A
	// non-zero exit with output is a host with no sudoers.d directory.
	out, err := s.run(ctx, cmd, maxSudoers)
	var ee *ssh.ExitError
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err == nil || errors.As(err, &ee) && len(out) > 0:
		snap.SudoersRead = true
		snap.Rules, snap.SudoersSkipped = ParseSudoers(out)
	}
	out, err = s.run(ctx, cmdLastlog, maxLastlog) // optional: not every host has lastlog
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil {
		snap.LastLogin = ParseLastlog(out)
	}
	return snap, nil
}

// commandError never carries the host's output.
func commandError(what string, err error) error {
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee):
		return fmt.Errorf("unixssh: %s exited with status %d", what, ee.ExitStatus())
	case errors.Is(err, ErrTooLarge), errors.Is(err, ErrTimeout), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("unixssh: %s: %w", what, err)
	}
	return fmt.Errorf("unixssh: %s failed", what)
}

// Discover reads the host and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	snap, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return c.build(snap), nil
}
