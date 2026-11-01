package sftpdrop

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var devRT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

const accountsCSV = "ID,Login,Mail,Status\nu1,alice,Alice@Example.com,active\nu2,bob,bob@example.com,disabled\n"
const entitlementsCSV = "ID,Role,Admin\nu1,payroll-admin,yes\nu1,viewer,no\nu2,viewer,no\n"

type fixture struct {
	srv  *fakeServer
	conf Config
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	signer, pem := newKey(t)
	srv := startServer(t, signer.PublicKey())
	srv.write(t, "accounts.csv", accountsCSV)
	srv.write(t, "ents.csv", entitlementsCSV)
	return &fixture{srv: srv, conf: Config{
		SSH:              unixssh.Config{Host: "127.0.0.1", Port: srv.port(), Username: "drop", HostKey: srv.fingerprint(), Key: connsync.NewSecret(pem)},
		Directory:        srv.dir,
		AccountsFile:     "accounts.csv",
		EntitlementsFile: "ents.csv",
		Mapping: flatfile.Mapping{
			Accounts:     flatfile.AccountCols{AccountID: "ID", Username: "Login", Email: "Mail", Status: "Status"},
			Entitlements: &flatfile.EntitlementCols{AccountID: "ID", Entitlement: "Role", Privileged: "Admin"},
		},
	}}
}

func (f *fixture) discover(t *testing.T) (*connectors.DiscoveryResult, error) {
	t.Helper()
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return c.Discover(ctx)
}

func TestDiscoverMapsTheDropLikeTheFlatFilePipeline(t *testing.T) {
	f := newFixture(t)
	res, err := f.discover(t)
	if err != nil {
		t.Fatal(err)
	}
	if res.System != System || len(res.Accounts) != 2 || len(res.Resources) != 1 || len(res.Permissions) != 2 || len(res.Edges) != 3 {
		t.Fatalf("system %q: %d accounts %d resources %d permissions %d edges", res.System, len(res.Accounts), len(res.Resources), len(res.Permissions), len(res.Edges))
	}
	a := res.Accounts[0]
	if a.ExternalID != "u1" || a.Username != "alice" || a.Status != "active" || a.Identity == nil || a.Identity.Email != "alice@example.com" {
		t.Errorf("account = %+v", a)
	}
	if res.Accounts[1].Status != "disabled" {
		t.Errorf("bob = %+v", res.Accounts[1])
	}
	priv := map[string]bool{}
	for _, p := range res.Permissions {
		priv[p.Action] = p.Privileged
	}
	if !priv["payroll-admin"] || priv["viewer"] {
		t.Errorf("privileged = %v", priv)
	}
}

func TestAccountsOnly(t *testing.T) {
	f := newFixture(t)
	f.conf.EntitlementsFile, f.conf.Mapping.Entitlements = "", nil
	res, err := f.discover(t)
	if err != nil || len(res.Accounts) != 2 || len(res.Permissions) != 0 {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestHostKeyIsPinned(t *testing.T) {
	f := newFixture(t)
	other, _ := newKey(t)
	for name, pin := range map[string]string{"another fingerprint": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "another key": strings.TrimSpace(string(marshal(other)))} {
		f.conf.SSH.HostKey = pin
		_, err := f.discover(t)
		if !errors.Is(err, unixssh.ErrHostKey) || !errors.Is(err, unixssh.ErrRefused) {
			t.Errorf("%s: err = %v, want the host key refusal", name, err)
		}
	}
}

func TestKeyNotAccepted(t *testing.T) {
	f := newFixture(t)
	_, other := newKey(t)
	f.conf.SSH.Key = connsync.NewSecret(other)
	if _, err := f.discover(t); !errors.Is(err, unixssh.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
}

func TestOnlyTheConfiguredDirectoryAndFilesAreRead(t *testing.T) {
	f := newFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.csv"), []byte(accountsCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	// a file name that leaves the directory or is not plain is refused before any connection
	for _, name := range []string{"../secret.csv", "sub/accounts.csv", "/etc/passwd", "..", "a..b.csv", ".hidden", "a b.csv", "x\x00.csv", ""} {
		c := f.conf
		c.AccountsFile = name
		if _, err := New(c, devRT, nil); err == nil {
			t.Errorf("accounts file %q accepted", name)
		}
		c = f.conf
		c.EntitlementsFile = name
		if name != "" {
			if _, err := New(c, devRT, nil); err == nil {
				t.Errorf("entitlements file %q accepted", name)
			}
		}
	}
	for _, dir := range []string{"", "relative", "/a/../etc", "/a/./b", "/a//b", "/a/", "/a b", "/a\n"} {
		c := f.conf
		c.Directory = dir
		if _, err := New(c, devRT, nil); err == nil {
			t.Errorf("directory %q accepted", dir)
		}
	}

	// a symbolic link in place of the file is refused, whatever it points at
	if err := os.Symlink(filepath.Join(outside, "secret.csv"), filepath.Join(f.srv.dir, "link.csv")); err != nil {
		t.Fatal(err)
	}
	f.conf.AccountsFile = "link.csv"
	if _, err := f.discover(t); !errors.Is(err, ErrFile) {
		t.Errorf("symlinked file: err = %v", err)
	}
	f.conf.AccountsFile = "missing.csv"
	if _, err := f.discover(t); !errors.Is(err, ErrFile) {
		t.Errorf("missing file: err = %v", err)
	}
	// a directory is not a file
	if err := os.Mkdir(filepath.Join(f.srv.dir, "dir.csv"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.conf.AccountsFile = "dir.csv"
	if _, err := f.discover(t); !errors.Is(err, ErrFile) {
		t.Errorf("directory as file: err = %v", err)
	}

	// the directory itself must be its real path: a link to another directory, or a path through one, is refused
	link := filepath.Join(t.TempDir(), "drop")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	f.conf.AccountsFile = "secret.csv"
	f.conf.EntitlementsFile, f.conf.Mapping.Entitlements = "", nil
	for _, dir := range []string{link, outside + "/nonexistent"} {
		f.conf.Directory = dir
		if _, err := f.discover(t); !errors.Is(err, ErrDirectory) {
			t.Errorf("directory %q: err = %v", dir, err)
		}
	}
	// the same file read from its real directory works, so the refusals above are the link checks
	f.conf.Directory = outside
	if rp, err := filepath.EvalSymlinks(outside); err == nil {
		f.conf.Directory = rp
	}
	if _, err := f.discover(t); err != nil {
		t.Errorf("real directory: %v", err)
	}
}

func TestSizeAndRowCaps(t *testing.T) {
	f := newFixture(t)
	f.srv.write(t, "accounts.csv", "ID,Login,Mail,Status\n"+strings.Repeat("u,x,,\n", flatfile.MaxBytes/6+10))
	if _, err := f.discover(t); !errors.Is(err, ErrTooLarge) {
		t.Errorf("large file: err = %v", err)
	}
	var b strings.Builder
	b.WriteString("ID,Login,Mail,Status\n")
	for i := 0; i <= flatfile.MaxRows; i++ {
		b.WriteString("u" + strconv.Itoa(i) + ",x,,\n")
	}
	if b.Len() > flatfile.MaxBytes {
		t.Fatalf("test file is %d bytes: the row cap must be what stops it", b.Len())
	}
	f.srv.write(t, "accounts.csv", b.String())
	if _, err := f.discover(t); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many rows: err = %v", err)
	}
}

// lyingDrop is an SFTP server whose one file reports a small size (lstat and fstat agree, so the
// size and swap checks pass) and then streams without end: only the read cap stops it.
type lyingDrop struct {
	dir    string
	served atomic.Int64 // bytes handed to the client
}

type lyingInfo struct {
	name string
	dir  bool
}

func (i lyingInfo) Name() string { return i.name }
func (i lyingInfo) Size() int64 {
	if i.dir {
		return 0
	}
	return 100 // the lie
}
func (i lyingInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (lyingInfo) ModTime() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
func (i lyingInfo) IsDir() bool      { return i.dir }
func (lyingInfo) Sys() any           { return nil }

type oneInfo struct{ fi os.FileInfo }

func (o oneInfo) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off > 0 {
		return 0, io.EOF
	}
	ls[0] = o.fi
	return 1, io.EOF
}

func (l *lyingDrop) Fileread(*sftp.Request) (io.ReaderAt, error) { return l, nil }

// ReadAt serves 'a' bytes without end, up to a 64 MiB backstop so a missing cap fails the test
// instead of hanging it.
func (l *lyingDrop) ReadAt(p []byte, off int64) (int, error) {
	if off >= 64<<20 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'a'
	}
	l.served.Add(int64(len(p)))
	return len(p), nil
}

func (l *lyingDrop) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "Stat", "Lstat":
		return oneInfo{lyingInfo{name: path.Base(r.Filepath), dir: r.Filepath == l.dir}}, nil
	}
	return nil, os.ErrPermission
}

func (*lyingDrop) Filewrite(*sftp.Request) (io.WriterAt, error) { return nil, os.ErrPermission }
func (*lyingDrop) Filecmd(*sftp.Request) error                  { return os.ErrPermission }

// A server that reports a small size and streams more than the limit: the read stops one byte over
// the limit (the LimitReader), whatever the server claims, and the file is refused as too large.
func TestLyingSizeIsCappedAtTheLimit(t *testing.T) {
	f := newFixture(t)
	drop := &lyingDrop{dir: "/drop"}
	f.srv.handlers = &sftp.Handlers{FileGet: drop, FilePut: drop, FileCmd: drop, FileList: drop}
	f.conf.Directory = drop.dir
	f.conf.EntitlementsFile = ""
	f.conf.Mapping.Entitlements = nil
	if _, err := f.discover(t); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// the client reads in 32 KiB requests: a little past the limit is served, never the backstop
	if n := drop.served.Load(); n < flatfile.MaxBytes+1 || n > flatfile.MaxBytes+256<<10 {
		t.Errorf("served %d bytes, want the limit (%d) plus at most a few requests", n, flatfile.MaxBytes)
	}
}

func TestReadReportsFileSizeAndModifiedTime(t *testing.T) {
	f := newFixture(t)
	mt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(f.srv.dir, "accounts.csv"), mt, mt); err != nil {
		t.Fatal(err)
	}
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Files) != 2 {
		t.Fatalf("files = %+v", snap.Files)
	}
	acc, ent := snap.Files[0], snap.Files[1]
	if acc.Role != "accounts" || acc.Size != int64(len(accountsCSV)) || !acc.ModTime.Equal(mt) {
		t.Errorf("accounts = %+v, want size %d modified %s", acc, len(accountsCSV), mt)
	}
	if ent.Role != "entitlements" || ent.Size != int64(len(entitlementsCSV)) || ent.ModTime.IsZero() {
		t.Errorf("entitlements = %+v", ent)
	}
}

func TestMaxAgeFromEnv(t *testing.T) {
	env := map[string]string{"TESSERA_SFTPDROP_HOST": "h", "TESSERA_SFTPDROP_USER": "u", "TESSERA_SFTPDROP_KEY": "env:K", "K": "key"}
	for name, tc := range map[string]struct {
		v    string
		want time.Duration
		bad  bool
	}{
		"unset":    {"", 0, false},
		"a day":    {"24", 24 * time.Hour, false},
		"zero":     {"0", 0, true},
		"text":     {"soon", 0, true},
		"negative": {"-1", 0, true},
		"huge":     {"99999", 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ConfigFromEnv(func(k string) string {
				if k == "TESSERA_SFTPDROP_MAX_AGE_HOURS" {
					return tc.v
				}
				return env[k]
			})
			if tc.bad {
				if err == nil || !strings.Contains(err.Error(), "MAX_AGE_HOURS") {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MaxAge != tc.want {
				t.Errorf("MaxAge = %v, want %v", cfg.MaxAge, tc.want)
			}
		})
	}
}

func TestInvalidFileFailsWholeWithFixedText(t *testing.T) {
	f := newFixture(t)
	secret := "=cmd|' /C calc'!A0-INJECTED"
	for name, content := range map[string]string{
		"bad email":    "ID,Login,Mail,Status\nu1,alice," + secret + ",active\n",
		"missing col":  "ID,Login\nu1,alice\n",
		"duplicate id": "ID,Login,Mail,Status\nu1,a,,\nu1,b,,\n",
		"bad status":   "ID,Login,Mail,Status\nu1,a,,<script>alert(1)</script>\n",
		"not utf8":     "ID,Login,Mail,Status\nu1,\xff\xfe,,\n",
		"empty":        "",
		"short row":    "ID,Login,Mail,Status\nu1,a\n",
	} {
		f.srv.write(t, "accounts.csv", content)
		res, err := f.discover(t)
		if !errors.Is(err, ErrInvalid) || res != nil {
			t.Errorf("%s: res %v err %v", name, res, err)
			continue
		}
		if msg := err.Error(); strings.Contains(msg, "INJECTED") || strings.Contains(msg, "script") || strings.Contains(msg, f.srv.dir) {
			t.Errorf("%s: the error echoes input: %q", name, msg)
		}
	}
	// a header-only accounts file (a failed export) is refused, not read as "all removed"
	f.srv.write(t, "accounts.csv", "ID,Login,Mail,Status\n")
	if res, err := f.discover(t); !errors.Is(err, ErrEmpty) || res != nil {
		t.Errorf("header only: res %v err %v", res, err)
	}
	// an entitlement of an account the accounts file lacks is invalid too
	f.srv.write(t, "accounts.csv", accountsCSV)
	f.srv.write(t, "ents.csv", "ID,Role,Admin\nu9,viewer,no\n")
	if _, err := f.discover(t); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown account: err = %v", err)
	}
}

func TestSocketIsGuarded(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name string
		rt   connsync.Runtime
		host string
	}{
		{"loopback in prod", connsync.Runtime{Env: config.Prod}, "127.0.0.1"},
		{"loopback without the exception", connsync.Runtime{Env: config.Dev}, "127.0.0.1"},
		{"private", devRT, "10.1.2.3"},
		{"metadata", connsync.Runtime{Env: config.Prod}, "169.254.169.254"},
	} {
		c := f.conf
		c.SSH.Host = tc.host
		cn, err := New(c, tc.rt, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = cn.Discover(ctx)
		cancel()
		// the address policy refused it, not a timeout, a host-key or a sign-in failure
		if !errors.Is(err, safehttp.ErrBlockedAddress) {
			t.Errorf("%s: err = %v, want safehttp.ErrBlockedAddress", tc.name, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	f := newFixture(t)
	for name, mut := range map[string]func(*Config){
		"same file twice":           func(c *Config) { c.EntitlementsFile = c.AccountsFile },
		"entitlements without cols": func(c *Config) { c.Mapping.Entitlements = nil },
		"missing account column":    func(c *Config) { c.Mapping.Accounts.AccountID = "" },
		"column serves two fields":  func(c *Config) { c.Mapping.Accounts.Username = c.Mapping.Accounts.AccountID },
		"bad host":                  func(c *Config) { c.SSH.Host = "https://h" },
		"no host key":               func(c *Config) { c.SSH.HostKey = "" },
		"not a key":                 func(c *Config) { c.SSH.Key = connsync.NewSecret("hunter2") },
	} {
		c := f.conf
		mut(&c)
		_, err := New(c, devRT, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the error echoes the credential: %v", name, err)
		}
	}
}

func TestFromEnvResolvesTheKeyReference(t *testing.T) {
	f := newFixture(t)
	env := map[string]string{"TESSERA_SFTPDROP_HOST": "127.0.0.1", "TESSERA_SFTPDROP_PORT": strconv.Itoa(f.srv.port()), "TESSERA_SFTPDROP_USER": "drop",
		"TESSERA_SFTPDROP_HOST_KEY": f.srv.fingerprint(), "TESSERA_SFTPDROP_KEY": "env:SECRET_VAR", "SECRET_VAR": f.conf.SSH.Key.Reveal(),
		"TESSERA_SFTPDROP_DIR": f.srv.dir, "TESSERA_SFTPDROP_ACCOUNTS_FILE": "accounts.csv", "TESSERA_SFTPDROP_ENTITLEMENTS_FILE": "ents.csv",
		"TESSERA_SFTPDROP_COL_ACCOUNT_ID": "ID", "TESSERA_SFTPDROP_COL_USERNAME": "Login", "TESSERA_SFTPDROP_COL_EMAIL": "Mail", "TESSERA_SFTPDROP_COL_STATUS": "Status",
		"TESSERA_SFTPDROP_COL_ENT_ACCOUNT_ID": "ID", "TESSERA_SFTPDROP_COL_ENT_ENTITLEMENT": "Role", "TESSERA_SFTPDROP_COL_ENT_PRIVILEGED": "Admin",
		"TESSERA_UNIXSSH_HOST": "ignored.example.com"} // the Unix connector's own variables are never read
	cn, err := FromEnv(func(k string) string { return env[k] }, devRT)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cn.Discover(context.Background())
	if err != nil || len(res.Accounts) != 2 {
		t.Fatalf("res %+v err %v", res, err)
	}
	env["TESSERA_SFTPDROP_PORT"] = "0"
	if _, err := FromEnv(func(k string) string { return env[k] }, devRT); err == nil || !strings.Contains(err.Error(), "TESSERA_SFTPDROP_PORT") {
		t.Errorf("bad port: %v", err)
	}
}

func TestNoCommandIsRun(t *testing.T) {
	// the fake refuses exec and shell requests; Discover working proves only the sftp subsystem is used
	f := newFixture(t)
	if _, err := f.discover(t); err != nil {
		t.Fatal(err)
	}
}
