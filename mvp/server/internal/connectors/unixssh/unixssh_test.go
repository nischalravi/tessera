package unixssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const passwdOut = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/usr/sbin/nologin
toor:x:0:0:second root:/root:/bin/sh
`

const groupOut = `root:x:0:
sudo:x:27:alice
wheel:x:10:bob
devs:x:2000:alice,bob,ghost
alice:x:1000:
bob:x:1001:
`

const sudoersOut = `# comment
Defaults env_reset
User_Alias ADMINS = alice, %devs
Cmnd_Alias SHELLS = ALL
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
ADMINS ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
bob ALL=(root) /usr/bin/less
`

const lastlogOut = `Username         Port     From             Latest
root                                       **Never logged in**
alice            pts/0    10.1.2.3         Mon Oct 20 09:15:02 +0000 2026
`

type fixture struct {
	h    *fakeHost
	key  string
	conf Config
}

// newFixture starts a fake host and returns a config that reaches it through the guarded dialer
// (dev runtime with the loopback exception).
func newFixture(t *testing.T, outputs map[string]fakeReply) *fixture {
	t.Helper()
	signer, pem := newKey(t)
	h := startHost(t, signer.PublicKey(), outputs)
	port := h.port()
	return &fixture{h: h, key: pem, conf: Config{Host: "127.0.0.1", Port: port, Username: "tessera", HostKey: h.fingerprint(), Key: connsync.NewSecret(pem)}}
}

var devRT = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

func fullOutputs() map[string]fakeReply {
	return map[string]fakeReply{
		cmdPasswd: {out: passwdOut}, cmdGroup: {out: groupOut}, cmdSudoers: {out: sudoersOut}, cmdSudoersD: {},
		cmdSudoersSudo: {out: sudoersOut}, cmdSudoersDSudo: {}, cmdLastlog: {out: lastlogOut},
	}
}

func discover(t *testing.T, f *fixture) *connectors.DiscoveryResult {
	t.Helper()
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDiscoverMapsAccountsGroupsAndSudo(t *testing.T) {
	f := newFixture(t, fullOutputs())
	res := discover(t, f)
	if res.System != System || res.Partial != "" {
		t.Fatalf("system %q partial %q", res.System, res.Partial)
	}
	h := "127.0.0.1"
	accts := map[string]connectors.AccountRecord{}
	for _, a := range res.Accounts {
		accts[a.Username] = a
	}
	if len(accts) != 5 {
		t.Fatalf("%d accounts", len(accts))
	}
	for name, want := range map[string][2]string{"root": {"user", "active"}, "daemon": {"service", "active"}, "alice": {"user", "active"}, "bob": {"user", "disabled"}} {
		a := accts[name]
		if a.Kind != want[0] || a.Status != want[1] || a.ExternalID != name+"@"+h {
			t.Errorf("%s = %+v", name, a)
		}
	}
	if a := accts["alice"]; a.LastLoginAt == nil || !a.LastLoginAt.Equal(time.Date(2026, 10, 20, 9, 15, 2, 0, time.UTC)) || a.Attributes["uid"] != "1000" {
		t.Errorf("alice = %+v", a)
	}
	if accts["bob"].LastLoginAt != nil {
		t.Error("bob has no login")
	}

	perms := map[string]connectors.PermissionRecord{}
	for _, p := range res.Permissions {
		perms[p.ExternalID] = p
		if !p.Privileged || p.ResourceExternalID != h {
			t.Errorf("permission %+v is not privileged on the host", p)
		}
	}
	if _, ok := perms[h+"|uid0"]; !ok {
		t.Error("no uid 0 permission")
	}
	sudo := 0
	for _, p := range res.Permissions {
		if strings.HasPrefix(p.Action, "sudo ") {
			sudo++
		}
	}
	if sudo != 4 {
		t.Errorf("%d sudo permissions, want 4", sudo)
	}

	groups := map[string]connectors.GroupRecord{}
	for _, g := range res.Groups {
		groups[g.Name] = g
	}
	for name, priv := range map[string]bool{"root": true, "sudo": true, "devs": true, "wheel": false, "alice": false} {
		if groups[name].Privileged != priv || groups[name].Kind != "unix_group" {
			t.Errorf("group %s = %+v, want privileged %v", name, groups[name], priv)
		}
	}

	has := func(rel, src, dst string) bool {
		return slices.ContainsFunc(res.Edges, func(e connectors.EdgeRecord) bool {
			return e.Relation == rel && e.Src.ExternalID == src && (e.Dst.ExternalID == dst || strings.HasPrefix(e.Dst.ExternalID, dst))
		})
	}
	for _, e := range [][3]string{
		{"member_of", "alice@" + h, "sudo@" + h}, {"member_of", "bob@" + h, "devs@" + h}, {"member_of", "bob@" + h, "wheel@" + h},
		{"member_of", "alice@" + h, "alice@" + h}, // the primary group
		{"direct_grant", "root@" + h, h + "|uid0"}, {"direct_grant", "toor@" + h, h + "|uid0"},
		{"grants", "sudo@" + h, h + "|sudo|"}, {"grants", "devs@" + h, h + "|sudo|"}, {"direct_grant", "alice@" + h, h + "|sudo|"}, {"direct_grant", "bob@" + h, h + "|sudo|"},
	} {
		if !has(e[0], e[1], e[2]) {
			t.Errorf("missing edge %v", e)
		}
	}
	if has("member_of", "ghost@"+h, "devs@"+h) {
		t.Error("an unknown member got an edge")
	}
	if slices.ContainsFunc(res.Edges, func(e connectors.EdgeRecord) bool {
		return e.Src.ExternalID == "daemon@"+h && e.Relation == "direct_grant"
	}) {
		t.Error("daemon holds no direct grant")
	}
}

func TestOnlyFixedCommandsAreSent(t *testing.T) {
	for _, useSudo := range []bool{false, true} {
		f := newFixture(t, fullOutputs())
		f.conf.UseSudo = useSudo
		discover(t, f)
		want := []string{cmdPasswd, cmdGroup, cmdSudoers, cmdSudoersD, cmdLastlog}
		if useSudo {
			want = []string{cmdPasswd, cmdGroup, cmdSudoersSudo, cmdSudoersDSudo, cmdLastlog}
		}
		if got := f.h.seen(); !slices.Equal(got, want) {
			t.Errorf("sudo=%v: commands %q, want %q", useSudo, got, want)
		}
	}
	for _, c := range []string{cmdPasswd, cmdGroup, cmdSudoers, cmdSudoersD, cmdSudoersSudo, cmdSudoersDSudo, cmdLastlog} {
		if strings.Contains(c, "%") || strings.Contains(c, "$") || strings.Contains(c, "`") {
			t.Errorf("command %q looks parameterised", c)
		}
	}
}

func TestSudoersUnreadableIsNotAFailure(t *testing.T) {
	out := fullOutputs()
	out[cmdSudoers] = fakeReply{status: 1} // cat: permission denied
	delete(out, cmdLastlog)                // no lastlog on this host
	f := newFixture(t, out)
	res := discover(t, f)
	if len(res.Accounts) != 5 {
		t.Fatalf("%d accounts", len(res.Accounts))
	}
	if !slices.Contains(res.Resources[0].Tags, "sudoers:unreadable") {
		t.Errorf("tags %v", res.Resources[0].Tags)
	}
	for _, p := range res.Permissions {
		if strings.HasPrefix(p.Action, "sudo ") {
			t.Errorf("a sudo rule from nowhere: %+v", p)
		}
	}
	// the rules are unknown, so the conventional sudo groups are privileged (and so are their members)
	h := "127.0.0.1"
	for _, g := range res.Groups {
		want := g.Name == "sudo" || g.Name == "wheel" || g.Name == "root"
		if g.Privileged != want {
			t.Errorf("group %s privileged = %v, want %v", g.Name, g.Privileged, want)
		}
	}
	var perm string
	for _, p := range res.Permissions {
		if p.ExternalID == h+"|sudo-group" && p.Privileged {
			perm = p.ExternalID
		}
	}
	grants, member := 0, false
	for _, e := range res.Edges {
		if e.Dst.ExternalID == perm && e.Relation == "grants" {
			grants++
		}
		if e.Src.ExternalID == "alice@"+h && e.Dst.ExternalID == "sudo@"+h && e.Relation == "member_of" {
			member = true
		}
	}
	if perm == "" || grants != 2 || !member {
		t.Errorf("assumed sudo permission %q, %d grants, alice a member %v", perm, grants, member)
	}
	if res.Partial != "" {
		t.Errorf("partial = %q: unreadable sudoers is a setting, not a failed read", res.Partial)
	}
}

func TestSudoersDFailureIsPartial(t *testing.T) {
	out := fullOutputs()
	out[cmdSudoersD] = fakeReply{status: 1} // find: permission denied on a 0750 directory
	res := discover(t, newFixture(t, out))
	if !strings.Contains(res.Partial, "sudoers") {
		t.Errorf("partial = %q", res.Partial)
	}
	if !slices.Contains(res.Resources[0].Tags, "sudoers-skipped:1") {
		t.Errorf("tags %v", res.Resources[0].Tags)
	}
	n := 0
	for _, p := range res.Permissions {
		if strings.HasPrefix(p.Action, "sudo ") {
			n++
		}
	}
	if n != 4 { // the main file's rules are still read
		t.Errorf("%d sudo rules", n)
	}
}

func TestSudoersDFilesAreSeparated(t *testing.T) {
	// the first file ends in a backslash; the second starts with a rule that must stay its own rule
	out := fullOutputs()
	out[cmdSudoersD] = fakeReply{out: "==> /etc/sudoers.d/a <==\nalice ALL=(root) /bin/ls, \\\n==> /etc/sudoers.d/b <==\nbob ALL=(root) /usr/bin/id\n"}
	res := discover(t, newFixture(t, out))
	var got []string
	for _, p := range res.Permissions {
		if strings.HasPrefix(p.Action, "sudo ") {
			got = append(got, p.Action)
		}
	}
	if len(got) != 6 || !slices.ContainsFunc(got, func(a string) bool { return strings.Contains(a, "/usr/bin/id") && !strings.Contains(a, "/bin/ls") }) {
		t.Errorf("rules %q", got)
	}
}

func TestMalformedLinesMakeTheReadPartial(t *testing.T) {
	out := fullOutputs()
	out[cmdPasswd] = fakeReply{out: passwdOut + "broken line\nzed:x:notanumber:1::/h:/bin/sh\n"}
	res := discover(t, newFixture(t, out))
	if !strings.Contains(res.Partial, "2 passwd or group lines") {
		t.Errorf("partial = %q", res.Partial)
	}
	if len(res.Accounts) != 5 {
		t.Errorf("%d accounts", len(res.Accounts))
	}
}

func TestCommandFailureNamesNoOutput(t *testing.T) {
	out := fullOutputs()
	out[cmdGroup] = fakeReply{out: "secret-looking output", status: 2}
	c, err := New(newFixtureWith(t, out), devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "getent group exited with status 2") || strings.Contains(err.Error(), "secret-looking") {
		t.Fatalf("err = %v", err)
	}
}

func newFixtureWith(t *testing.T, out map[string]fakeReply) Config {
	return newFixture(t, out).conf
}

func TestOversizedOutputIsRefused(t *testing.T) {
	lb := &limitBuf{max: 8}
	if _, err := lb.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := lb.Write([]byte("6789")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	// through a session: a sudoers read over its limit is treated as unreadable, not parsed
	out := fullOutputs()
	out[cmdSudoers] = fakeReply{out: strings.Repeat("# padding padding padding padding padding padding\n", 60000)} // ~3 MiB
	res := discover(t, newFixture(t, out))
	if !slices.Contains(res.Resources[0].Tags, "sudoers:unreadable") {
		t.Errorf("tags %v", res.Resources[0].Tags)
	}
}

func TestOversizedOutputReturnsAtOnce(t *testing.T) {
	out := fullOutputs()
	// the command writes too much and then never ends
	out[cmdPasswd] = fakeReply{out: strings.Repeat("x", maxPasswd+1024), hangAfter: true}
	f := newFixture(t, out)
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Read(context.Background())
	if !errors.Is(err, ErrTooLarge) || time.Since(start) > 8*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

func TestHungCommandStopsWithTheContext(t *testing.T) {
	out := fullOutputs()
	out[cmdGroup] = fakeReply{hang: true}
	f := newFixture(t, out)
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Discover(ctx); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

func TestHostKeyPinning(t *testing.T) {
	f := newFixture(t, fullOutputs())
	other, _ := newKey(t)
	otherFP := ssh.FingerprintSHA256(other.PublicKey())
	otherLine := string(ssh.MarshalAuthorizedKey(other.PublicKey()))
	for _, c := range []struct {
		name, pin string
		ok        bool
	}{
		{"fingerprint", f.h.fingerprint(), true},
		{"public key", f.h.pubLine(), true},
		{"known_hosts line", "[127.0.0.1]:22 " + f.h.pubLine(), true},
		{"other fingerprint", otherFP, false},
		{"other public key", otherLine, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := f.h.authAttempts()
			conf := f.conf
			conf.HostKey = c.pin
			cn, err := New(conf, devRT, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = cn.Read(context.Background())
			switch {
			case c.ok && err != nil:
				t.Fatalf("pinned host refused: %v", err)
			case !c.ok && !errors.Is(err, ErrHostKey):
				t.Fatalf("err = %v, want the host key refusal", err)
			case !c.ok && !errors.Is(err, ErrRefused):
				t.Fatal("a host key refusal is a refusal")
			case !c.ok && f.h.authAttempts() != before:
				t.Fatal("the client authenticated to a host with another key")
			}
		})
	}
}

func TestWrongClientKeyIsRefused(t *testing.T) {
	f := newFixture(t, fullOutputs())
	_, pem := newKey(t)
	f.conf.Key = connsync.NewSecret(pem)
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(context.Background()); !errors.Is(err, ErrRefused) || errors.Is(err, ErrHostKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	f := newFixture(t, nil)
	_, encrypted := encryptedKey(t)
	dsa := "ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAAAAFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QAAAIEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoAAACAJtnhW4ZpRZyBF0yblgXYKtlOPbMDvX6LvlcDGXtt8dFlFIwXsjSDUBRFaIsBGVNIhj3K7ksNbXmJ7fnWmFZHjHb2cdlr4t1NtDJI0vtjj0G0BdLTnNMw/Bd6b5sGSxbhXPRNB5RDGSz4pHKPD8XDCX0eA3bfpqKnqG21Fd0xrOo= x"
	for _, c := range []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"no host key", func(c *Config) { c.HostKey = "" }, "host key"},
		{"short fingerprint", func(c *Config) { c.HostKey = "SHA256:abc" }, "fingerprint"},
		{"md5 fingerprint", func(c *Config) { c.HostKey = "MD5:aa:bb" }, "host key"},
		{"cert authority", func(c *Config) { c.HostKey = "@cert-authority * " + f.h.pubLine() }, "host key"},
		{"two lines", func(c *Config) { c.HostKey = f.h.pubLine() + f.h.pubLine() }, "host key"},
		{"dsa host key", func(c *Config) { c.HostKey = dsa }, "host key"},
		{"url host", func(c *Config) { c.Host = "ssh://h.example.com" }, "host"},
		{"port in host", func(c *Config) { c.Host = "h.example.com:22" }, "host"},
		{"zone", func(c *Config) { c.Host = "fe80::1%eth0" }, "zone"},
		{"port 70000", func(c *Config) { c.Port = 70000 }, "port"},
		{"bad user", func(c *Config) { c.Username = "a b; id" }, "user"},
		{"empty user", func(c *Config) { c.Username = "" }, "user"},
		{"not a key", func(c *Config) { c.Key = connsync.NewSecret("hunter2-secret") }, "private key"},
		{"passphrase key", func(c *Config) { c.Key = connsync.NewSecret(encrypted) }, "private key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			conf := f.conf
			c.mut(&conf)
			_, err := New(conf, devRT, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "BEGIN") {
				t.Fatalf("the error quotes the credential: %v", err)
			}
		})
	}
}

func encryptedKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	return nil, string(pem.EncodeToMemory(blk))
}

// TestAddressPolicy: with no test dialer the socket goes through the safehttp address policy.
func TestAddressPolicy(t *testing.T) {
	f := newFixture(t, fullOutputs())
	for _, c := range []struct {
		name string
		rt   connsync.Runtime
		host string
	}{
		{"loopback in prod", connsync.Runtime{Env: config.Prod}, "127.0.0.1"},
		{"loopback in dev without the exception", connsync.Runtime{Env: config.Dev}, "127.0.0.1"},
		{"private", devRT, "10.1.2.3"},
		{"private 192.168", connsync.Runtime{Env: config.Prod}, "192.168.1.10"},
		{"link-local", devRT, "169.254.1.1"},
		{"metadata", devRT, "169.254.169.254"},
		{"ipv6 loopback in prod", connsync.Runtime{Env: config.Prod}, "::1"},
		{"ipv6 unique local", devRT, "fd00:ec2::254"},
		{"numeric form", devRT, "2130706433"},
	} {
		t.Run(c.name, func(t *testing.T) {
			conf := f.conf
			conf.Host = c.host
			cn, err := New(conf, c.rt, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = cn.Read(ctx)
			if err == nil || !errors.Is(err, safehttp.ErrBlockedAddress) && !errors.Is(err, safehttp.ErrURL) {
				t.Fatalf("err = %v, want a blocked address", err)
			}
		})
	}
	// only the configured port is dialled
	conf := f.conf
	conf.Port = 1
	cn, _ := New(conf, devRT, nil)
	if _, err := cn.Read(context.Background()); err == nil {
		t.Error("a closed port answered")
	}
}

func TestProbeLikeRead(t *testing.T) {
	f := newFixture(t, fullOutputs())
	c, err := New(f.conf, devRT, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Accounts) != 5 || len(snap.Groups) != 6 || len(snap.Rules) != 4 || !snap.SudoersRead || c.Identity() != "tessera" {
		t.Errorf("accounts %d groups %d rules %d", len(snap.Accounts), len(snap.Groups), len(snap.Rules))
	}
}

func TestConfigFromEnv(t *testing.T) {
	f := newFixture(t, nil)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	good := map[string]string{"TESSERA_UNIXSSH_HOST": "h.example.com", "TESSERA_UNIXSSH_USER": "tessera", "TESSERA_UNIXSSH_HOST_KEY": f.h.fingerprint(),
		"TESSERA_UNIXSSH_KEY": "env:K", "K": f.key, "TESSERA_UNIXSSH_PORT": "2222", "TESSERA_UNIXSSH_SUDO": "true"}
	cfg, err := ConfigFromEnv(env(good))
	if err != nil || cfg.Port != 2222 || !cfg.UseSudo || cfg.Host != "h.example.com" || cfg.Username != "tessera" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := New(cfg, connsync.Runtime{Env: config.Prod}, nil); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"TESSERA_UNIXSSH_PORT": "0", "TESSERA_UNIXSSH_SUDO": "maybe", "TESSERA_UNIXSSH_KEY": "", "K": ""} {
		bad := map[string]string{}
		for a, b := range good {
			bad[a] = b
		}
		bad[k] = v
		if _, err := ConfigFromEnv(env(bad)); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
}

// TestNoInsecureHostKeyOutsideTests keeps the rule in the code: no production file may skip
// host-key verification, shell out, or build a command from a variable.
func TestNoInsecureHostKeyOutsideTests(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{"InsecureIgnoreHostKey", "Password(", "KeyboardInteractive", "os/exec", "fmt.Sprintf(\"getent", "http.DefaultClient"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %s", f, bad)
			}
		}
		if strings.Contains(src, ".Run(") && f != "unixssh.go" {
			t.Errorf("%s runs a command", f)
		}
	}
	// every command given to run is one of the constants
	b, _ := os.ReadFile("unixssh.go")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "s.run(ctx, ") && !strings.Contains(line, "func (s *session)") {
			ok := false
			for _, c := range []string{"cmdPasswd", "cmdGroup", "sudoersCmd,", "sudoersDCmd,", "cmdLastlog"} {
				ok = ok || strings.Contains(line, "s.run(ctx, "+c)
			}
			if !ok {
				t.Errorf("run is given something other than a constant: %s", strings.TrimSpace(line))
			}
		}
	}
}
