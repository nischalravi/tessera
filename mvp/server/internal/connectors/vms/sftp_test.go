package vms

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/unixssh"
)

const (
	sftpPassword = "hunter2-correct-horse"
	sftpGoodCSV  = "worker_id,name,email,sponsor_email,end_date\nW1,Casey,casey@agency.example,dana@corp.example,2027-01-31\n"
)

// sftpServer is an in-process SSH server with an SFTP subsystem over a real directory. It accepts
// one password and one client key, and refuses exec and shell requests.
type sftpServer struct {
	ln      net.Listener
	hostKey ssh.Signer
	dir     string
}

func newSigner(t testing.TB) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sg, string(pem.EncodeToMemory(blk))
}

func startSFTP(t testing.TB, clientKey ssh.PublicKey) *sftpServer {
	t.Helper()
	hk, _ := newSigner(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sftpServer{ln: ln, hostKey: hk, dir: dir}
	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "feeds" && string(pw) == sftpPassword {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if clientKey != nil && c.User() == "feeds" && string(k.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, os.ErrPermission
		}}
	conf.AddHostKey(hk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, conf)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return s
}

func (s *sftpServer) serve(c net.Conn, conf *ssh.ServerConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, conf)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				if r.Type != "subsystem" || len(r.Payload) < 4 || string(r.Payload[4:]) != "sftp" {
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(true, nil)
				if srv, err := sftp.NewServer(ch, sftp.ReadOnly()); err == nil {
					_ = srv.Serve()
				}
				return
			}
		}()
	}
}

func (s *sftpServer) port() int           { return s.ln.Addr().(*net.TCPAddr).Port }
func (s *sftpServer) fingerprint() string { return ssh.FingerprintSHA256(s.hostKey.PublicKey()) }

func (s *sftpServer) write(t testing.TB, name, content string) string {
	t.Helper()
	p := filepath.Join(s.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *sftpServer) fetcher(auth, cred, file string) *SFTPFetcher {
	return &SFTPFetcher{
		SFTP: SFTPSettings{Host: "127.0.0.1", Port: s.port(), Path: s.dir + "/" + file, Username: "feeds",
			HostKey: s.fingerprint(), Auth: auth},
		Credential: connsync.NewSecret(cred), RT: connsynctest.Runtime,
		Now: func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }}
}

func TestSFTPFetch(t *testing.T) {
	ck, keyPEM := newSigner(t)
	srv := startSFTP(t, ck.PublicKey())
	srv.write(t, "contractors.csv", sftpGoodCSV)
	srv.write(t, "binary.csv", "worker_id,name\n\x00\x01\x02\xff\xfe")
	srv.write(t, "notes.csv", "hello,world\n1,2\n")
	srv.write(t, "big.csv", "worker_id,name,email\n"+strings.Repeat("x", MaxCSVBytes+10))
	if err := os.Symlink(srv.dir+"/contractors.csv", srv.dir+"/link.csv"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(srv.dir+"/sub", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(srv.dir+"/sub", srv.dir+"/linkdir"); err != nil {
		t.Fatal(err)
	}
	srv.write(t, "sub/c.csv", sftpGoodCSV)
	sum := sha256.Sum256([]byte(sftpGoodCSV))

	tests := []struct {
		name  string
		auth  string
		cred  string
		file  string
		edit  func(f *SFTPFetcher)
		want  error  // errors.Is
		text  string // or a substring of the error
		count int
	}{
		{name: "password", auth: SFTPPassword, cred: sftpPassword, file: "contractors.csv", count: 1},
		{name: "private key", auth: SFTPKey, cred: keyPEM, file: "contractors.csv", count: 1},
		{name: "wrong password", auth: SFTPPassword, cred: "nope-nope", file: "contractors.csv", want: unixssh.ErrRefused},
		{name: "key not accepted", auth: SFTPKey, cred: func() string { _, k := newSigner(t); return k }(), file: "contractors.csv", want: unixssh.ErrRefused},
		{name: "wrong host key", auth: SFTPPassword, cred: sftpPassword, file: "contractors.csv", want: unixssh.ErrHostKey,
			edit: func(f *SFTPFetcher) {
				other, _ := newSigner(t)
				f.SFTP.HostKey = ssh.FingerprintSHA256(other.PublicKey())
			}},
		{name: "no host key", auth: SFTPPassword, cred: sftpPassword, file: "contractors.csv", text: "host key",
			edit: func(f *SFTPFetcher) { f.SFTP.HostKey = "" }},
		{name: "traversal in path", auth: SFTPPassword, cred: sftpPassword, file: "sub/../contractors.csv", text: "no . or .."},
		{name: "traversal out of dir", auth: SFTPPassword, cred: sftpPassword, file: "../etc/passwd.csv", text: "no . or .."},
		{name: "not a csv name", auth: SFTPPassword, cred: sftpPassword, file: "contractors.txt", text: ".csv"},
		{name: "symlinked file", auth: SFTPPassword, cred: sftpPassword, file: "link.csv", want: ErrSFTPFile},
		{name: "path through a symlinked directory", auth: SFTPPassword, cred: sftpPassword, file: "linkdir/c.csv", want: ErrSFTPFile},
		{name: "missing", auth: SFTPPassword, cred: sftpPassword, file: "gone.csv", want: ErrSFTPFile},
		{name: "oversized", auth: SFTPPassword, cred: sftpPassword, file: "big.csv", want: ErrSFTPTooLarge},
		{name: "binary content", auth: SFTPPassword, cred: sftpPassword, file: "binary.csv", want: ErrCSV},
		{name: "not the feed's columns", auth: SFTPPassword, cred: sftpPassword, file: "notes.csv", want: ErrCSV},
		{name: "no credential", auth: SFTPPassword, cred: "", file: "contractors.csv", text: "no stored credential"},
		{name: "loopback refused in prod", auth: SFTPPassword, cred: sftpPassword, file: "contractors.csv", text: "connect",
			edit: func(f *SFTPFetcher) { f.RT = connsync.Runtime{Env: "prod"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := srv.fetcher(tc.auth, tc.cred, tc.file)
			if tc.edit != nil {
				tc.edit(f)
			}
			res, err := f.Fetch(context.Background())
			switch {
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
			case tc.text != "":
				if err == nil || !strings.Contains(err.Error(), tc.text) {
					t.Fatalf("err = %v, want text %q", err, tc.text)
				}
			case err != nil:
				t.Fatal(err)
			default:
				if len(res.Records) != tc.count || res.Records[0].WorkerID != "W1" || res.Records[0].SponsorEmail != "dana@corp.example" {
					t.Fatalf("records = %+v", res.Records)
				}
				if res.Digest != hex.EncodeToString(sum[:]) || res.Size != len(sftpGoodCSV) {
					t.Fatalf("digest = %s size = %d", res.Digest, res.Size)
				}
			}
			if err != nil {
				// no error quotes the credential, a path or a file's content
				for _, secret := range []string{tc.cred, srv.dir, "hello,world"} {
					if secret != "" && strings.Contains(err.Error(), secret) {
						t.Fatalf("error leaks %q: %v", secret, err)
					}
				}
			}
		})
	}
}

func TestSFTPSettingsValidate(t *testing.T) {
	good := SFTPSettings{Host: "sftp.agency.example", Port: 22, Path: "/drop/contractors.csv", Username: "feeds",
		HostKey: "SHA256:" + strings.Repeat("A", 43), Auth: SFTPPassword}
	if err := good.Validate(); err != nil {
		t.Fatalf("good settings: %v", err)
	}
	tests := []struct {
		name string
		edit func(s *SFTPSettings)
	}{
		{"no host key", func(s *SFTPSettings) { s.HostKey = "" }},
		{"garbage host key", func(s *SFTPSettings) { s.HostKey = "trust me" }},
		{"metadata host", func(s *SFTPSettings) { s.Host = "169.254.169.254" }},
		{"url as host", func(s *SFTPSettings) { s.Host = "sftp://a.example" }},
		{"bad port", func(s *SFTPSettings) { s.Port = 70000 }},
		{"relative path", func(s *SFTPSettings) { s.Path = "drop/c.csv" }},
		{"dotdot path", func(s *SFTPSettings) { s.Path = "/drop/../c.csv" }},
		{"shell in path", func(s *SFTPSettings) { s.Path = "/drop/$(x).csv" }},
		{"not csv", func(s *SFTPSettings) { s.Path = "/drop/c.sh" }},
		{"no file", func(s *SFTPSettings) { s.Path = "/c.csv/" }},
		{"bad user", func(s *SFTPSettings) { s.Username = "a b" }},
		{"bad auth", func(s *SFTPSettings) { s.Auth = "token" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			tc.edit(&s)
			if err := s.Validate(); err == nil {
				t.Fatalf("%+v was accepted", s)
			}
		})
	}
	if err := good.CheckCredential("a-password"); err != nil {
		t.Fatal(err)
	}
	key := good
	key.Auth = SFTPKey
	if err := key.CheckCredential("a-password"); err == nil || strings.Contains(err.Error(), "a-password") {
		t.Fatalf("a password as key: %v", err)
	}
}
