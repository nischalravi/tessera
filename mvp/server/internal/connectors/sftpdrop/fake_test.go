package sftpdrop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// fakeServer is an in-process SSH server with an SFTP subsystem over a real directory (so symbolic
// links behave as on a real host). It refuses exec and shell requests.
type fakeServer struct {
	ln      net.Listener
	hostKey ssh.Signer
	dir     string // the real path of the served directory
}

func newKey(t testing.TB) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pem.EncodeToMemory(blk))
}

func startServer(t testing.TB, clientKey ssh.PublicKey) *fakeServer {
	t.Helper()
	hk, _ := newKey(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{ln: ln, hostKey: hk, dir: dir}
	conf := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) {
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

func (s *fakeServer) serve(c net.Conn, conf *ssh.ServerConfig) {
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
					_ = r.Reply(false, nil) // no exec, no shell
					continue
				}
				_ = r.Reply(true, nil)
				srv, err := sftp.NewServer(ch, sftp.ReadOnly())
				if err != nil {
					return
				}
				_ = srv.Serve()
				return
			}
		}()
	}
}

func (s *fakeServer) port() int           { return s.ln.Addr().(*net.TCPAddr).Port }
func (s *fakeServer) fingerprint() string { return ssh.FingerprintSHA256(s.hostKey.PublicKey()) }

func (s *fakeServer) write(t testing.TB, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshal(s ssh.Signer) []byte { return ssh.MarshalAuthorizedKey(s.PublicKey()) }

func itoa(n int) string { return strconv.Itoa(n) }
