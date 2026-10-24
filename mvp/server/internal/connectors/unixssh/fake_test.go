package unixssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeHost is an in-process SSH server that answers a fixed table of exec requests. It never echoes
// what a client sent: an unknown command gets exit status 127 and no output, and the command is only
// recorded for the test to compare with the connector's constants.
type fakeHost struct {
	ln      net.Listener
	hostKey ssh.Signer
	allowed ssh.PublicKey // the client key the server accepts

	mu       sync.Mutex
	outputs  map[string]fakeReply
	commands []string
	auths    int
}

type fakeReply struct {
	out    string
	status uint32
	hang   bool
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

// startHost starts the server on a loopback port. clientKey is the public key it accepts.
func startHost(t testing.TB, clientKey ssh.PublicKey, outputs map[string]fakeReply) *fakeHost {
	t.Helper()
	hk, _ := newKey(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{ln: ln, hostKey: hk, allowed: clientKey, outputs: outputs}
	conf := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		h.mu.Lock()
		h.auths++
		h.mu.Unlock()
		if string(k.Marshal()) == string(h.allowed.Marshal()) {
			return nil, nil
		}
		return nil, errNoKey
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
			go h.serve(c, conf)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return h
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNoKey = constErr("key not accepted")

func (h *fakeHost) port() int {
	return h.ln.Addr().(*net.TCPAddr).Port
}

func (h *fakeHost) fingerprint() string { return ssh.FingerprintSHA256(h.hostKey.PublicKey()) }

func (h *fakeHost) pubLine() string { return string(ssh.MarshalAuthorizedKey(h.hostKey.PublicKey())) }

func (h *fakeHost) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.commands...)
}

func (h *fakeHost) authAttempts() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.auths
}

func (h *fakeHost) serve(c net.Conn, conf *ssh.ServerConfig) {
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
		go h.session(ch, creqs)
	}
}

func (h *fakeHost) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			_ = r.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		if ssh.Unmarshal(r.Payload, &p) != nil {
			_ = r.Reply(false, nil)
			continue
		}
		_ = r.Reply(true, nil)
		h.mu.Lock()
		h.commands = append(h.commands, p.Command)
		reply, ok := h.outputs[p.Command]
		h.mu.Unlock()
		if reply.hang {
			time.Sleep(10 * time.Second)
			return
		}
		status := reply.status
		if !ok {
			status = 127
		}
		_, _ = ch.Write([]byte(reply.out))
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

// portString is the port as the settings carry it.
func (h *fakeHost) portString() string { return strconv.Itoa(h.port()) }
