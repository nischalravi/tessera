package ibmi_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 handshake in a test server
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ibmi"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// fakeMapepire is an in-process Mapepire server: TLS, the WebSocket upgrade
// with HTTP Basic credentials, and the connect, sql, sqlmore and sqlclose
// requests, with knobs for each way a server can misbehave.
type fakeMapepire struct {
	addr  string
	pool  *x509.CertPool
	rows  []map[string]any
	reqs  []map[string]any // what the client sent after the upgrade
	mu    sync.Mutex
	ready chan struct{}
	once  sync.Once
	user  string
	pass  string
	hello func(w net.Conn) bool // overrides the upgrade; true if it handled the connection
	// reply overrides the reply bytes (a raw frame) for a request type.
	reply map[string]func(req map[string]any) []byte
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ibmi.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func frame(op byte, fin bool, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	h := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		h = append(h, byte(n))
	case n <= 0xFFFF:
		h = append(h, 126, byte(n>>8), byte(n))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	return append(h, payload...)
}

func text(s string) []byte { return frame(1, true, []byte(s)) }

func newFake(t *testing.T) *fakeMapepire {
	t.Helper()
	cert, pool := selfSigned(t)
	f := &fakeMapepire{ready: make(chan struct{}), pool: pool, user: "TESSERA", pass: "s3cret", reply: map[string]func(map[string]any) []byte{}}
	for i := 0; i < 5; i++ {
		f.rows = append(f.rows, map[string]any{"AUTHORIZATION_NAME": fmt.Sprintf("USER%d", i), "STATUS": "*ENABLED", "USER_CLASS_NAME": "*USER",
			"SPECIAL_AUTHORITIES": "*JOBCTL *SAVSYS", "GROUP_PROFILE_NAME": "PAYGRP", "SUPPLEMENTAL_GROUP_LIST": "DEVGRP OPSGRP", "TEXT_DESCRIPTION": "User"})
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close(); f.start() })
	go func() {
		<-f.ready // the test has finished configuring the fake
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeMapepire) start() { f.once.Do(func() { close(f.ready) }) }

func (f *fakeMapepire) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// Never close before the client does. A server that replies and closes
	// while the client's request is unread or still in flight resets the TCP
	// connection, and the client can then see a connection error instead of
	// the reply the case is about; under load that raced. The client always
	// closes after a failed call (and the deadline bounds the wait).
	defer func() { _, _ = io.Copy(io.Discard, c) }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br) // the upgrade request is read before any reply, hello included
	if err != nil {
		return
	}
	if f.hello != nil && f.hello(c) {
		return
	}
	u, p, ok := req.BasicAuth()
	if !ok || u != f.user || p != f.pass {
		_, _ = io.WriteString(c, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+
		base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
	cursor := 0
	for {
		m, err := readClient(br)
		if err != nil {
			return
		}
		var r map[string]any
		if json.Unmarshal(m, &r) != nil {
			return
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.mu.Unlock()
		typ, _ := r["type"].(string)
		id, _ := r["id"].(string)
		if h, ok := f.reply[typ]; ok {
			if b := h(r); b != nil {
				_, _ = c.Write(b)
			}
			continue
		}
		var out map[string]any
		switch typ {
		case "connect":
			out = map[string]any{"id": id, "success": true, "job": "123456/QUSER/QZDASOINIT"}
		case "sql", "sqlmore":
			if typ == "sql" {
				cursor = 0
			}
			n := int(r["rows"].(float64))
			end := min(cursor+n, len(f.rows))
			out = map[string]any{"id": id, "success": true, "data": f.rows[cursor:end], "is_done": end == len(f.rows), "execution_time": 3}
			cursor = end
		case "sqlclose":
			out = map[string]any{"id": id, "success": true}
		default:
			out = map[string]any{"id": id, "success": false, "error": "SERVER-SECRET-TEXT"}
		}
		b, _ := json.Marshal(out)
		_, _ = c.Write(text(string(b)))
	}
}

// readClient reads one masked client text frame.
func readClient(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint64(e[:]))
	}
	if h[1]&0x80 == 0 {
		return nil, errors.New("client frame not masked")
	}
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] ^= mask[i%4]
	}
	if h[0]&0x0F == 8 {
		return nil, io.EOF
	}
	return b, nil
}

// spec is a job spec for the fake, with an agent-style Dialer: prod, agent
// local, the fake's address allowlisted (it is loopback), TLS roots set.
func (f *fakeMapepire) spec(t *testing.T) agent.ProberSpec {
	t.Helper()
	host, port, _ := net.SplitHostPort(f.addr)
	allow, err := safedial.ParseAllow(net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	d, err := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: allow, RootCAs: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	var p int
	_, _ = fmt.Sscan(port, &p)
	return agent.ProberSpec{Target: agent.Target{Host: host, Port: p}, Config: agent.ProbeConfig{BindDN: f.user}, Password: f.pass, RootCAs: f.pool, Dialer: d}
}

func read(t *testing.T, f *fakeMapepire, s agent.ProberSpec, max int, timeout time.Duration) ([]ibmi.Profile, error) {
	t.Helper()
	f.start()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	src, err := ibmi.OpenMapepire(ctx, s)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	return src.Profiles(ctx, max)
}

func TestMapepire_Success(t *testing.T) {
	f := newFake(t)
	ps, err := read(t, f, f.spec(t), 100, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 5 || ps[2].Name != "USER2" || ps[2].Status != "*ENABLED" || ps[2].UserClass != "*USER" || ps[2].GroupProfile != "PAYGRP" ||
		strings.Join(ps[2].SpecialAuthorities, ",") != "*JOBCTL,*SAVSYS" || strings.Join(ps[2].SupplementalGroups, ",") != "DEVGRP,OPSGRP" {
		t.Fatalf("profiles %+v", ps)
	}
	// Only the fixed requests were sent: a read-only connect and one SELECT.
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reqs[0]["type"] != "connect" || f.reqs[0]["props"] != "access=read only" {
		t.Errorf("connect %v", f.reqs[0])
	}
	sql, _ := f.reqs[1]["sql"].(string)
	if f.reqs[1]["type"] != "sql" || !strings.HasPrefix(sql, "SELECT ") || !strings.Contains(sql, "FROM QSYS2.USER_INFO") || strings.Contains(sql, ";") {
		t.Errorf("sql %v", f.reqs[1])
	}
	for _, r := range f.reqs {
		switch r["type"] {
		case "connect", "sql", "sqlmore", "sqlclose":
		default:
			t.Errorf("unexpected request type %v", r["type"])
		}
	}
}

func TestMapepire_PagesAndCaps(t *testing.T) {
	f := newFake(t)
	f.rows = nil
	for i := 0; i < 450; i++ {
		f.rows = append(f.rows, map[string]any{"AUTHORIZATION_NAME": fmt.Sprintf("U%d", i)})
	}
	ps, err := read(t, f, f.spec(t), 450, 5*time.Second)
	if err != nil || len(ps) != 450 {
		t.Fatalf("%d profiles, %v", len(ps), err)
	}
	f.mu.Lock()
	more := 0
	for _, r := range f.reqs {
		if r["type"] == "sqlmore" {
			more++
		}
	}
	f.mu.Unlock()
	if more != 2 {
		t.Errorf("%d sqlmore requests, want 2", more)
	}
	// One over the cap is ErrTooLarge, never a cut-off list, and the cursor is closed.
	f2 := newFake(t)
	f2.rows = f.rows
	if ps, err := read(t, f2, f2.spec(t), 449, 5*time.Second); !errors.Is(err, ibmi.ErrTooLarge) || ps != nil {
		t.Errorf("over the cap: %d profiles, %v", len(ps), err)
	}
}

func TestMapepire_Failures(t *testing.T) {
	huge := text(`{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"` + strings.Repeat("A", 5<<20) + `"}],"is_done":true}`)
	tests := []struct {
		name  string
		setup func(f *fakeMapepire, s *agent.ProberSpec)
		want  error
	}{
		{"wrong password", func(f *fakeMapepire, s *agent.ProberSpec) { s.Password = "nope" }, ibmi.ErrLogin},
		{"empty password", func(f *fakeMapepire, s *agent.ProberSpec) { s.Password = "" }, ibmi.ErrLogin},
		{"bad profile name", func(f *fakeMapepire, s *agent.ProberSpec) { s.Config.BindDN = "a:b" }, ibmi.ErrLogin},
		{"connect refused by job", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["connect"] = func(r map[string]any) []byte {
				return text(fmt.Sprintf(`{"id":%q,"success":false,"error":"SERVER-SECRET-TEXT"}`, r["id"]))
			}
		}, ibmi.ErrLogin},
		{"not json", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return text("not json{") }
		}, ibmi.ErrProtocol},
		{"wrong id", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return text(`{"id":"zzz","success":true,"is_done":true}`) }
		}, ibmi.ErrProtocol},
		{"sql failed", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(r map[string]any) []byte {
				return text(fmt.Sprintf(`{"id":%q,"success":false,"error":"SERVER-SECRET-TEXT","sql_rc":-551}`, r["id"]))
			}
		}, ibmi.ErrProtocol},
		{"column of wrong type", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.rows = []map[string]any{{"AUTHORIZATION_NAME": 7}}
		}, ibmi.ErrProtocol},
		{"missing name", func(f *fakeMapepire, s *agent.ProberSpec) { f.rows = []map[string]any{{"STATUS": "*ENABLED"}} }, ibmi.ErrProtocol},
		{"binary frame", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return frame(2, true, []byte("x")) }
		}, ibmi.ErrProtocol},
		{"masked server frame", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return []byte{0x81, 0x81, 1, 2, 3, 4, 5} }
		}, ibmi.ErrProtocol},
		{"reserved bit", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return []byte{0xC1, 0x00} }
		}, ibmi.ErrProtocol},
		{"cursor never ends", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(r map[string]any) []byte {
				return text(fmt.Sprintf(`{"id":%q,"success":true,"data":[],"is_done":false}`, r["id"]))
			}
		}, ibmi.ErrProtocol},
		{"oversized reply", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return huge }
		}, ibmi.ErrOversize},
		{"oversized frame header", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return []byte{0x81, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} }
		}, ibmi.ErrOversize},
		{"server closes", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.reply["sql"] = func(map[string]any) []byte { return frame(8, true, []byte{0x03, 0xE8}) }
		}, ibmi.ErrClosed},
		{"no upgrade", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.hello = func(c net.Conn) bool {
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				return true
			}
		}, ibmi.ErrProtocol},
		{"bad accept key", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.hello = func(c net.Conn) bool {
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n")
				return true
			}
		}, ibmi.ErrProtocol},
		{"endless upgrade headers", func(f *fakeMapepire, s *agent.ProberSpec) {
			f.hello = func(c net.Conn) bool {
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n")
				for i := 0; i < 5000; i++ {
					if _, err := io.WriteString(c, "X-Pad: "+strings.Repeat("a", 100)+"\r\n"); err != nil {
						break
					}
				}
				return true
			}
		}, ibmi.ErrProtocol},
		{"untrusted certificate", func(f *fakeMapepire, s *agent.ProberSpec) {
			d, _ := safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, Allow: mustAllow(t, f.addr)})
			s.Dialer = d // no CA configured: the self-signed certificate must be refused
		}, ibmi.ErrTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			s := f.spec(t)
			tt.setup(f, &s)
			_, err := read(t, f, s, 100, 5*time.Second)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error %v, want %v", err, tt.want)
			}
			// Fixed error text: no server message, credential or address.
			for _, leak := range []string{"SERVER-SECRET-TEXT", "s3cret", "nope", "127.0.0.1"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q leaks %q", err, leak)
				}
			}
		})
	}
}

func mustAllow(t *testing.T, addr string) []safedial.AllowEntry {
	t.Helper()
	a, err := safedial.ParseAllow(addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMapepire_SlowServer(t *testing.T) {
	f := newFake(t)
	f.reply["sql"] = func(map[string]any) []byte { return nil } // never answers
	start := time.Now()
	_, err := read(t, f, f.spec(t), 100, 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("slow server: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// A server that stalls before the upgrade is bounded by the same deadline.
	f2 := newFake(t)
	f2.hello = func(c net.Conn) bool { time.Sleep(2 * time.Second); return true }
	if _, err := read(t, f2, f2.spec(t), 100, 300*time.Millisecond); err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("stalled upgrade: %v", err)
	}
}

// TestMapepire_RefusesWhatTheDialerRefuses: the transport has no network path
// of its own. A non-allowlisted private host, a blocked address and a port the
// policy refuses are never connected to.
func TestMapepire_RefusesWhatTheDialerRefuses(t *testing.T) {
	f := newFake(t)
	for _, tt := range []struct {
		name string
		edit func(s *agent.ProberSpec)
	}{
		{"loopback not on the allowlist", func(s *agent.ProberSpec) {
			s.Dialer, _ = safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, RootCAs: f.pool})
		}},
		{"other allowlisted port only", func(s *agent.ProberSpec) {
			s.Dialer, _ = safedial.New(safedial.Options{Env: config.Prod, AgentLocal: true, RootCAs: f.pool, Allow: mustAllow(t, "127.0.0.1:9999")})
		}},
		{"cloud metadata", func(s *agent.ProberSpec) { s.Target.Host = "169.254.169.254" }},
		{"port below 1024", func(s *agent.ProberSpec) { s.Target.Port = 80 }},
		{"database port", func(s *agent.ProberSpec) { s.Target.Port = 5432 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := f.spec(t)
			tt.edit(&s)
			_, err := read(t, f, s, 10, 2*time.Second)
			if !errors.Is(err, ibmi.ErrRefused) {
				t.Errorf("error %v, want ErrRefused", err)
			}
		})
	}
	if _, err := ibmi.OpenMapepire(context.Background(), agent.ProberSpec{Config: agent.ProbeConfig{BindDN: "X"}, Password: "p"}); !errors.Is(err, ibmi.ErrNoDriver) {
		t.Errorf("no dialer: %v", err)
	}
	f.mu.Lock()
	n := len(f.reqs)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("a refused target still reached the server (%d requests)", n)
	}
}

// TestMapepire_ThroughModule: the module maps what the transport reads, and a
// transport failure reaches the agent as a fixed error.
func TestMapepire_ThroughModule(t *testing.T) {
	f := newFake(t)
	f.start()
	sy, err := ibmi.Module(ibmi.OpenMapepire).New(f.spec(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := sy.Discover(context.Background(), lim)
	if err != nil || len(res.Accounts) != 5 {
		t.Fatalf("%v %+v", err, res)
	}
	s := f.spec(t)
	s.Password = "wrong-password"
	sy, _ = ibmi.Module(ibmi.OpenMapepire).New(s)
	if _, err := sy.Discover(context.Background(), lim); !errors.Is(err, ibmi.ErrLogin) || strings.Contains(err.Error(), "wrong-password") {
		t.Errorf("auth failure: %v", err)
	}
}
