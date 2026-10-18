package ldap

// A small in-process LDAP server for tests (test-only, loopback). It speaks
// just enough LDAPv3 over BER (github.com/go-asn1-ber/asn1-ber) for the probe:
// simple bind, search with paging and size limits, Who Am I, StartTLS and the
// Get Effective Rights control. Every operation is recorded; any operation
// that is not a bind, search, Who Am I, StartTLS or unbind is a "write" and
// is what TestProbers_ReadOnly fails on.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

type fakeEntry struct {
	DN    string              `json:"dn"`
	Attrs map[string][]string `json:"attrs"`
}

// fakeDir describes a directory server's data and behaviour. Fixtures under
// testdata/ are JSON of this shape.
type fakeDir struct {
	Name    string              `json:"name"`
	RootDSE map[string][]string `json:"rootdse"`
	Entries []fakeEntry         `json:"entries"`
	// Users maps a bind DN to its password.
	Users map[string]string `json:"users"`
	// WhoAmI: the server implements RFC 4532.
	WhoAmI bool `json:"whoami"`
	// Paged: the server honours the paged-results control.
	Paged bool `json:"paged"`
	// SizeLimit is the server's per-search (per-page when paged) limit for
	// non-root binds; 0 means none.
	SizeLimit int `json:"size_limit"`
	// GER: the server honours Get Effective Rights. GERWrite lists DNs of
	// bind identities that have write rights.
	GER      bool     `json:"ger"`
	GERWrite []string `json:"ger_write"`
	// RootBinds are bind DNs that bypass the size limit (the rootDN).
	RootBinds []string `json:"root_binds"`
	// NoStartTLS: the server refuses StartTLS.
	NoStartTLS bool `json:"no_starttls"`
}

func loadFixture(t *testing.T, name string) *fakeDir {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var d fakeDir
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &d
}

var operational = map[string]bool{"entryuuid": true, "createtimestamp": true, "modifytimestamp": true, "nsuniqueid": true,
	"memberof": true, "pwdendtime": true, "passwordexpirationtime": true, "entrylevelrights": true, "attributelevelrights": true}

type fakeServer struct {
	d      *fakeDir
	cfg    *tls.Config
	plain  net.Listener
	secure net.Listener

	mu          sync.Mutex
	ops         []string
	writes      []string
	plainBinds  int // binds received on a connection that was not TLS
	bindPasswds []string
	conns       sync.WaitGroup
	closeOnce   sync.Once
	closed      chan struct{}
	searchBases []string
	inflight    int // searches currently held by holdSearch
	maxInflight int
	holdSearch  chan struct{} // when set, searches wait on it (concurrency test)
}

func startFake(t *testing.T, d *fakeDir, cfg *tls.Config) *fakeServer {
	t.Helper()
	s := &fakeServer{d: d, cfg: cfg, closed: make(chan struct{})}
	var err error
	if s.plain, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if s.secure, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go s.accept(s.plain, false)
	go s.accept(s.secure, true)
	t.Cleanup(s.close)
	return s
}

func (s *fakeServer) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.plain.Close()
		_ = s.secure.Close()
	})
}

func (s *fakeServer) accept(l net.Listener, secure bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.serve(c, secure)
	}
}

func (s *fakeServer) record(op string, write bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, op)
	if write {
		s.writes = append(s.writes, op)
	}
}

func (s *fakeServer) snapshot() (ops, writes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...), append([]string(nil), s.writes...)
}

// transport sends every dial to this server: port 636 to the TLS listener,
// anything else to the plain one (which can upgrade with StartTLS).
type fakeTransport struct{ s *fakeServer }

func (f fakeTransport) DialTarget(ctx context.Context, _ string, port int) (net.Conn, error) {
	addr := f.s.plain.Addr().String()
	if port == 636 {
		addr = f.s.secure.Addr().String()
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func str(p *ber.Packet) string {
	if v, ok := p.Value.(string); ok {
		return v
	}
	if p.Data != nil {
		return p.Data.String()
	}
	return ""
}

func num(p *ber.Packet) int64 {
	switch v := p.Value.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	}
	return 0
}

func result(op ber.Tag, code int, diag string, extra ...*ber.Packet) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, op, nil, "")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, ""))
	for _, e := range extra {
		r.AppendChild(e)
	}
	return r
}

func envelope(id int64, op *ber.Packet, controls ...*ber.Packet) []byte {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	m.AppendChild(op)
	if len(controls) > 0 {
		c := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
		for _, x := range controls {
			c.AppendChild(x)
		}
		m.AppendChild(c)
	}
	return m.Bytes()
}

type reqControl struct {
	oid   string
	value []byte
}

func (s *fakeServer) serve(raw net.Conn, secure bool) {
	var conn net.Conn = raw
	if secure {
		tc := tls.Server(raw, s.cfg)
		if tc.Handshake() != nil {
			_ = raw.Close()
			return
		}
		conn = tc
	}
	defer func() { _ = conn.Close() }()
	var bindDN string
	encrypted := secure
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id := num(p.Children[0])
		op := p.Children[1]
		var controls []reqControl
		if len(p.Children) > 2 {
			for _, c := range p.Children[2].Children {
				rc := reqControl{oid: str(c.Children[0])}
				if n := len(c.Children); n > 1 {
					rc.value = []byte(str(c.Children[n-1]))
				}
				controls = append(controls, rc)
			}
		}
		write := func(b []byte) bool { _, err := conn.Write(b); return err == nil }
		switch op.Tag {
		case 0: // bind
			s.record("bind", false)
			dn, pw := str(op.Children[1]), str(op.Children[2])
			s.mu.Lock()
			if !encrypted {
				s.plainBinds++
			}
			s.bindPasswds = append(s.bindPasswds, pw)
			s.mu.Unlock()
			want, known := s.d.Users[strings.ToLower(dn)]
			switch {
			case pw == "" && dn == "":
				bindDN = ""
				write(envelope(id, result(1, 0, "")))
			case known && want == pw && pw != "":
				bindDN = dn
				write(envelope(id, result(1, 0, "")))
			default:
				write(envelope(id, result(1, 49, "invalid credentials")))
			}
		case 2: // unbind
			s.record("unbind", false)
			return
		case 3: // search
			s.record("search", false)
			if !write(s.search(id, op, controls, bindDN)) {
				return
			}
		case 23: // extended
			oid := str(op.Children[0])
			switch oid {
			case "1.3.6.1.4.1.1466.20037":
				s.record("starttls", false)
				if s.d.NoStartTLS || s.cfg == nil {
					write(envelope(id, result(24, 2, "StartTLS not supported")))
					continue
				}
				if !write(envelope(id, result(24, 0, ""))) {
					return
				}
				tc := tls.Server(conn, s.cfg)
				if tc.Handshake() != nil {
					return
				}
				conn, encrypted = tc, true
			case "1.3.6.1.4.1.4203.1.11.3":
				s.record("whoami", false)
				if !s.d.WhoAmI {
					write(envelope(id, result(24, 2, "unsupported extended operation")))
					continue
				}
				authz := ""
				if bindDN != "" {
					authz = "dn:" + strings.ToLower(bindDN)
				}
				val := ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, authz, "")
				write(envelope(id, result(24, 0, "", val)))
			default:
				s.record("extended:"+oid, true)
				write(envelope(id, result(24, 53, "refused")))
			}
		default:
			s.record(fmt.Sprintf("op%d", op.Tag), true) // add 8, modify 6, delete 10, modrdn 12, compare 14
			write(envelope(id, result(op.Tag+1, 50, "insufficient access")))
		}
	}
}

func normDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, ",")
}

func inScope(base, dn string, scope int64) bool {
	b, d := normDN(base), normDN(dn)
	switch scope {
	case 0:
		return b == d
	case 1:
		i := strings.Index(d, ",")
		return i > 0 && d[i+1:] == b
	}
	return d == b || strings.HasSuffix(d, ","+b) || b == ""
}

func (s *fakeServer) search(id int64, op *ber.Packet, controls []reqControl, bindDN string) []byte {
	base, scope := str(op.Children[0]), num(op.Children[1])
	sizeLimit, typesOnly := int(num(op.Children[3])), false
	if v, ok := op.Children[5].Value.(bool); ok {
		typesOnly = v
	}
	filter, err := goldap.DecompileFilter(op.Children[6])
	if err != nil {
		return envelope(id, result(5, 2, "bad filter"))
	}
	var attrs []string
	for _, a := range op.Children[7].Children {
		attrs = append(attrs, str(a))
	}
	s.mu.Lock()
	s.searchBases = append(s.searchBases, base)
	s.mu.Unlock()

	var matches []fakeEntry
	if base == "" && scope == 0 {
		matches = []fakeEntry{{DN: "", Attrs: s.d.RootDSE}}
	} else {
		for _, e := range s.d.Entries {
			if inScope(base, e.DN, scope) && matchFilter(filter, e.Attrs) {
				matches = append(matches, e)
			}
		}
		if len(matches) == 0 {
			exists := false
			for _, e := range s.d.Entries {
				if normDN(e.DN) == normDN(base) {
					exists = true
				}
			}
			if !exists && scope == 0 {
				return envelope(id, result(5, 32, "no such object"))
			}
		}
	}
	isRoot := false
	for _, r := range s.d.RootBinds {
		if strings.EqualFold(r, bindDN) {
			isRoot = true
		}
	}
	if strings.HasSuffix(normDN(base), "cn=config") && !isRoot { // the config database is root-only
		return envelope(id, result(5, 50, "insufficient access"))
	}
	if s.holdSearch != nil { // requests in flight, not sockets (a closed one lingers server-side)
		s.mu.Lock()
		s.inflight++
		s.maxInflight = max(s.maxInflight, s.inflight)
		s.mu.Unlock()
		<-s.holdSearch
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}
	// Paged results, when the server honours the control.
	var pageSize, offset int
	paged := false
	ger := false
	for _, c := range controls {
		switch c.oid {
		case goldap.ControlTypePaging:
			if s.d.Paged {
				pk := ber.DecodePacket(c.value)
				pageSize = int(num(pk.Children[0]))
				if ck := str(pk.Children[1]); ck != "" {
					offset, _ = strconv.Atoi(ck)
				}
				paged = true
			}
		case "1.3.6.1.4.1.42.2.27.9.5.2":
			ger = s.d.GER
		}
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].DN < matches[j].DN })
	limit := sizeLimit
	if s.d.SizeLimit > 0 && !isRoot && (limit == 0 || s.d.SizeLimit < limit) {
		limit = s.d.SizeLimit
	}
	code := 0
	next := ""
	if paged {
		if offset > len(matches) {
			offset = len(matches)
		}
		matches = matches[offset:]
		if len(matches) > pageSize {
			matches = matches[:pageSize]
			next = strconv.Itoa(offset + pageSize)
		}
		if limit > 0 && len(matches) > limit {
			matches, code, next = matches[:limit], 4, ""
		}
	} else if limit > 0 && len(matches) > limit {
		matches, code = matches[:limit], 4
	}
	var out bytes.Buffer
	for _, e := range matches {
		entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
		entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, ""))
		list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for name, vals := range s.pick(e, attrs, ger, bindDN) {
			a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			if !typesOnly {
				for _, v := range vals {
					set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
				}
			}
			a.AppendChild(set)
			list.AppendChild(a)
		}
		entry.AppendChild(list)
		out.Write(envelope(id, entry))
	}
	var ctrls []*ber.Packet
	if paged {
		val := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		val.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(len(s.d.Entries)), ""))
		val.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, next, ""))
		c := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, goldap.ControlTypePaging, ""))
		c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(val.Bytes()), ""))
		ctrls = append(ctrls, c)
	}
	out.Write(envelope(id, result(5, code, ""), ctrls...))
	return out.Bytes()
}

// pick returns the attributes a search asks for. Operational attributes are
// returned only when named (or "+"); "1.1" returns none.
func (s *fakeServer) pick(e fakeEntry, req []string, ger bool, bindDN string) map[string][]string {
	out := map[string][]string{}
	want := map[string]bool{}
	all, plus := len(req) == 0, false
	for _, a := range req {
		switch a {
		case "*":
			all = true
		case "+":
			plus = true
		case "1.1":
		default:
			want[strings.ToLower(a)] = true
		}
	}
	for name, vals := range e.Attrs {
		l := strings.ToLower(name)
		if want[l] || (all && !operational[l]) || (plus && operational[l]) {
			out[name] = vals
		}
	}
	if ger && (want["entrylevelrights"] || want["attributelevelrights"]) && e.DN != "" {
		rights, el := "uid:rsc, cn:rsc, mail:rsc", "v"
		for _, w := range s.d.GERWrite {
			if strings.EqualFold(w, bindDN) {
				rights, el = "uid:rscwo, cn:rscwo, mail:rscwo", "vadn"
			}
		}
		out["entryLevelRights"] = []string{el}
		out["attributeLevelRights"] = []string{rights}
	}
	return out
}

// ---------------------------------------------------------------- filters

func matchFilter(f string, attrs map[string][]string) bool {
	ok, rest := evalFilter(strings.TrimSpace(f), attrs)
	return ok && rest == ""
}

func evalFilter(f string, attrs map[string][]string) (bool, string) {
	if !strings.HasPrefix(f, "(") {
		return false, f
	}
	f = f[1:]
	switch f[0] {
	case '&', '|':
		op := f[0]
		f = f[1:]
		res := op == '&'
		for strings.HasPrefix(f, "(") {
			var ok bool
			ok, f = evalFilter(f, attrs)
			if op == '&' {
				res = res && ok
			} else {
				res = res || ok
			}
		}
		return res, strings.TrimPrefix(f, ")")
	case '!':
		ok, rest := evalFilter(f[1:], attrs)
		return !ok, strings.TrimPrefix(rest, ")")
	}
	end := strings.Index(f, ")")
	item, rest := f[:end], f[end+1:]
	name, val, _ := strings.Cut(item, "=")
	var have []string
	for k, v := range attrs {
		if strings.EqualFold(k, name) {
			have = v
		}
	}
	if val == "*" {
		return len(have) > 0, rest
	}
	for _, v := range have {
		if strings.EqualFold(v, val) {
			return true, rest
		}
	}
	return false, rest
}
