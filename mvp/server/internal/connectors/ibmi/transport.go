package ibmi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
)

// The live transport: Mapepire.
//
// Go's standard library cannot speak the IBM i host servers (DRDA, port 446 or
// 9471), and a DRDA client is too large to write and verify here. IBM's
// open-source Mapepire server for IBM i (github.com/Mapepire-IBMi, port 8076)
// runs the SQL on the system through JDBC and speaks JSON over a TLS WebSocket,
// which a small client can do with the standard library. What this file relies
// on, from Mapepire's published material:
//
//   - Server protocol reference, https://mapepire-ibmi.github.io/reference/maintenance/serverprotocol/:
//     JSON requests {"id","type",...}; replies carry "id" (the request's),
//     "success", "execution_time" and on failure "error" (never decoded here).
//     Types used: connect, sql ("sql", "rows"), sqlmore ("cont_id", "rows"),
//     sqlclose ("cont_id"). A reply to sql or sqlmore has "data" (an array of
//     row objects keyed by column name) and "is_done".
//   - Server install/config guide, https://mapepire-ibmi.github.io/guides/sysadmin/:
//     default port 8076, TLS always on (a self-signed certificate if none is
//     configured, so a deployment gives the agent its CA).
//   - Client source, github.com/Mapepire-IBMi/mapepire-python (websocket.py,
//     sql_job.py): wss://host:port/db/ with an "Authorization: Basic" header
//     on the upgrade request; the first message is a connect request.
//
// It has not been run against a real Mapepire server: the tests use an
// in-process fake of the same message format. Port 8076 is inside
// safedial.PortAllowed (1024 and above, not a blocked service), so the policy
// is unchanged.
//
// What the transport guarantees, whatever the server sends:
//   - It reaches the system only through the agent's safedial Dialer, over TLS
//     that verifies the chain and host name (the agent's CA bundle, if any).
//   - It is read-only: the one statement it sends is the constant userInfoSQL.
//     There is no parameter, no caller text in SQL, and the JDBC connection is
//     opened "access=read only" as a second layer.
//   - It is bounded: the row cap, a byte cap per message and in total, a page
//     cap, and a deadline on every read and write.
//   - Its errors have fixed text. The server's "error" text, and the
//     credential, are never read into an error, a log or a result.

const (
	// DefaultPort is Mapepire's port.
	DefaultPort = 8076

	wsPath = "/db/"
	// userInfoSQL is the only statement the transport sends.
	userInfoSQL = "SELECT AUTHORIZATION_NAME, STATUS, USER_CLASS_NAME, SPECIAL_AUTHORITIES, GROUP_PROFILE_NAME, " +
		"SUPPLEMENTAL_GROUP_LIST, TEXT_DESCRIPTION FROM QSYS2.USER_INFO ORDER BY AUTHORIZATION_NAME"
	// connectProps are the JDBC properties of the job: read-only access.
	connectProps = "access=read only"

	pageRows     = 200      // rows requested per round trip
	maxMessage   = 2 << 20  // bytes of one reply: pageRows rows of at most maxRowLen
	maxTotal     = 32 << 20 // bytes of all replies of one read
	maxFieldLen  = 1024     // bytes of one column value
	ioTimeout    = 20 * time.Second
	maxPassword  = 128
	maxPageTurns = 10000
)

// Fixed errors of the transport. None carries server, job or credential text.
var (
	errConnect  = errors.New("ibmi: could not connect to the system")
	errRefused  = errors.New("ibmi: the connection to that address is not allowed")
	errTLS      = errors.New("ibmi: the system's certificate could not be verified")
	errLogin    = errors.New("ibmi: the system refused the sign-in")
	errProtocol = errors.New("ibmi: the system sent a reply that is not valid")
	errOversize = errors.New("ibmi: the system's reply exceeds the size limit")
	errTimeout  = errors.New("ibmi: the system did not answer in time")
	errClosed   = errors.New("ibmi: the system closed the connection")
)

// Exported aliases so callers can test for them.
var (
	ErrConnect  = errConnect
	ErrRefused  = errRefused
	ErrTLS      = errTLS
	ErrLogin    = errLogin
	ErrProtocol = errProtocol
	ErrOversize = errOversize
	ErrTimeout  = errTimeout
	ErrClosed   = errClosed
)

// transportErrors are the errors Discover passes through unchanged; every
// other error from a Source becomes the generic read error.
var transportErrors = []error{ErrTooLarge, errConnect, errRefused, errTLS, errLogin, errProtocol, errOversize, errTimeout, errClosed}

// validHost reports a plain host name or IP literal, safe to put in the Host
// header: no CR, LF, space, "@", "/" or other syntax, whatever the dialer checked.
func validHost(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return len(h) > 0 && len(h) <= 253 && hostRE.MatchString(h)
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// userRE is an IBM i profile name the transport signs in as. It also keeps ":"
// and control characters out of the Basic credential.
var userRE = regexp.MustCompile(`^[A-Za-z#$@][A-Za-z0-9#$@_]{0,9}$`)

// OpenMapepire is the live Opener: it dials s.Target through s.Dialer, upgrades
// to a WebSocket, signs in with s.Config.BindDN (the IBM i profile) and
// s.Password, and starts a read-only job. The agent registers it for the
// "ibmi" module.
func OpenMapepire(ctx context.Context, s agent.ProberSpec) (Source, error) {
	if s.Dialer == nil {
		return nil, ErrNoDriver
	}
	user := s.Config.BindDN
	if !userRE.MatchString(user) || s.Password == "" || len(s.Password) > maxPassword || strings.ContainsAny(s.Password, "\x00\r\n") {
		return nil, errLogin
	}
	port := s.Target.Port
	if port == 0 {
		port = DefaultPort
	}
	if !validHost(s.Target.Host) {
		return nil, errRefused
	}
	// ModeLDAPS is safedial's "TLS from the first byte" mode; it verifies the
	// chain and host name against the Dialer's roots and is the only mode used.
	c, err := s.Dialer.DialMode(ctx, s.Target.Host, port, safedial.ModeLDAPS, false)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, ctx.Err()
		case errors.Is(err, safedial.ErrHandshake):
			return nil, errTLS
		case errors.Is(err, safedial.ErrBlockedAddress), errors.Is(err, safedial.ErrPort),
			errors.Is(err, safedial.ErrHost), errors.Is(err, safedial.ErrTLSMode):
			return nil, errRefused
		}
		return nil, errConnect
	}
	if !c.Secure() {
		_ = c.Close()
		return nil, errTLS
	}
	cr := &capReader{r: c, left: maxHandshake}
	m := &mapepire{ws: &wsConn{conn: c, cap: cr, rd: bufio.NewReaderSize(cr, 16<<10), timeout: ioTimeout}}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	dl, _ := ctx.Deadline()
	host := net.JoinHostPort(strings.TrimSuffix(s.Target.Host, "."), strconv.Itoa(port))
	if err := m.ws.handshake(host, wsPath, user, s.Password, dl); err != nil {
		_ = c.Close()
		return nil, m.fail(ctx, err)
	}
	if _, err := m.call(ctx, request{Type: "connect", Props: connectProps}); err != nil {
		_ = c.Close()
		if errors.Is(err, errProtocol) {
			// connect answered success:false: the job did not start (bad
			// profile or password, or a connection rule on the system).
			return nil, errLogin
		}
		return nil, err
	}
	return m, nil
}

// mapepire is a Source over one WebSocket job.
type mapepire struct {
	ws    *wsConn
	seq   int
	total int
}

// request is a Mapepire request. Only the fields of the four request types the
// transport sends exist.
type request struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Props  string `json:"props,omitempty"`
	SQL    string `json:"sql,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	ContID string `json:"cont_id,omitempty"`
}

func (m *mapepire) fail(ctx context.Context, err error) error {
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case isTimeout(err):
		if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
			return context.DeadlineExceeded // the job's own deadline, which the net deadline raced
		}
		return errTimeout
	}
	for _, f := range []error{errLogin, errProtocol, errOversize, errClosed} {
		if errors.Is(err, f) {
			return f
		}
	}
	return errConnect
}

// call sends r (with a fresh id) and reads its reply.
func (m *mapepire) call(ctx context.Context, r request) (*reply, error) {
	m.seq++
	r.ID = "t" + strconv.Itoa(m.seq)
	b, _ := json.Marshal(r)
	dl, _ := ctx.Deadline()
	if err := m.ws.writeText(b, dl); err != nil {
		return nil, m.fail(ctx, err)
	}
	msg, err := m.ws.readMessage(maxMessage, dl)
	if err != nil {
		return nil, m.fail(ctx, err)
	}
	m.total += len(msg)
	if m.total > maxTotal {
		return nil, errOversize
	}
	return decodeReply(msg, r.ID)
}

// Profiles runs the one fixed statement and pages through the result.
func (m *mapepire) Profiles(ctx context.Context, max int) ([]Profile, error) {
	m.total = 0
	stop := context.AfterFunc(ctx, func() { _ = m.ws.conn.Close() })
	defer stop()
	var out []Profile
	rep, err := m.call(ctx, request{Type: "sql", SQL: userInfoSQL, Rows: pageRows})
	if err != nil {
		return nil, err
	}
	first := m.seq
	for turns := 0; ; turns++ {
		for _, p := range rep.Data {
			if len(out) >= max {
				if !rep.IsDone {
					m.closeCursor(ctx, first)
				}
				return nil, ErrTooLarge
			}
			out = append(out, p)
		}
		if rep.IsDone {
			return out, nil
		}
		if len(rep.Data) == 0 || turns >= maxPageTurns {
			return nil, errProtocol // a cursor that neither ends nor yields rows
		}
		if rep, err = m.call(ctx, request{Type: "sqlmore", ContID: "t" + strconv.Itoa(first), Rows: pageRows}); err != nil {
			return nil, err
		}
	}
}

// closeCursor is a best-effort sqlclose; its outcome does not matter.
func (m *mapepire) closeCursor(ctx context.Context, first int) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = m.call(cctx, request{Type: "sqlclose", ContID: "t" + strconv.Itoa(first)})
}

// Close ends the WebSocket and the connection.
func (m *mapepire) Close() {
	_ = m.ws.writeFrame(opClose, []byte{0x03, 0xE8}, time.Now().Add(time.Second))
	_ = m.ws.conn.Close()
}

// splitList splits a space or comma separated list column.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
}
