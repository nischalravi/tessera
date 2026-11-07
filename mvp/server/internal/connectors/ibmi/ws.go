package ibmi

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 section 4.2.2 fixes SHA-1 for Sec-WebSocket-Accept; it is not a security hash here
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// A minimal RFC 6455 WebSocket client, just enough for Mapepire: one text
// message at a time, no extensions, no sub-protocols. It is hand written so the
// agent takes no new dependency and no code path it does not need: it never
// dials (it is handed a connection that safedial opened and verified), it
// accepts only unmasked text frames from the server, and every length is
// checked against a cap before anything is allocated.

const (
	wsGUID        = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC 6455 section 1.3
	maxHandshake  = 16 << 10                               // bytes of the HTTP upgrade reply
	maxFrames     = 4096                                   // frames (data and control) per message
	opContinue    = 0x0
	opText        = 0x1
	opBinary      = 0x2
	opClose       = 0x8
	opPing        = 0x9
	opPong        = 0xA
	maxControlLen = 125
)

// capReader limits what the HTTP upgrade reply may read, then lets everything
// through (the frame reader enforces its own caps).
type capReader struct {
	r    io.Reader
	left int64 // < 0: unlimited
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, errProtocol
	}
	if c.left > 0 && int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	if c.left > 0 {
		c.left -= int64(n)
	}
	return n, err
}

// wsConn is a client WebSocket over an already verified connection.
type wsConn struct {
	conn net.Conn
	cap  *capReader
	rd   *bufio.Reader
	// timeout bounds every read and write that has no earlier context deadline.
	timeout time.Duration
}

// arm sets the deadline of the next read or write.
func (w *wsConn) arm(d time.Time) {
	t := time.Now().Add(w.timeout)
	if !d.IsZero() && d.Before(t) {
		t = d
	}
	_ = w.conn.SetDeadline(t)
}

// handshake performs the HTTP upgrade (RFC 6455 section 4.1) with HTTP Basic
// credentials, as Mapepire expects (mapepire-python websocket.py).
func (w *wsConn) handshake(host, path, user, password string, deadline time.Time) error {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return errConnect
	}
	k := base64.StdEncoding.EncodeToString(key[:])
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Key: " + k + "\r\nSec-WebSocket-Version: 13\r\n")
	b.WriteString("Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)) + "\r\n\r\n")
	w.arm(deadline)
	if _, err := io.WriteString(w.conn, b.String()); err != nil {
		return err
	}
	resp, err := http.ReadResponse(w.rd, &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errLogin
	case resp.StatusCode != http.StatusSwitchingProtocols:
		return errProtocol
	}
	sum := sha1.Sum([]byte(k + wsGUID)) // #nosec G401 -- see the import
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") ||
		resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) ||
		resp.Header.Get("Sec-WebSocket-Extensions") != "" || resp.Header.Get("Sec-WebSocket-Protocol") != "" {
		return errProtocol
	}
	w.cap.left = -1
	return nil
}

// writeFrame sends one masked, final frame (clients must mask, section 5.3).
func (w *wsConn) writeFrame(op byte, payload []byte, deadline time.Time) error {
	if len(payload) > 1<<20 {
		return errOversize
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return errConnect
	}
	hdr := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = binary.BigEndian.AppendUint16(append(hdr, 0x80|126), uint16(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	hdr = append(hdr, mask[:]...)
	out := make([]byte, len(payload))
	for i, c := range payload {
		out[i] = c ^ mask[i%4]
	}
	w.arm(deadline)
	_, err := w.conn.Write(append(hdr, out...))
	return err
}

// writeText sends one JSON text message.
func (w *wsConn) writeText(p []byte, deadline time.Time) error {
	return w.writeFrame(opText, p, deadline)
}

// readMessage reads one text message of at most limit bytes (fragments
// included). Server frames must be unmasked, have no reserved bits, and be text:
// a binary frame, an oversized frame or a close is an error. Pings are answered.
func (w *wsConn) readMessage(limit int, deadline time.Time) ([]byte, error) {
	var msg []byte
	started := false
	for frames := 0; ; frames++ {
		if frames > maxFrames {
			return nil, errProtocol
		}
		w.arm(deadline)
		op, fin, payload, err := readFrame(w.rd, limit-len(msg))
		if err != nil {
			return nil, err
		}
		switch op {
		case opPing:
			if err := w.writeFrame(opPong, payload, deadline); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			return nil, errClosed
		case opText:
			if started {
				return nil, errProtocol
			}
			started = true
		case opContinue:
			if !started {
				return nil, errProtocol
			}
		default: // binary, or a reserved opcode
			return nil, errProtocol
		}
		msg = append(msg, payload...)
		if fin {
			return msg, nil
		}
	}
}

// readFrame reads one frame header and payload. room is how many more payload
// bytes the caller can take; a longer frame is errOversize, checked before the
// payload is allocated. It is the decoder the fuzz test drives.
func readFrame(r io.Reader, room int) (op byte, fin bool, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, false, nil, err
	}
	fin = h[0]&0x80 != 0
	op = h[0] & 0x0F
	if h[0]&0x70 != 0 || h[1]&0x80 != 0 { // reserved bits (no extension is negotiated); a server must not mask
		return 0, false, nil, errProtocol
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var e [2]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return 0, false, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err = io.ReadFull(r, e[:]); err != nil {
			return 0, false, nil, err
		}
		n = binary.BigEndian.Uint64(e[:])
	}
	if op >= opClose && (!fin || n > maxControlLen) { // control frames are short and never fragmented
		return 0, false, nil, errProtocol
	}
	if room < 0 || n > uint64(room) {
		return 0, false, nil, errOversize
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, false, nil, err
	}
	return op, fin, payload, nil
}

// isTimeout reports a network deadline.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
