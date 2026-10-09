package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// The strict JSON layer. It reads the document through encoding/json's token
// stream (json.Decoder with UseNumber) into a small tree that remembers byte
// positions, and enforces what encoding/json does not:
//   - duplicate object keys are an error (the IAM grammar: "Individual elements
//     must not contain multiple instances of the same key");
//   - data after the top-level value is an error;
//   - invalid UTF-8 and a byte-order mark are errors (encoding/json would
//     silently replace invalid bytes with U+FFFD);
//   - nesting depth, string length and value count are capped (Limits).
//
// json.Decoder.DisallowUnknownFields only works when decoding into structs,
// which loses key order, duplicate keys and positions. The closed grammar is
// therefore enforced by the interpreter in parse.go, member by member.

type jkind uint8

const (
	jObject jkind = iota + 1
	jArray
	jString
	jNumber
	jBool
	jNull
)

func (k jkind) String() string {
	switch k {
	case jObject:
		return "object"
	case jArray:
		return "array"
	case jString:
		return "string"
	case jNumber:
		return "number"
	case jBool:
		return "boolean"
	case jNull:
		return "null"
	}
	return "value"
}

// jnode is one JSON value. start and end are byte offsets into the raw
// document; end is exclusive.
type jnode struct {
	kind       jkind
	start, end int
	str        string // string value, or the number's literal text
	b          bool
	members    []jmember // objects, in document order
	elems      []*jnode  // arrays
}

type jmember struct {
	key      string
	keyStart int
	val      *jnode
}

type jreader struct {
	dec    *json.Decoder
	raw    []byte
	lim    Limits
	values int
	pos    *positions
}

func readTree(raw []byte, lim Limits, pos *positions) (*jnode, error) {
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, newError(pos, 0, CodeInvalidJSON, "", "byte-order mark is not allowed")
	}
	if !utf8.Valid(raw) {
		off := 0
		for off < len(raw) {
			r, w := utf8.DecodeRune(raw[off:])
			if r == utf8.RuneError && w <= 1 {
				break
			}
			off += w
		}
		return nil, newError(pos, off, CodeInvalidJSON, "", "invalid UTF-8")
	}
	if off := loneSurrogate(raw); off >= 0 {
		return nil, newError(pos, off, CodeInvalidJSON, "", "unpaired UTF-16 surrogate escape")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	r := &jreader{dec: dec, raw: raw, lim: lim, pos: pos}
	root, err := r.value(0, "")
	if err != nil {
		return nil, err
	}
	// Anything but white space after the document is an error.
	end := r.offset()
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, newError(pos, skipSpace(raw, end), CodeTrailingData, "", "data after the policy document")
	}
	return root, nil
}

// offset is the decoder's position: the end of the most recently read token.
func (r *jreader) offset() int {
	return int(r.dec.InputOffset()) // #nosec G115 -- bounded by len(raw) ≤ Limits.MaxBytes
}

// next reads one token and returns where it starts.
func (r *jreader) next(path string) (json.Token, int, error) {
	start := skipSep(r.raw, r.offset())
	tok, err := r.dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			if start == 0 {
				return nil, start, newError(r.pos, start, CodeInvalidJSON, path, "empty document")
			}
			return nil, start, newError(r.pos, start, CodeInvalidJSON, path, "unexpected end of JSON input")
		}
		off := start
		var se *json.SyntaxError
		if errors.As(err, &se) {
			off = int(se.Offset) // #nosec G115 -- bounded by len(raw)
		}
		return nil, start, newError(r.pos, off, CodeInvalidJSON, path, jsonMessage(err))
	}
	return tok, start, nil
}

func (r *jreader) value(depth int, path string) (*jnode, error) {
	tok, start, err := r.next(path)
	if err != nil {
		return nil, err
	}
	r.values++
	if r.values > r.lim.MaxValues {
		return nil, newError(r.pos, start, CodeLimitExceeded, path, fmt.Sprintf("more than %d JSON values", r.lim.MaxValues))
	}
	n := &jnode{start: start}
	switch t := tok.(type) {
	case json.Delim:
		if t != '{' && t != '[' {
			return nil, newError(r.pos, start, CodeInvalidJSON, path, fmt.Sprintf("unexpected %q", rune(t)))
		}
		if depth+1 > r.lim.MaxDepth {
			return nil, newError(r.pos, start, CodeLimitExceeded, path, fmt.Sprintf("nesting deeper than %d", r.lim.MaxDepth))
		}
		if t == '{' {
			n.kind = jObject
			err = r.object(n, depth+1, path)
		} else {
			n.kind = jArray
			err = r.array(n, depth+1, path)
		}
		if err != nil {
			return nil, err
		}
	case string:
		if len(t) > r.lim.MaxStringBytes {
			return nil, newError(r.pos, start, CodeLimitExceeded, path, fmt.Sprintf("string longer than %d bytes", r.lim.MaxStringBytes))
		}
		n.kind, n.str = jString, t
	case json.Number:
		if len(t) > r.lim.MaxStringBytes {
			return nil, newError(r.pos, start, CodeLimitExceeded, path, fmt.Sprintf("number longer than %d bytes", r.lim.MaxStringBytes))
		}
		n.kind, n.str = jNumber, string(t)
	case bool:
		n.kind, n.b = jBool, t
	case nil:
		n.kind = jNull
	default:
		return nil, newError(r.pos, start, CodeInvalidJSON, path, "unexpected token")
	}
	n.end = r.offset()
	return n, nil
}

func (r *jreader) object(n *jnode, depth int, path string) error {
	seen := map[string]bool{}
	for r.dec.More() {
		tok, keyStart, err := r.next(path)
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return newError(r.pos, keyStart, CodeInvalidJSON, path, "object key must be a string")
		}
		if len(key) > r.lim.MaxStringBytes {
			return newError(r.pos, keyStart, CodeLimitExceeded, path, fmt.Sprintf("key longer than %d bytes", r.lim.MaxStringBytes))
		}
		if seen[key] {
			return newError(r.pos, keyStart, CodeDuplicateKey, path, fmt.Sprintf("duplicate key %q", key))
		}
		seen[key] = true
		v, err := r.value(depth, joinPath(path, key))
		if err != nil {
			return err
		}
		n.members = append(n.members, jmember{key: key, keyStart: keyStart, val: v})
	}
	_, _, err := r.next(path) // the closing '}'
	return err
}

func (r *jreader) array(n *jnode, depth int, path string) error {
	for i := 0; r.dec.More(); i++ {
		v, err := r.value(depth, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return err
		}
		n.elems = append(n.elems, v)
	}
	_, _, err := r.next(path) // the closing ']'
	return err
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// skipSep skips JSON white space and the ',' and ':' separators, which the
// decoder consumes as part of the next token.
func skipSep(raw []byte, off int) int {
	for off < len(raw) {
		switch raw[off] {
		case ' ', '\t', '\n', '\r', ',', ':':
			off++
		default:
			return off
		}
	}
	return off
}

func skipSpace(raw []byte, off int) int {
	for off < len(raw) {
		switch raw[off] {
		case ' ', '\t', '\n', '\r':
			off++
		default:
			return off
		}
	}
	return off
}

// jsonMessage strips encoding/json's "json: " prefix if present.
func jsonMessage(err error) string {
	return string(bytes.TrimPrefix([]byte(err.Error()), []byte("json: ")))
}

// positions converts byte offsets to 1-based line and column numbers.
// Columns count Unicode code points. A line ends at "\n", "\r\n" (one break)
// or a lone "\r", as in editors and JSON's own white space.
type positions struct {
	raw   []byte
	lines []int // byte offset of the start of each line
}

func newPositions(raw []byte) *positions {
	return &positions{raw: raw, lines: lineStarts(raw)}
}

// lineStarts returns the byte offset of the start of each line of raw.
func lineStarts(raw []byte) []int {
	lines := []int{0}
	for i, c := range raw {
		switch {
		case c == '\n':
			lines = append(lines, i+1)
		case c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n'):
			lines = append(lines, i+1)
		}
	}
	return lines
}

// at returns the line and column of byte offset off (clamped to the document).
func (p *positions) at(off int) (line, col int) {
	if off < 0 {
		off = 0
	}
	if off > len(p.raw) {
		off = len(p.raw)
	}
	// Binary search for the last line start ≤ off.
	lo, hi := 0, len(p.lines)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if p.lines[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1, utf8.RuneCount(p.raw[p.lines[lo]:off]) + 1
}

// span returns the inclusive span of a node.
func (p *positions) span(n *jnode) *Span {
	sl, sc := p.at(n.start)
	last := n.end - 1
	if last < n.start {
		last = n.start
	}
	el, ec := p.at(last)
	return &Span{StartLine: sl, StartCol: sc, EndLine: el, EndCol: ec}
}

// loneSurrogate returns the offset of the first \uXXXX escape that is a UTF-16
// surrogate not part of a high+low pair, or -1. encoding/json would silently
// replace it with U+FFFD, so the model would no longer match the raw bytes.
// In valid JSON a backslash occurs only inside strings; elsewhere the decoder
// reports a syntax error anyway.
func loneSurrogate(raw []byte) int {
	hex4 := func(i int) (rune, bool) {
		if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range raw[i+2 : i+6] {
			switch {
			case '0' <= c && c <= '9':
				r = r<<4 | rune(c-'0')
			case 'a' <= c && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case 'A' <= c && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		r, ok := hex4(i)
		if !ok {
			i++ // skip the escaped character (including an escaped backslash)
			continue
		}
		switch {
		case 0xD800 <= r && r <= 0xDBFF:
			if lo, ok := hex4(i + 6); ok && 0xDC00 <= lo && lo <= 0xDFFF {
				i += 11
				continue
			}
			return i
		case 0xDC00 <= r && r <= 0xDFFF:
			return i
		}
		i += 5
	}
	return -1
}
