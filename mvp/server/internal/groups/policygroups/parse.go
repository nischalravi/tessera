package policygroups

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The parser reads Cedar policy text into a general expression tree; lower.go
// then admits only the fragment of design §8.2. Parsing the whole expression
// grammar (rather than only the fragment) is what lets an unsupported construct
// get a precise "context is not available" or "arithmetic is not supported"
// instead of a bare syntax error.

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tInt
	tPunct
)

type token struct {
	kind tokKind
	text string // identifier or punctuation; the decoded value of a string; the digits of an integer
	at   Pos
}

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "end of file"
	case tString:
		return strconv.Quote(t.text)
	}
	return "'" + t.text + "'"
}

// Limits on a policy file: parsing is bounded in depth, size and tokens.
const (
	MaxFileBytes = 256 << 10
	maxDepth     = 64
	maxTokens    = 200_000
)

// bail aborts a parse with a diagnostic; parse recovers it. Nothing else is recovered.
type bail struct{ d Diagnostic }

func fail(at Pos, code, format string, args ...any) {
	panic(bail{Diagnostic{Line: at.Line, Col: at.Col, Code: code, Msg: fmt.Sprintf(format, args...)}})
}

// ---------------------------------------------------------------- lexer

type lexer struct {
	src       string
	i         int
	line, col int
}

func (l *lexer) pos() Pos { return Pos{l.line, l.col} }

func (l *lexer) next() (byte, bool) {
	if l.i >= len(l.src) {
		return 0, false
	}
	b := l.src[l.i]
	l.i++
	if b == '\n' {
		l.line++
		l.col = 1
	} else if b&0xC0 != 0x80 { // a continuation byte is not a column
		l.col++
	}
	return b, true
}

func (l *lexer) peek() byte {
	if l.i >= len(l.src) {
		return 0
	}
	return l.src[l.i]
}

func isIdentStart(b byte) bool { return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func isDigit(b byte) bool      { return b >= '0' && b <= '9' }

func lex(src string) []token {
	l := &lexer{src: src, line: 1, col: 1}
	var out []token
	for {
		for l.i < len(l.src) {
			b := l.peek()
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				l.next()
			} else if b == '/' && l.i+1 < len(l.src) && l.src[l.i+1] == '/' {
				for l.i < len(l.src) && l.peek() != '\n' {
					l.next()
				}
			} else {
				break
			}
		}
		at := l.pos()
		if l.i >= len(l.src) {
			return append(out, token{kind: tEOF, at: at})
		}
		if len(out) >= maxTokens {
			fail(at, CodeSyntax, "the file is too long")
		}
		b := l.peek()
		switch {
		case isIdentStart(b):
			start := l.i
			for l.i < len(l.src) && (isIdentStart(l.peek()) || isDigit(l.peek())) {
				l.next()
			}
			out = append(out, token{kind: tIdent, text: l.src[start:l.i], at: at})
		case isDigit(b):
			start := l.i
			for l.i < len(l.src) && isDigit(l.peek()) {
				l.next()
			}
			out = append(out, token{kind: tInt, text: l.src[start:l.i], at: at})
		case b == '"':
			out = append(out, token{kind: tString, text: lexString(l), at: at})
		default:
			out = append(out, token{kind: tPunct, text: lexPunct(l, at), at: at})
		}
	}
}

func lexPunct(l *lexer, at Pos) string {
	b, _ := l.next()
	two := func(second byte) bool {
		if l.peek() == second {
			l.next()
			return true
		}
		return false
	}
	switch b {
	case '=':
		if two('=') {
			return "=="
		}
		fail(at, CodeSyntax, "unexpected '=': use '=='")
	case '!':
		if two('=') {
			return "!="
		}
		return "!"
	case '<':
		if two('=') {
			return "<="
		}
		return "<"
	case '>':
		if two('=') {
			return ">="
		}
		return ">"
	case '&':
		if two('&') {
			return "&&"
		}
		fail(at, CodeSyntax, "unexpected '&': use '&&'")
	case '|':
		if two('|') {
			return "||"
		}
		fail(at, CodeSyntax, "unexpected '|': use '||'")
	case ':':
		if two(':') {
			return "::"
		}
		return ":"
	case '(', ')', '{', '}', '[', ']', ',', '.', ';', '@', '+', '-', '*', '/':
		return string(b)
	}
	if b >= utf8.RuneSelf {
		fail(at, CodeSyntax, "unexpected character outside a string")
	}
	fail(at, CodeSyntax, "unexpected character %q", string(b))
	return ""
}

func lexString(l *lexer) string {
	start := l.pos()
	l.next() // the opening quote
	var sb strings.Builder
	for {
		b, ok := l.next()
		if !ok {
			fail(start, CodeSyntax, "unterminated string")
		}
		switch b {
		case '"':
			s := sb.String()
			if !utf8.ValidString(s) {
				fail(start, CodeSyntax, "a string must be valid UTF-8")
			}
			return s
		case '\\':
			e, ok := l.next()
			if !ok {
				fail(start, CodeSyntax, "unterminated string")
			}
			switch e {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case '0':
				sb.WriteByte(0)
			case '\\', '"', '\'':
				sb.WriteByte(e)
			case 'u':
				sb.WriteRune(lexUnicode(l, start))
			default:
				fail(start, CodeSyntax, "unknown escape \\%s in a string", string(e))
			}
		default:
			if b < 0x20 && b != '\t' || b == 0x7f {
				fail(start, CodeSyntax, "a string holds no raw control character: write it as an escape, such as \\n or \\u{...}")
			}
			sb.WriteByte(b)
		}
	}
}

func lexUnicode(l *lexer, start Pos) rune {
	if b, _ := l.next(); b != '{' {
		fail(start, CodeSyntax, "\\u must be followed by {hex}")
	}
	var hex strings.Builder
	for {
		b, ok := l.next()
		if !ok {
			fail(start, CodeSyntax, "unterminated string")
		}
		if b == '}' {
			break
		}
		hex.WriteByte(b)
	}
	if hex.Len() == 0 || hex.Len() > 6 {
		fail(start, CodeSyntax, "invalid \\u{...} escape")
	}
	var r rune
	for _, d := range hex.String() { // at most six digits: no overflow
		var v rune
		switch {
		case d >= '0' && d <= '9':
			v = d - '0'
		case d >= 'a' && d <= 'f':
			v = d - 'a' + 10
		case d >= 'A' && d <= 'F':
			v = d - 'A' + 10
		default:
			fail(start, CodeSyntax, "invalid \\u{...} escape")
		}
		r = r<<4 | v
	}
	if !utf8.ValidRune(r) {
		fail(start, CodeSyntax, "invalid \\u{...} escape")
	}
	return r
}

// ---------------------------------------------------------------- general tree

type node interface{ at() Pos }

type (
	nVar struct {
		name string
		p    Pos
	}
	nStr struct {
		val string
		p   Pos
	}
	nInt struct {
		raw string
		p   Pos
	}
	nBool struct {
		val bool
		p   Pos
	}
	nAttr struct {
		x    node
		name string
		p    Pos
	}
	nHas struct {
		x    node
		name string
		p    Pos
	}
	nCall struct {
		x      node
		method string
		args   []node
		p      Pos
	}
	nFn struct {
		name string
		args []node
		p    Pos
	}
	nBin struct {
		op   string
		l, r node
		p    Pos
	}
	nUn struct {
		op string
		x  node
		p  Pos
	}
	nLike struct {
		x node
		p Pos
	}
	nIs struct {
		x  node
		ty string
		p  Pos
	}
	nIf  struct{ p Pos }
	nSet struct {
		elems []node
		p     Pos
	}
	nRecord struct{ p Pos }
	nEntity struct {
		ty, id string
		p      Pos
	}
)

func (n nVar) at() Pos    { return n.p }
func (n nStr) at() Pos    { return n.p }
func (n nInt) at() Pos    { return n.p }
func (n nBool) at() Pos   { return n.p }
func (n nAttr) at() Pos   { return n.p }
func (n nHas) at() Pos    { return n.p }
func (n nCall) at() Pos   { return n.p }
func (n nFn) at() Pos     { return n.p }
func (n nBin) at() Pos    { return n.p }
func (n nUn) at() Pos     { return n.p }
func (n nLike) at() Pos   { return n.p }
func (n nIs) at() Pos     { return n.p }
func (n nIf) at() Pos     { return n.p }
func (n nSet) at() Pos    { return n.p }
func (n nRecord) at() Pos { return n.p }
func (n nEntity) at() Pos { return n.p }

// ---------------------------------------------------------------- parser

type parser struct {
	toks  []token
	i     int
	depth int
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) advance() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) isPunct(s string) bool {
	t := p.peek()
	return t.kind == tPunct && t.text == s
}

func (p *parser) isIdent(s string) bool {
	t := p.peek()
	return t.kind == tIdent && t.text == s
}

func (p *parser) accept(s string) bool {
	if p.isPunct(s) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) expect(s string) Pos {
	t := p.peek()
	if t.kind != tPunct || t.text != s {
		fail(t.at, CodeSyntax, "expected '%s', found %s", s, t.describe())
	}
	p.advance()
	return t.at
}

func (p *parser) expectIdent(s string) Pos {
	t := p.peek()
	if t.kind != tIdent || t.text != s {
		fail(t.at, CodeSyntax, "expected '%s', found %s", s, t.describe())
	}
	p.advance()
	return t.at
}

func (p *parser) enter(at Pos) {
	p.depth++
	if p.depth > maxDepth {
		fail(at, CodeSyntax, "the condition is nested more than %d levels deep", maxDepth)
	}
}

func (p *parser) leave() { p.depth-- }

func (p *parser) expr() node {
	t := p.peek()
	p.enter(t.at)
	defer p.leave()
	if p.isIdent("if") {
		p.advance()
		p.expr()
		p.expectIdent("then")
		p.expr()
		p.expectIdent("else")
		p.expr()
		return nIf{p: t.at}
	}
	return p.or()
}

func (p *parser) or() node {
	l := p.and()
	for p.isPunct("||") {
		t := p.advance()
		l = nBin{op: "||", l: l, r: p.and(), p: t.at}
	}
	return l
}

func (p *parser) and() node {
	l := p.rel()
	for p.isPunct("&&") {
		t := p.advance()
		l = nBin{op: "&&", l: l, r: p.rel(), p: t.at}
	}
	return l
}

func (p *parser) rel() node {
	l := p.add()
	t := p.peek()
	switch {
	case t.kind == tPunct && (t.text == "==" || t.text == "!=" || t.text == "<" || t.text == "<=" || t.text == ">" || t.text == ">="):
		p.advance()
		return nBin{op: t.text, l: l, r: p.add(), p: t.at}
	case t.kind == tIdent && t.text == "in":
		p.advance()
		return nBin{op: "in", l: l, r: p.add(), p: t.at}
	case t.kind == tIdent && t.text == "has":
		p.advance()
		a := p.advance()
		if a.kind != tIdent && a.kind != tString {
			fail(a.at, CodeSyntax, "expected an attribute name after 'has', found %s", a.describe())
		}
		name := a.text
		for p.isPunct(".") { // has a.b.c
			p.advance()
			b := p.advance()
			if b.kind != tIdent {
				fail(b.at, CodeSyntax, "expected an attribute name after '.', found %s", b.describe())
			}
			name += "." + b.text
		}
		return nHas{x: l, name: name, p: t.at}
	case t.kind == tIdent && t.text == "like":
		p.advance()
		s := p.advance()
		if s.kind != tString {
			fail(s.at, CodeSyntax, "expected a pattern string after 'like', found %s", s.describe())
		}
		return nLike{x: l, p: t.at}
	case t.kind == tIdent && t.text == "is":
		p.advance()
		ty := p.entityPath()
		if p.isIdent("in") {
			p.advance()
			p.add()
		}
		return nIs{x: l, ty: ty, p: t.at}
	}
	return l
}

func (p *parser) entityPath() string {
	t := p.advance()
	if t.kind != tIdent {
		fail(t.at, CodeSyntax, "expected a type name, found %s", t.describe())
	}
	path := t.text
	for p.isPunct("::") && p.toks[p.i+1].kind == tIdent {
		p.advance()
		path += "::" + p.advance().text
	}
	return path
}

func (p *parser) add() node {
	l := p.mul()
	for p.isPunct("+") || p.isPunct("-") {
		t := p.advance()
		l = nBin{op: t.text, l: l, r: p.mul(), p: t.at}
	}
	return l
}

func (p *parser) mul() node {
	l := p.unary()
	for p.isPunct("*") {
		t := p.advance()
		l = nBin{op: "*", l: l, r: p.unary(), p: t.at}
	}
	return l
}

func (p *parser) unary() node {
	t := p.peek()
	if t.kind == tPunct && (t.text == "!" || t.text == "-") {
		p.advance()
		p.enter(t.at)
		defer p.leave()
		return nUn{op: t.text, x: p.unary(), p: t.at}
	}
	return p.member()
}

func (p *parser) member() node {
	x := p.primary()
	for {
		t := p.peek()
		switch {
		case t.kind == tPunct && t.text == ".":
			p.advance()
			a := p.advance()
			if a.kind != tIdent {
				fail(a.at, CodeSyntax, "expected an attribute or method name after '.', found %s", a.describe())
			}
			if p.isPunct("(") {
				x = nCall{x: x, method: a.text, args: p.args(), p: a.at}
			} else {
				x = nAttr{x: x, name: a.text, p: a.at}
			}
		case t.kind == tPunct && t.text == "[":
			p.advance()
			s := p.advance()
			if s.kind != tString {
				fail(s.at, CodeSyntax, "expected an attribute name string, found %s", s.describe())
			}
			p.expect("]")
			x = nAttr{x: x, name: s.text, p: s.at}
		default:
			return x
		}
	}
}

func (p *parser) args() []node {
	p.expect("(")
	var out []node
	for !p.isPunct(")") {
		if len(out) > 0 {
			p.expect(",")
		}
		out = append(out, p.expr())
		if len(out) > 64 {
			fail(p.peek().at, CodeSyntax, "too many arguments")
		}
	}
	p.expect(")")
	return out
}

func (p *parser) primary() node {
	t := p.advance()
	switch t.kind {
	case tString:
		return nStr{val: t.text, p: t.at}
	case tInt:
		return nInt{raw: t.text, p: t.at}
	case tIdent:
		switch t.text {
		case "true", "false":
			return nBool{val: t.text == "true", p: t.at}
		case "principal", "action", "resource", "context":
			return nVar{name: t.text, p: t.at}
		}
		if p.isPunct("::") {
			path := t.text
			for p.isPunct("::") {
				p.advance()
				n := p.advance()
				switch n.kind {
				case tString:
					return nEntity{ty: path, id: n.text, p: t.at}
				case tIdent:
					path += "::" + n.text
				default:
					fail(n.at, CodeSyntax, "expected a name or an id string after '::', found %s", n.describe())
				}
			}
			fail(t.at, CodeSyntax, "expected an entity id string after %s", path)
		}
		if p.isPunct("(") {
			return nFn{name: t.text, args: p.args(), p: t.at}
		}
		fail(t.at, CodeSyntax, "unknown name '%s'", t.text)
	case tPunct:
		switch t.text {
		case "(":
			p.enter(t.at)
			defer p.leave()
			x := p.expr()
			p.expect(")")
			return x
		case "[":
			p.enter(t.at)
			defer p.leave()
			var elems []node
			for !p.isPunct("]") {
				if len(elems) > 0 {
					p.expect(",")
				}
				elems = append(elems, p.expr())
				if len(elems) > 1024 {
					fail(t.at, CodeSyntax, "a list is at most 1024 items")
				}
			}
			p.expect("]")
			return nSet{elems: elems, p: t.at}
		case "{":
			p.enter(t.at)
			defer p.leave()
			for depth := 1; depth > 0; { // skip the record: it is rejected on lowering
				n := p.advance()
				switch {
				case n.kind == tEOF:
					fail(t.at, CodeSyntax, "unterminated record")
				case n.kind == tPunct && n.text == "{":
					depth++
				case n.kind == tPunct && n.text == "}":
					depth--
				}
			}
			return nRecord{p: t.at}
		}
	}
	fail(t.at, CodeSyntax, "unexpected %s", t.describe())
	return nil
}

// ---------------------------------------------------------------- file

// rawPolicy is a policy as written: annotations, effect, scope and conditions.
type rawPolicy struct {
	at       Pos
	effect   Effect
	annots   map[string][]string
	annotPos map[string]Pos
	resource string
	resAt    Pos
	whens    []node
	unlesses []node
}

// parseRaw reads a policy file into raw policies. A syntax error stops the file.
func parseRaw(path, src string) (pols []*rawPolicy, diag *Diagnostic) {
	defer func() {
		if r := recover(); r != nil {
			b, ok := r.(bail)
			if !ok {
				panic(r)
			}
			b.d.Path = path
			diag = &b.d
		}
	}()
	if len(src) > MaxFileBytes {
		return nil, &Diagnostic{Path: path, Line: 1, Col: 1, Code: CodeFileTooLarge, Msg: fmt.Sprintf("a policy file is at most %d bytes", MaxFileBytes)}
	}
	p := &parser{toks: lex(src)}
	for p.peek().kind != tEOF {
		pols = append(pols, p.policy())
		if len(pols) > 1000 {
			fail(p.peek().at, CodeSyntax, "a policy file has at most 1000 policies")
		}
	}
	return pols, nil
}

func (p *parser) annotations() (map[string][]string, map[string]Pos) {
	annots, at := map[string][]string{}, map[string]Pos{}
	for p.isPunct("@") {
		p.advance()
		n := p.advance()
		if n.kind != tIdent {
			fail(n.at, CodeSyntax, "expected an annotation name after '@', found %s", n.describe())
		}
		if _, dup := annots[n.text]; dup {
			fail(n.at, CodeInvalidPolicy, "annotation @%s is given twice", n.text)
		}
		var vals []string
		p.expect("(")
		for !p.isPunct(")") {
			if len(vals) > 0 {
				p.expect(",")
			}
			s := p.advance()
			if s.kind != tString {
				fail(s.at, CodeSyntax, "an annotation takes string values, found %s", s.describe())
			}
			vals = append(vals, s.text)
		}
		p.expect(")")
		annots[n.text], at[n.text] = vals, n.at
	}
	return annots, at
}

func (p *parser) entity(wantType string) (string, Pos) {
	t := p.peek()
	n := p.expr()
	e, ok := n.(nEntity)
	if !ok {
		fail(t.at, CodeInvalidPolicy, "expected %s::\"...\", found %s", wantType, t.describe())
	}
	if e.ty != wantType {
		fail(t.at, CodeInvalidPolicy, "expected an entity of type %s, found %s", wantType, e.ty)
	}
	return e.id, t.at
}

func (p *parser) policy() *rawPolicy {
	rp := &rawPolicy{}
	rp.annots, rp.annotPos = p.annotations()
	t := p.advance()
	if t.kind != tIdent || (t.text != "permit" && t.text != "forbid") {
		fail(t.at, CodeSyntax, "expected 'permit' or 'forbid', found %s", t.describe())
	}
	rp.at = t.at
	if t.text == "forbid" {
		rp.effect = Forbid
	}
	p.expect("(")
	// principal: unconstrained (conditions say who)
	pt := p.peek()
	p.expectIdent("principal")
	if !p.isPunct(",") {
		fail(pt.at, CodeUnsupported, "a principal constraint in the scope is not supported: use a when condition (principal in Tessera::Group::\"...\")")
	}
	p.expect(",")
	at := p.peek()
	p.expectIdent("action")
	p.expect("==")
	if id, _ := p.entity("Tessera::Action"); id != "member" {
		fail(at.at, CodeInvalidPolicy, "the action must be Tessera::Action::\"member\", found %q", id)
	}
	p.expect(",")
	p.expectIdent("resource")
	p.expect("==")
	rp.resource, rp.resAt = p.entity("Tessera::Group")
	p.expect(")")
	for p.isIdent("when") || p.isIdent("unless") {
		kw := p.advance()
		p.expect("{")
		c := p.expr()
		p.expect("}")
		if kw.text == "when" {
			rp.whens = append(rp.whens, c)
		} else {
			rp.unlesses = append(rp.unlesses, c)
		}
	}
	p.expect(";")
	return rp
}
