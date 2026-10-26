// Package cedarx is Tessera's wrapper around cedar-go for the access-as-code
// repository (design access-as-code-repo.md §3 and §9): the generated schema,
// policy and schema parsing, validation against the schema, and the size and
// depth limits that make a bundle's Cedar safe to parse.
//
// The package is pure: no database, no network, no clock, no file system. Bytes
// come in as arguments (internal/archtest enforces it). Every parse entry point
// runs Check first, which refuses an oversized or too deeply nested source by a
// lexical scan, before cedar-go sees it.
package cedarx

import (
	"fmt"
	"strings"
)

// Limits of untrusted Cedar input (design §9).
const (
	MaxFileBytes       = 256 << 10 // one file
	MaxDepth           = 32        // nesting of (), [], {} (and <> in a schema), and of chained unary operators and ifs
	MaxEntities        = 10000     // entities validated at once
	MaxAnnotationBytes = 1 << 10   // one annotation value
	MaxPolicyTokens    = 20000     // lexical tokens in one policy (bounds operator chains)
	MaxPolicies        = 5000      // policies in one file
)

// Error codes.
const (
	CodeTooLarge      = "too_large"
	CodeTooDeep       = "too_deep"
	CodeTooComplex    = "too_complex"
	CodeSyntax        = "syntax"
	CodeSchema        = "schema"
	CodeValidation    = "validation"
	CodeAnnotation    = "annotation_too_long"
	CodeTooManyEntity = "too_many_entities"
)

// Error is a refusal with a stable code. Line is 1-based, or 0 when unknown.
type Error struct {
	Code string
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("cedarx: %s: line %d: %s", e.Code, e.Line, e.Msg)
	}
	return "cedarx: " + e.Code + ": " + e.Msg
}

func errf(code string, line int, format string, args ...any) *Error {
	return &Error{Code: code, Line: line, Msg: fmt.Sprintf(format, args...)}
}

// Check refuses src if it is larger than MaxFileBytes, nests deeper than
// MaxDepth, or has a policy of more than MaxPolicyTokens tokens or a file of
// more than MaxPolicies policies. It scans the bytes once, in time linear in
// their length and constant space, and never builds a tree, so it bounds what a
// recursive parser later does. It does not check the syntax: an unterminated
// string or a stray bracket is the parser's to report. schema selects the
// schema grammar, in which '<' and '>' also nest (Set<Set<...>>).
func Check(src []byte, schema bool) error {
	if len(src) > MaxFileBytes {
		return errf(CodeTooLarge, 0, "%d bytes; a file is at most %d", len(src), MaxFileBytes)
	}
	var (
		line     = 1
		depth    = 0 // open brackets
		prefix   = 0 // consecutive prefix operators ('!', '-')
		ifs      = 0 // 'if's seen in the current statement
		tokens   = 0
		policies = 0
	)
	tooDeep := func() error { return errf(CodeTooDeep, line, "nesting deeper than %d", MaxDepth) }
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"':
			tokens++
			prefix = 0
			i++
			for i < len(src) && src[i] != '"' {
				switch src[i] {
				case '\\':
					i++
				case '\n':
					line++
				}
				i++
			}
			i++
		case c == '(' || c == '[' || c == '{' || (schema && c == '<'):
			tokens++
			prefix = 0
			depth++
			if depth+ifs > MaxDepth {
				return tooDeep()
			}
			i++
		case c == ')' || c == ']' || c == '}' || (schema && c == '>'):
			tokens++
			prefix = 0
			if depth > 0 {
				depth--
			}
			i++
		case c == '!' || c == '-':
			tokens++
			prefix++
			if depth+prefix+ifs > MaxDepth {
				return tooDeep()
			}
			i++
		case c == ';':
			tokens++
			prefix = 0
			if depth == 0 {
				policies++
				if policies > MaxPolicies {
					return errf(CodeTooComplex, line, "more than %d policies in a file", MaxPolicies)
				}
				ifs, tokens = 0, 0
			}
			i++
		case isWord(c):
			j := i
			for j < len(src) && isWord(src[j]) {
				j++
			}
			tokens++
			prefix = 0
			if string(src[i:j]) == "if" {
				ifs++
				if depth+ifs > MaxDepth {
					return tooDeep()
				}
			}
			i = j
		default:
			tokens++
			prefix = 0
			i++
		}
		if tokens > MaxPolicyTokens {
			return errf(CodeTooComplex, line, "more than %d tokens in one policy", MaxPolicyTokens)
		}
	}
	return nil
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// ident reports whether s is a Cedar identifier usable as an attribute name
// without quoting, and not a reserved word.
func ident(s string) bool {
	if s == "" || len(s) > 64 || reserved[s] {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

var reserved = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields("true false if then else in is like has permit forbid when unless principal action resource context") {
		m[w] = true
	}
	return m
}()
