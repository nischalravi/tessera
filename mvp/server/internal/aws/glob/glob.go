// Package glob is the one wildcard matcher of the AWS evaluator (design §8.5).
//
// Every '*' and '?' match (actions, resources, StringLike, ArnLike) goes
// through it. Policy JSON is untrusted, so the matcher uses no regexp, no
// recursion and no backtracking stack, and does not allocate while matching:
// the work is bounded by len(pattern)·len(subject) whatever the input.
//
// The package does no I/O and reads no clock.
package glob

import (
	"errors"
	"unicode/utf8"
)

// MaxPatternBytes caps a pattern's size. It equals policy.DefaultLimits.MaxStringBytes
// (an eval test pins the two together); glob does not import policy so it stays a leaf.
const MaxPatternBytes = 8 << 10

// Compile errors.
var (
	ErrInvalidUTF8 = errors.New("glob: pattern is not valid UTF-8")
	ErrTooLong     = errors.New("glob: pattern exceeds the size cap")
)

type kind uint8

const (
	lit  kind = iota // match this byte exactly (or ASCII-case-insensitively when fold is set)
	star             // '*': any run of characters, including none
	one              // '?': exactly one character (one UTF-8 rune)
)

// Pattern is a compiled IAM wildcard pattern. A literal '*', '?' or '$'
// produced by the ${*}, ${?} and ${$} escapes (§9.3, CompileEscaped) is
// compiled as lit, never as a wildcard. A Pattern is immutable and safe for
// concurrent use.
type Pattern struct {
	src  string // original text, for traces
	b    []byte // pattern bytes (escapes already resolved)
	k    []kind // parallel to b
	fold bool   // ASCII case-insensitive (actions); false for ARNs and StringLike
}

// Compile compiles src. Every character other than '*' and '?' is literal.
// fold selects ASCII-only case-insensitive literals (A-Z only, §8.1).
// It rejects invalid UTF-8 and patterns over MaxPatternBytes.
func Compile(src string, fold bool) (*Pattern, error) {
	return compile(src, fold, false)
}

// CompileEscaped is Compile for a pattern that may still carry the policy
// variable escapes ${*}, ${?} and ${$}, which stand for a literal '*', '?'
// and '$'. Other ${...} text is literal.
func CompileEscaped(src string, fold bool) (*Pattern, error) {
	return compile(src, fold, true)
}

func compile(src string, fold, escapes bool) (*Pattern, error) {
	if len(src) > MaxPatternBytes {
		return nil, ErrTooLong
	}
	if !utf8.ValidString(src) {
		return nil, ErrInvalidUTF8
	}
	p := &Pattern{src: src, fold: fold, b: make([]byte, 0, len(src)), k: make([]kind, 0, len(src))}
	for i := 0; i < len(src); i++ {
		c := src[i]
		if escapes && c == '$' && i+3 < len(src) && src[i+1] == '{' && src[i+3] == '}' {
			switch src[i+2] {
			case '*', '?', '$':
				p.b = append(p.b, src[i+2])
				p.k = append(p.k, lit)
				i += 3
				continue
			}
		}
		switch c {
		case '*':
			p.b = append(p.b, c)
			p.k = append(p.k, star)
		case '?':
			p.b = append(p.b, c)
			p.k = append(p.k, one)
		default:
			p.b = append(p.b, c)
			p.k = append(p.k, lit)
		}
	}
	return p, nil
}

// String returns the pattern text as given to Compile.
func (p *Pattern) String() string { return p.src }

// EndsInStar reports whether the last element is a wildcard '*' (not an
// escaped literal one).
func (p *Pattern) EndsInStar() bool {
	return len(p.k) > 0 && p.k[len(p.k)-1] == star
}

// IsAll reports whether the pattern is only '*' elements (matches any string).
func (p *Pattern) IsAll() bool {
	for _, k := range p.k {
		if k != star {
			return false
		}
	}
	return len(p.k) > 0
}

// Match reports whether s matches p.
// Time: O(len(p)·len(s)) worst case, O(len(p)+len(s)) when p has at most one '*'.
// Space: O(1). No input can make it exponential. The subject may be any
// string; an invalid byte counts as one character for '?'.
func (p *Pattern) Match(s string) bool {
	pi, si := 0, 0
	starPi, starSi := -1, 0 // last '*' seen in p, and where in s its absorption ends
	for si < len(s) {
		if pi < len(p.b) {
			switch p.k[pi] {
			case star:
				starPi, starSi = pi, si
				pi++
				continue
			case one:
				_, w := utf8.DecodeRuneInString(s[si:])
				pi, si = pi+1, si+w
				continue
			case lit:
				if p.eq(p.b[pi], s[si]) {
					pi, si = pi+1, si+1
					continue
				}
			}
		}
		if starPi < 0 {
			return false
		}
		// Mismatch: let the most recent '*' absorb one more rune and resume just after it.
		// Earlier stars never need revisiting: with only '*' and '?' (no character classes),
		// the last star can absorb anything an earlier star would have.
		_, w := utf8.DecodeRuneInString(s[starSi:])
		starSi += w
		pi, si = starPi+1, starSi
	}
	for pi < len(p.b) && p.k[pi] == star {
		pi++
	}
	return pi == len(p.b)
}

func (p *Pattern) eq(a, b byte) bool {
	return a == b || (p.fold && lowerASCII(a) == lowerASCII(b))
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
