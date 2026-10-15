package eval

import (
	"encoding/base64"
	"math/big"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// This file holds the value coercions and matchers the condition operators
// need (§9.3). Everything here is pure and bounded: inputs longer than the
// caps below are "unparseable", and unparseable means "does not match".

const (
	maxDecimalLen = 128
	maxDateLen    = 64
	maxEpochDigit = 18 // an int64 holds 18 decimal digits whatever they are
)

// decimal is a decimal number in canonical form: no leading zeros in the
// integer part, no trailing zeros in the fraction, and zero is never negative.
// Comparison is exact; there is no float rounding and no big-number parsing of
// untrusted exponents.
type decimal struct {
	neg  bool
	ip   string // integer digits, "" for zero
	frac string // fraction digits without trailing zeros
}

// parseDecimal accepts [+-]digits[.digits] or [+-].digits. It rejects exponents,
// spaces, "NaN", "Inf" and anything over maxDecimalLen bytes.
func parseDecimal(s string) (decimal, bool) {
	var d decimal
	if len(s) == 0 || len(s) > maxDecimalLen {
		return d, false
	}
	i := 0
	switch s[0] {
	case '-':
		d.neg = true
		i++
	case '+':
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	ip := s[start:i]
	frac := ""
	if i < len(s) && s[i] == '.' {
		i++
		fs := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		frac = s[fs:i]
		if frac == "" {
			return decimal{}, false
		}
	}
	if i != len(s) || (ip == "" && frac == "") {
		return decimal{}, false
	}
	d.ip = strings.TrimLeft(ip, "0")
	d.frac = strings.TrimRight(frac, "0")
	if d.ip == "" && d.frac == "" {
		d.neg = false
	}
	return d, true
}

// compare returns -1, 0 or +1.
func (d decimal) compare(o decimal) int {
	switch {
	case d.neg && !o.neg:
		return -1
	case !d.neg && o.neg:
		return 1
	}
	c := d.compareMagnitude(o)
	if d.neg {
		return -c
	}
	return c
}

func (d decimal) compareMagnitude(o decimal) int {
	if len(d.ip) != len(o.ip) {
		if len(d.ip) < len(o.ip) {
			return -1
		}
		return 1
	}
	if c := strings.Compare(d.ip, o.ip); c != 0 {
		return c
	}
	// Fractions have no trailing zeros, so a proper prefix is smaller.
	return strings.Compare(d.frac, o.frac)
}

// rat converts to an exact rational; the text was validated by parseDecimal.
func (d decimal) rat() *big.Rat {
	s := d.ip
	if s == "" {
		s = "0"
	}
	if d.frac != "" {
		s += "." + d.frac
	}
	if d.neg {
		s = "-" + s
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return new(big.Rat)
	}
	return r
}

// dateVal is an instant as UTC epoch seconds plus nanoseconds, so comparison
// does not depend on time.Time's internal range.
type dateVal struct {
	sec  int64
	nsec int
}

func (d dateVal) compare(o dateVal) int {
	switch {
	case d.sec < o.sec:
		return -1
	case d.sec > o.sec:
		return 1
	case d.nsec < o.nsec:
		return -1
	case d.nsec > o.nsec:
		return 1
	}
	return 0
}

var dateLayouts = []string{
	time.RFC3339, // also accepts fractional seconds
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
	"2006-01",
}

// parseDate accepts epoch seconds (all digits, so "2026" is epoch second 2026,
// not a year) or the W3C profiles of ISO 8601 listed in dateLayouts. A value
// without a zone is UTC.
func parseDate(s string) (dateVal, bool) {
	if len(s) == 0 || len(s) > maxDateLen {
		return dateVal{}, false
	}
	if allDigits(s) {
		if len(s) > maxEpochDigit {
			return dateVal{}, false
		}
		var n int64
		for i := 0; i < len(s); i++ {
			n = n*10 + int64(s[i]-'0')
		}
		return dateVal{sec: n}, true
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			t = t.UTC()
			return dateVal{sec: t.Unix(), nsec: t.Nanosecond()}, true
		}
	}
	return dateVal{}, false
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// parseBoolValue accepts "true" and "false" in any ASCII/Unicode case.
func parseBoolValue(s string) (val, ok bool) {
	switch {
	case strings.EqualFold(s, "true"):
		return true, true
	case strings.EqualFold(s, "false"):
		return false, true
	}
	return false, false
}

// parseIPValue parses a request-context address. Zones are rejected and an
// IPv4-mapped IPv6 address is treated as the IPv4 address.
func parseIPValue(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// parseIPPolicy parses a policy value: a CIDR block, or a bare address meaning
// /32 or /128. The result is masked.
func parseIPPolicy(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") {
		a, ok := parseIPValue(s)
		if !ok {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// lastAddr is the highest address of a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// decodeBinary decodes standard base64 for BinaryEquals.
func decodeBinary(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil
}

// ---- wildcard matching -------------------------------------------------

type tokKind uint8

const (
	tokLit  tokKind = iota // matches exactly r
	tokStar                // matches any run, including empty
	tokAny                 // matches exactly one character
)

type tok struct {
	r    rune
	kind tokKind
}

// tokens turns a pattern into matcher tokens. Text in a literal segment (a
// substituted variable value or a ${*}, ${?}, ${$} escape) never acts as a
// wildcard; plain policy text does.
func (p Pattern) tokens() []tok {
	var out []tok
	for _, s := range p.Segs {
		for _, r := range s.Text {
			k := tokLit
			if !s.Lit {
				switch r {
				case '*':
					k = tokStar
				case '?':
					k = tokAny
				}
			}
			out = append(out, tok{r: r, kind: k})
		}
	}
	return out
}

func runesOf(s string) []rune {
	if utf8.ValidString(s) {
		return []rune(s)
	}
	// Invalid bytes become U+FFFD, the same on both sides of a comparison.
	return []rune(strings.ToValidUTF8(s, string(utf8.RuneError)))
}

// globTokens matches s against a token pattern. It uses the standard
// two-pointer scan with a single backtrack point, so it never blows up
// exponentially: work is at most len(p)*len(s), and there is no regexp and no
// recursion. (internal/aws/glob, PR-3, adds the strictly linear matcher the
// resource and ARN matching use; this one serves condition operators only.)
func globTokens(p []tok, s []rune) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi].kind == tokStar:
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi].kind == tokAny || p[pi].r == s[si]):
			pi++
			si++
		case star >= 0:
			mark++
			si = mark
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(p) && p[pi].kind == tokStar {
		pi++
	}
	return pi == len(p)
}

// likeMatch is StringLike.
func likeMatch(p Pattern, v string) bool { return globTokens(p.tokens(), runesOf(v)) }

// arnLikeMatch is ArnLike/ArnEquals (§9.3, default A1): the first five
// segments match one by one, the sixth is the rest of the ARN colons included,
// and a trailing "*" on the last pattern segment 3-5 matches the remainder of
// the ARN. A "*" never crosses a colon otherwise. A value that is not a
// six-segment ARN never matches.
func arnLikeMatch(p Pattern, v string) bool {
	pt := p.tokens()
	vr := runesOf(v)
	psegs := splitArn(pt)
	vsegs := splitArnRunes(vr)
	if len(vsegs) < 6 {
		return false
	}
	if len(psegs) < 6 {
		last := len(psegs) - 1
		if last < 2 || len(psegs[last]) == 0 || psegs[last][len(psegs[last])-1].kind != tokStar {
			return false
		}
		for i := 0; i < last; i++ {
			if !globTokens(psegs[i], vsegs[i]) {
				return false
			}
		}
		// The remainder of the ARN starts where value segment `last` starts.
		off := 0
		for i := 0; i < last; i++ {
			off += len(vsegs[i]) + 1
		}
		return globTokens(psegs[last], vr[off:])
	}
	for i := 0; i < 6; i++ {
		if !globTokens(psegs[i], vsegs[i]) {
			return false
		}
	}
	return true
}

// splitArn splits at the first five colons, leaving the sixth segment whole.
func splitArn(t []tok) [][]tok {
	var segs [][]tok
	start := 0
	for i := 0; i < len(t) && len(segs) < 5; i++ {
		if t[i].r == ':' {
			segs = append(segs, t[start:i])
			start = i + 1
		}
	}
	return append(segs, t[start:])
}

func splitArnRunes(r []rune) [][]rune {
	var segs [][]rune
	start := 0
	for i := 0; i < len(r) && len(segs) < 5; i++ {
		if r[i] == ':' {
			segs = append(segs, r[start:i])
			start = i + 1
		}
	}
	return append(segs, r[start:])
}
