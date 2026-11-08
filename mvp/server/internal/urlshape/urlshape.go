// Package urlshape classifies values that a URL parser may read as a URL. It is the one definition of "a URL value"
// and "a URL-valued setting" behind the refusal of credentialed connection URLs, their masking in views, the
// credential drop when an endpoint moves (internal/readiness) and the cleaning of the config export
// (internal/transport), so the four cannot drift (issues #908, #921).
//
// Browsers and other WHATWG-style parsers are lenient where net/url is not: they drop surrounding control
// characters and spaces, remove tabs and line breaks anywhere, read "\" as "/" in http(s), ws(s) and ftp URLs, and
// for those schemes accept any number of slashes (none included) between the scheme and the authority, so
// "https:user:pass@host" names a host with credentials. Classify rewrites a value to the "scheme://" form such a
// parser sees, so the callers can inspect it with net/url.
package urlshape

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Shape is how a value reads as a URL.
type Shape uint8

const (
	// NotURL is a value with no scheme and no leading "//".
	NotURL Shape = iota
	// Authority is a URL that names a host (and so may carry userinfo): "scheme://…", a special scheme in any
	// separator form, or a scheme-relative "//…".
	Authority
	// Opaque is a value with a scheme prefix and no authority ("mailto:a@b", "host:443", "user:pass@host").
	Opaque
)

var schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)

// special are the schemes for which WHATWG parsers ignore the number and direction of the slashes after "scheme:".
var special = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true}

// Classify returns v as a lenient URL parser reads it and its shape. Surrounding Unicode spaces are dropped as well,
// as Go's strings.TrimSpace does. For an Authority value the result is in
// "scheme://…" (or "//…") form with a lower-case scheme, and "\" read as "/" before any query or fragment where
// the parser does so. A NotURL value is returned unchanged; an Opaque one trimmed of what the parser ignores.
func Classify(v string) (string, Shape) {
	// Unicode spaces too: Go readers (connsync.ParseBaseURL, the SCIM probe) TrimSpace a value before parsing it, so
	// "\u00a0https://u:p@h" is "https://u:p@h" to them.
	s := strings.TrimFunc(v, func(r rune) bool { return r <= 0x20 || unicode.IsSpace(r) })
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	if m := schemeRe.FindString(s); m != "" {
		scheme, rest := strings.ToLower(m[:len(m)-1]), s[len(m):]
		switch {
		case special[scheme]:
			return scheme + "://" + slashes(strings.TrimLeft(rest, `/\`)), Authority
		case strings.HasPrefix(rest, "//"):
			return scheme + ":" + rest, Authority
		}
		return s, Opaque
	}
	if len(s) >= 2 && isSlash(s[0]) && isSlash(s[1]) {
		// scheme-relative: against an http(s) page either slash starts the authority
		return "//" + slashes(strings.TrimLeft(s, `/\`)), Authority
	}
	return v, NotURL
}

// HasAuthority reports whether v reads as a URL that names a host.
func HasAuthority(v string) bool {
	_, sh := Classify(v)
	return sh == Authority
}

// URLKey reports whether a settings key names a URL: "url", "uri" or "endpoint" in it, in any case.
func URLKey(k string) bool {
	lk := strings.ToLower(k)
	return strings.Contains(lk, "url") || strings.Contains(lk, "uri") || strings.Contains(lk, "endpoint")
}

// URLSetting reports whether a settings entry holds a URL: its key names one, or its value reads as a URL that
// names a host.
func URLSetting(k, v string) bool {
	return URLKey(k) || HasAuthority(v)
}

// Embedded reports whether v, read as anything but a URL that names a host, still holds a "scheme://" URL ("note:
// https://u:p@h"): no parser reads v as that URL, but a credential in it is kept in clear all the same.
func Embedded(v string) bool {
	_, sh := Classify(v)
	return sh != Authority && strings.Contains(v, "://")
}

func isSlash(c byte) bool { return c == '/' || c == '\\' }

// slashes reads "\" as "/" up to the first "?" or "#".
func slashes(s string) string {
	end := strings.IndexAny(s, "?#")
	if end < 0 {
		end = len(s)
	}
	return strings.ReplaceAll(s[:end], `\`, "/") + s[end:]
}

// Fold returns v as a reader sees it, for detection only (issue #932): Unicode format characters (zero-width space
// and joiners, bidi marks, soft hyphen, BOM) dropped, then NFKC, which reads compatibility forms as the ASCII
// characters they render as, then combining marks NFKC left uncomposed are dropped and the look-alikes in
// confusables read as ":" and "/": fullwidth "\uff1a" "\uff0f" "\uff20" "\uff3c" "\uff1f" "\uff03" "\uff0e" and
// letters, small forms "\ufe55" "\ufe6b". The ideographic full stops IDNA reads as "." (U+3002, U+FF61) are read as
// "." too. A credentialed URL written with any of them is still a credential to whoever reads the value, so the
// refusal, the masks and the export cleaner look at Fold(v) as well as v. Never store or export the result.
func Fold(v string) string {
	if isASCII(v) {
		return v
	}
	drop := func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}
	s := strings.Map(drop, norm.NFKC.String(strings.Map(drop, v)))
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			// a combining mark NFKC did not compose ("https:\u0338//"): the separator under it still reads as one
			return -1
		}
		if r == '\u3002' || r == '\uff61' {
			return '.'
		}
		if a, ok := confusables[r]; ok {
			return a
		}
		return r
	}, s)
}

// confusables are look-alikes of URL separators that NFKC leaves alone: every entry of Unicode's confusables.txt
// for ":" and "/" that NFKC does not already map (fold_test.go checks each entry against NFKC, so the table holds
// only what NFKC misses; U+2F03 and U+FF89 reach U+4E3F and U+30CE through NFKC). Letters and signs are included
// (modifier letter colons, visarga signs, katakana "no"): Fold is for detection only, and reading one as a separator
// can only make a value look more like a credentialed URL, never less. No "@" look-alike survives NFKC (U+FF20 and
// U+FE6B are NFKC forms).
var confusables = map[rune]rune{
	// colon
	'\u02d0': ':', '\u02f8': ':', '\u0589': ':', '\u05c3': ':', '\u0703': ':', '\u0704': ':', '\u0831': ':',
	'\u0903': ':', '\u0a83': ':', '\u1361': ':', '\u1393': ':', '\u16ec': ':', '\u1803': ':', '\u1809': ':',
	'\u205a': ':', '\u2236': ':', '\ua4fd': ':', '\ua789': ':', '\U00010aF5': ':', '\U0001015b': ':',
	'\U00011002': ':', '\U00011082': ':', '\U00011182': ':', '\U000115be': ':', '\U000116ac': ':',
	'\U00011838': ':', '\U0001123a': ':', '\U00011dd9': ':', '\U0001d108': ':',
	// slash
	'\u1735': '/', '\u2041': '/', '\u2044': '/', '\u2215': '/', '\u2571': '/', '\u27cb': '/', '\u29f8': '/',
	'\u2cc6': '/', '\u2cc7': '/', '\u3033': '/', '\u30ce': '/', '\u31d2': '/', '\u31d3': '/', '\u4e3f': '/',
	'\U0001d23a': '/',
}

// NonASCIIHead reports whether the scheme or authority of v holds a non-ASCII character: everything before the
// first "/" or "\", and, when that starts "//", up to the next "/", "\", "?" or "#". A value without a "/" is
// all head. A percent-encoded non-ASCII byte in the head ("%E2%88%B6") counts as non-ASCII: parsers decode it in a
// host. International host names must be given as punycode, so a look-alike colon, slash or "@" in the head
// is refused rather than guessed at (issue #936).
func NonASCIIHead(v string) bool {
	s := strings.TrimSpace(v)
	end := len(s)
	if i := strings.IndexAny(s, `/\`); i >= 0 {
		end = i
		if i+1 < len(s) && isSlash(s[i+1]) {
			if j := strings.IndexAny(s[i+2:], `/\?#`); j >= 0 {
				end = i + 2 + j
			} else {
				end = len(s)
			}
		}
	}
	return !isASCII(s[:end]) || pctHigh(s[:end])
}

// pctHigh reports whether s holds a percent-encoded non-ASCII byte: net/url and WHATWG parsers decode "%E2%88%B6" in
// a host to U+2236, so an ASCII-only head can still name a non-ASCII authority.
func pctHigh(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && strings.IndexByte("89abcdefABCDEF", s[i+1]) >= 0 && isHex(s[i+2]) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
