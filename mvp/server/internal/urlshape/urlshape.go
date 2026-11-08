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

// Classify returns v as a lenient URL parser reads it and its shape. For an Authority value the result is in
// "scheme://…" (or "//…") form with a lower-case scheme, and "\" read as "/" before any query or fragment where
// the parser does so. A NotURL value is returned unchanged; an Opaque one trimmed of what the parser ignores.
func Classify(v string) (string, Shape) {
	s := strings.TrimFunc(v, func(r rune) bool { return r <= 0x20 })
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

func isSlash(c byte) bool { return c == '/' || c == '\\' }

// slashes reads "\" as "/" up to the first "?" or "#".
func slashes(s string) string {
	end := strings.IndexAny(s, "?#")
	if end < 0 {
		end = len(s)
	}
	return strings.ReplaceAll(s[:end], `\`, "/") + s[end:]
}
