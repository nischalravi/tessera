package safehttp

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
)

// Origin is where a request to raw would go: scheme://host:port, case
// folded, with the default port of http and https filled in. Two URLs with
// the same Origin differ only in path, query or fragment. A stored credential
// bound to a destination must not follow an edit that changes it (#315,
// #332). An unparsable URL has no origin: Origin returns "" and never the
// input, which may carry a token. Use OriginKey to compare destinations.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// OriginKey is Origin for comparing two destinations: an unparsable URL is its own origin (a digest of it, so no
// text of the URL is kept), so any change to it counts as a change of origin.
func OriginKey(raw string) string {
	if o := Origin(raw); o != "" {
		return o
	}
	sum := sha256.Sum256([]byte(raw))
	return "unparsable:" + hex.EncodeToString(sum[:8])
}
