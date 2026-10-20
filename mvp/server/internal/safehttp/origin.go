package safehttp

import (
	"net"
	"net/url"
	"strings"
)

// Origin is where a request to raw would go: scheme://host:port, case
// folded, with the default port of http and https filled in. Two URLs with
// the same Origin differ only in path, query or fragment. A stored credential
// bound to a destination must not follow an edit that changes it (#315,
// #332). An unparsable URL is returned as is, so any change to it counts as
// a change of origin.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[scheme]
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
