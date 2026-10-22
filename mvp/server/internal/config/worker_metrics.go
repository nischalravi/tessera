package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// The connector worker's metrics listener (issue #302): `tessera worker
// -metrics-addr` or TESSERA_WORKER_METRICS_ADDR. A worker has no HTTP API, so
// its Prometheus endpoint is the only listener it opens, and it is off unless
// an address is given (several workers share a host; there is no default
// port to collide on).
//
// The metrics name tenants' connections only by counts, but they are still an
// operator surface, so the guard rail is simple: the address must be an IP
// literal on a loopback, private or link-local network. A wildcard bind, a
// public address and a host name (which can resolve anywhere) are refused
// unless TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true says that a network policy
// limits the scraper. The rule is the same in every environment, so a dev
// setup cannot grow into a production one by accident.

// CheckWorkerMetricsAddr validates a worker metrics listen address. An empty
// address (or off/none/false) is valid and means no listener.
func CheckWorkerMetricsAddr(addr string, allowPublic bool) (string, error) {
	addr = strings.TrimSpace(addr)
	switch strings.ToLower(addr) {
	case "", "off", "none", "false":
		return "", nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q has no usable port", addr)
	}
	if a, perr := netip.ParseAddr(host); perr == nil {
		a = a.Unmap()
		if !a.IsUnspecified() && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()) {
			return addr, nil
		}
		if allowPublic {
			return addr, nil
		}
		if a.IsUnspecified() {
			return "", fmt.Errorf("%s listens on every interface: bind a loopback or private address, or set TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true when a network policy limits the scraper", addr)
		}
		return "", fmt.Errorf("%s is a public address: bind a loopback or private address, or set TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true when a network policy limits the scraper", addr)
	}
	switch {
	case host == "":
		if !allowPublic {
			return "", fmt.Errorf("%s listens on every interface: bind a loopback or private address, or set TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true when a network policy limits the scraper", addr)
		}
		return addr, nil
	case allowPublic:
		return addr, nil
	}
	return "", errors.New(addr + ": use an IP literal (a host name can resolve to a public address), or set TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true")
}
