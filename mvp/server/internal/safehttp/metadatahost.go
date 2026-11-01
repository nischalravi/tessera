package safehttp

import (
	"net/netip"
	"strings"
)

// metadataHostNames are the DNS names the cloud metadata services answer to.
var metadataHostNames = map[string]bool{
	"metadata.google.internal":   true, // GCP
	"metadata.goog":              true, // GCP
	"metadata":                   true, // GCP short name
	"instance-data":              true, // AWS short name
	"instance-data.ec2.internal": true,
	"metadata.azure.internal":    true,
	"metadata.tencentyun.com":    true,
}

// metadataHostAddrs are the literal metadata addresses (the CIDR guard in Blocked also covers them at
// connect time; naming them lets a save-time check refuse them with a clear message).
var metadataHostAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, Azure, GCP, OpenStack
	netip.MustParseAddr("169.254.170.2"),   // ECS/Fargate container credentials
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba
	netip.MustParseAddr("192.0.0.192"),     // Oracle
	netip.MustParseAddr("168.63.129.16"),   // Azure wire server
}

// IsMetadataHost reports whether host (a bare host name or IP literal, as in url.URL.Hostname; the
// case, a trailing dot, brackets and IPv4-mapped IPv6 forms are normalised) names a cloud metadata
// service. Configuration that would point a connector there is refused at save time in every
// environment; the dial guard refuses the addresses at connect time as well.
func IsMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if metadataHostNames[h] {
		return true
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, m := range metadataHostAddrs {
		if a == m {
			return true
		}
	}
	return false
}
