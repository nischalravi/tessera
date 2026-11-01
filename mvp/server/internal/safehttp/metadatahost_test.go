package safehttp

import "testing"

func TestIsMetadataHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"metadata.google.internal", true},
		{"Metadata.Google.Internal.", true},
		{"metadata.goog", true},
		{"instance-data.ec2.internal", true},
		{"169.254.169.254", true},
		{"::ffff:169.254.169.254", true},
		{"169.254.170.2", true},
		{"fd00:ec2::254", true},
		{"[FD00:EC2:0::254]", true},
		{"100.100.100.200", true},
		{"168.63.129.16", true},
		{"api.example.com", false},
		{"metadata.example.com", false},
		{"169.254.1.1", false}, // link-local, but not a metadata address: the dial guard refuses it
		{"8.8.8.8", false},
		{"", false},
	} {
		if got := IsMetadataHost(tc.host); got != tc.want {
			t.Errorf("IsMetadataHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
