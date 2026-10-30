package lpauto_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/lpauto"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

func TestKindsAreTheAutoEligibleOnes(t *testing.T) {
	want := []string{target.AWSDetachPolicy, target.AWSDeleteInlinePolicy, target.AWSSetPolicyVersion, target.AWSRemoveFromGroup, target.AWSDeleteAssignment}
	if !slices.Equal(lpauto.Kinds, want) {
		t.Errorf("Kinds = %v, want %v", lpauto.Kinds, want)
	}
}

func TestParse(t *testing.T) {
	const ok = "version: 1\nkinds: [aws_set_policy_version]\n"
	tests := []struct {
		name, in, wantErr string
	}{
		{"minimal, safe defaults", ok, ""},
		{"full", ok + "confidence: high\nmin_unused_days: 120\nmax_per_day: 20\naccounts: ['111122223333']\nexclude_break_glass: true\nprivileged_prod: suggest\n", ""},
		{"empty", "", "empty"},
		{"no version", "kinds: [aws_detach_policy]\n", "version must be"},
		{"no kinds", "version: 1\n", "kinds is required"},
		{"medium confidence", ok + "confidence: medium\n", "confidence must be"},
		{"under 90 days", ok + "min_unused_days: 60\n", "min_unused_days is"},
		{"over a year", ok + "min_unused_days: 366\n", "min_unused_days is"},
		{"too many per day", ok + "max_per_day: 101\n", "max_per_day is"},
		{"zero per day", ok + "max_per_day: 0\n", "max_per_day is"},
		{"break-glass included", ok + "exclude_break_glass: false\n", "exclude_break_glass cannot be false"},
		{"privileged prod auto", ok + "privileged_prod: auto\n", "privileged_prod must be"},
		{"a kind that is never auto", "version: 1\nkinds: [aws_trust_policy]\n", "not auto-eligible"},
		{"a kind twice", "version: 1\nkinds: [aws_detach_policy, aws_detach_policy]\n", "named twice"},
		{"a bad account", ok + "accounts: ['123']\n", "12-digit"},
		{"unknown field", ok + "cap_per_run: 500\n", "cap_per_run"},
		{"two documents", ok + "---\nversion: 1\n", "more than one"},
		{"not yaml", "kinds: [", "lp/auto.yaml"},
		{"too large", ok + "# " + strings.Repeat("x", lpauto.MaxFileBytes), "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := lpauto.Parse([]byte(tt.in))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Parse = %v", err)
				}
				if p.Confidence != "high" || !p.ExcludeBreakGlass || p.PrivilegedProd != "suggest" || p.MinUnusedDays < 90 {
					t.Errorf("unsafe policy: %+v", p)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestDigestIsStableAndRoundTrips(t *testing.T) {
	a, err := lpauto.Parse([]byte("version: 1\nkinds: [aws_set_policy_version, aws_detach_policy]\naccounts: ['222222222222', '111122223333']\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := lpauto.Parse([]byte("# comment\nkinds: [aws_detach_policy, aws_set_policy_version]\nversion: 1\naccounts: ['111122223333', '222222222222']\nmin_unused_days: 90\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() || len(a.Digest()) != 64 {
		t.Errorf("the same policy written differently has two digests: %s %s", a.Digest(), b.Digest())
	}
	back, err := lpauto.FromJSON(a.Canonical())
	if err != nil || back.Digest() != a.Digest() {
		t.Errorf("round trip = %v, %v", back, err)
	}
	for _, bad := range []string{`{}`, strings.Replace(a.Canonical(), `"high"`, `"medium"`, 1), strings.Replace(a.Canonical(), `"min_unused_days":90`, `"min_unused_days":1`, 1),
		strings.Replace(a.Canonical(), `"exclude_break_glass":true`, `"exclude_break_glass":false`, 1), `{"x":1}`} {
		if _, err := lpauto.FromJSON(bad); err == nil {
			t.Errorf("FromJSON accepted %s", bad)
		}
	}
}

func TestAllows(t *testing.T) {
	p, err := lpauto.Parse([]byte("version: 1\nkinds: [aws_set_policy_version]\nmin_unused_days: 100\naccounts: ['111122223333']\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := lpauto.Candidate{Kind: "aws_set_policy_version", Account: "111122223333", Confidence: "high", UnusedDays: 100}
	if why := p.Allows(c); why != "" {
		t.Errorf("a covered candidate was refused: %s", why)
	}
	for name, mut := range map[string]func(*lpauto.Candidate){
		"medium": func(c *lpauto.Candidate) { c.Confidence = "medium" },
		"unused": func(c *lpauto.Candidate) { c.UnusedDays = 99 },
		"kind":   func(c *lpauto.Candidate) { c.Kind = "aws_detach_policy" },
		"acct":   func(c *lpauto.Candidate) { c.Account = "999999999999" },
	} {
		x := c
		mut(&x)
		if p.Allows(x) == "" {
			t.Errorf("%s: a candidate outside the policy was allowed", name)
		}
	}
}
