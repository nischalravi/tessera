package eval

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseDecimal(t *testing.T) {
	good := map[string]string{ // input -> canonical
		"0": "0", "-0": "0", "+5": "5", "007": "7", "1.50": "1.5", ".5": "0.5", "-0.0": "0", "10.010": "10.01",
	}
	for in, want := range good {
		d, ok := parseDecimal(in)
		if !ok {
			t.Errorf("%q should parse", in)
			continue
		}
		var got string
		switch {
		case d.ip == "" && d.frac == "":
			got = "0"
		default:
			got = d.ip
			if got == "" {
				got = "0"
			}
			if d.frac != "" {
				got += "." + d.frac
			}
			if d.neg {
				got = "-" + got
			}
		}
		if got != want {
			t.Errorf("%q canonical %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "-", "+", ".", "1.", "1e3", "NaN", "Inf", " 1", "1 ", "1,5", "0x10", "--1", strings.Repeat("9", maxDecimalLen+1)} {
		if _, ok := parseDecimal(in); ok {
			t.Errorf("%q should not parse", in)
		}
	}
}

func TestDecimalOrder(t *testing.T) {
	order := []string{"-100", "-10.5", "-10.49", "-0.1", "0", "0.001", "0.01", "0.1", "1", "1.5", "2", "10", "100.25", "1000"}
	for i, a := range order {
		for j, b := range order {
			da, _ := parseDecimal(a)
			db, _ := parseDecimal(b)
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := da.compare(db); got != want {
				t.Errorf("compare(%s,%s)=%d want %d", a, b, got, want)
			}
		}
	}
}

func FuzzDecimalCompare(f *testing.F) {
	for _, s := range [][2]string{{"1", "1.0"}, {"-0", "0"}, {"0.30000000000000004", "0.3"}, {"-5", "4.9"}, {"1e3", "1000"}, {"", "-"}, {"999999999999999999999", "1"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		da, oka := parseDecimal(a)
		db, okb := parseDecimal(b)
		if oka {
			if da.compare(da) != 0 {
				t.Fatalf("%q not equal to itself", a)
			}
			if r := da.rat(); r == nil {
				t.Fatal("nil rat")
			}
		}
		if oka && okb {
			c := da.compare(db)
			if c != -db.compare(da) {
				t.Fatalf("not antisymmetric for %q %q", a, b)
			}
			if c != da.rat().Cmp(db.rat()) {
				t.Fatalf("compare(%q,%q)=%d disagrees with big.Rat", a, b, c)
			}
		}
	})
}

func TestParseDate(t *testing.T) {
	eq := func(a, b string) {
		t.Helper()
		da, ok1 := parseDate(a)
		db, ok2 := parseDate(b)
		if !ok1 || !ok2 || da.compare(db) != 0 {
			t.Errorf("%q and %q should be the same instant (%v %v %v %v)", a, b, da, ok1, db, ok2)
		}
	}
	eq("2026-10-01T00:00:00Z", "1790812800")
	eq("2026-10-01T00:00:00Z", "2026-10-01")
	eq("2026-10-01T00:00:00Z", "2026-10-01T00:00")
	eq("2026-10-01T00:00:00Z", "2026-10-01T00:00:00")
	eq("2026-10-01T00:00:00Z", "2026-10-01T02:00:00+02:00")
	eq("2026-10-01T00:00:00Z", "2026-10-01T00:00Z")
	eq("2026-10-01T00:00:00.000Z", "2026-10-01T00:00:00Z")
	eq("2026-10-01", "2026-10-01T00:00:00Z")
	eq("2026-10", "2026-10-01")
	a, _ := parseDate("2026-10-01T00:00:00.5Z")
	b, _ := parseDate("2026-10-01T00:00:00Z")
	if a.compare(b) != 1 {
		t.Error("fractional seconds must order")
	}
	for _, s := range []string{"", "yesterday", "2026-13-01", "2026-10-32", "10/01/2026", " 2026-10-01", "-5", "1.5", strings.Repeat("9", 19), strings.Repeat("a", maxDateLen+1)} {
		if _, ok := parseDate(s); ok {
			t.Errorf("%q should not parse", s)
		}
	}
}

func FuzzDateParse(f *testing.F) {
	for _, s := range []string{"2026-10-01T00:00:00Z", "1790812800", "2026-10", "0000-01-01T00:00:00+23:59", "9999-12-31T23:59:59.999999999Z", "", "-1", "2026-10-01T00:00:60Z", "٣٤"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, ok := parseDate(s)
		d2, ok2 := parseDate(s)
		if ok != ok2 || d != d2 {
			t.Fatalf("parse of %q is not deterministic", s)
		}
		if ok {
			if d.nsec < 0 || d.nsec >= 1_000_000_000 {
				t.Fatalf("nsec out of range for %q: %d", s, d.nsec)
			}
			if d.compare(d) != 0 {
				t.Fatalf("%q not equal to itself", s)
			}
		}
	})
}

func TestIPParsing(t *testing.T) {
	if _, ok := parseIPValue("fe80::1%eth0"); ok {
		t.Error("zones must be rejected")
	}
	if a, ok := parseIPValue("::ffff:1.2.3.4"); !ok || !a.Is4() {
		t.Error("4in6 must unmap")
	}
	p, ok := parseIPPolicy("10.1.2.3/8")
	if !ok || p.String() != "10.0.0.0/8" {
		t.Errorf("policy prefix must be masked: %v", p)
	}
	if p, ok := parseIPPolicy("::ffff:10.0.0.0/104"); !ok || p.String() != "10.0.0.0/8" {
		t.Errorf("4in6 prefix: %v %v", p, ok)
	}
	if p, ok := parseIPPolicy("2001:db8::1"); !ok || p.Bits() != 128 {
		t.Errorf("bare v6: %v", p)
	}
	for _, s := range []string{"", "10.0.0.0/33", "10.0.0/8", "x", "10.0.0.0/-1"} {
		if _, ok := parseIPPolicy(s); ok {
			t.Errorf("%q should not parse", s)
		}
	}
	if got := lastAddr(netip.MustParsePrefix("10.0.0.0/8")); got.String() != "10.255.255.255" {
		t.Errorf("lastAddr %v", got)
	}
	if got := lastAddr(netip.MustParsePrefix("2001:db8::/32")); got.String() != "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff" {
		t.Errorf("lastAddr v6 %v", got)
	}
}

func TestGlob(t *testing.T) {
	lit := func(s string) Pattern { return Pattern{Segs: []Seg{{Text: s}}} }
	tests := []struct {
		p, s string
		want bool
	}{
		{"", "", true}, {"", "a", false}, {"*", "", true}, {"*", "anything", true},
		{"a*", "abc", true}, {"*c", "abc", true}, {"a*c", "abc", true}, {"a*c", "ac", true}, {"a*c", "ab", false},
		{"a?c", "abc", true}, {"a?c", "ac", false}, {"?", "é", true}, {"??", "é", false},
		{"*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", false}, // the classic exponential case
		{"a**b", "ab", true}, {"*?*", "", false}, {"*?*", "x", true},
	}
	for _, tc := range tests {
		if got := likeMatch(lit(tc.p), tc.s); got != tc.want {
			t.Errorf("like(%q,%q)=%v want %v", tc.p, tc.s, got, tc.want)
		}
	}
	// Invalid UTF-8 on either side must not panic and must be consistent.
	if !likeMatch(lit("a?"), "a\xff") {
		t.Error("invalid byte counts as one character")
	}
}

// TestArnLikeShortPatterns pins the A1 default for patterns of fewer than six
// segments: a last segment ending in "*" absorbs the rest of the ARN from that
// segment on (segment 0 included), and a non-ARN value never matches.
func TestArnLikeShortPatterns(t *testing.T) {
	const arn = "arn:aws:sqs:us-east-1:111111111111:q"
	tests := []struct {
		name, pat, val string
		want           bool
	}{
		{"bare star", "*", arn, true},
		{"arn star", "arn:*", arn, true},
		{"partition star", "arn:aws:*", arn, true},
		{"service star", "arn:aws:s3:*", "arn:aws:s3:::bucket/k", true},
		{"service star, other service", "arn:aws:s3:*", arn, false},
		{"segment 0 star prefix", "a*", arn, true},
		{"segment 0 star prefix, mismatch", "b*", arn, false},
		{"star crosses colons from its segment", "arn:aws:sqs:*", arn, true},
		{"no trailing star, short pattern", "arn:aws:sqs", arn, false},
		{"bare star, not an arn", "*", "bucket", false},
		{"arn star, not an arn", "arn:*", "arn:aws", false},
		{"partition star, not an arn", "arn:aws:*", "arn:aws:s3:::", true},
		{"partition star, five segments", "arn:aws:*", "arn:aws:s3:us-east-1:1", false},
		{"service star, not an arn", "arn:aws:s3:*", "not-an-arn", false},
		{"service star, empty value", "arn:aws:s3:*", "", false},
		{"bare star, empty value", "*", "", false},
		{"six segments, star stays in segment", "arn:aws:*:::x", "arn:aws:sns:us-east-1:1:x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := arnLikeMatch(Pattern{Segs: []Seg{{Text: tc.pat}}}, tc.val); got != tc.want {
				t.Errorf("arnLikeMatch(%q, %q) = %v, want %v", tc.pat, tc.val, got, tc.want)
			}
		})
	}
}

func FuzzGlob(f *testing.F) {
	for _, s := range [][2]string{{"a*b", "axxb"}, {"*?*", ""}, {"${*}", "*"}, {"\xff*", "\xfe"}, {"arn:aws:s3:::*", "arn:aws:s3:::b"}, {"*", "arn:aws:s3:::b"}, {"arn:*", "arn:aws:s3:::b"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, p, s string) {
		pat := Pattern{Segs: []Seg{{Text: p}}}
		a := likeMatch(pat, s)
		if a != likeMatch(pat, s) {
			t.Fatal("not deterministic")
		}
		// "*" accepts everything; a pattern with no wildcards is equality
		// (after the same invalid-UTF-8 repair on both sides).
		if !likeMatch(Pattern{Segs: []Seg{{Text: "*"}}}, s) {
			t.Fatal("* must match")
		}
		_ = arnLikeMatch(pat, s)
	})
}
