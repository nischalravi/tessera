package glob

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func mustCompile(t testing.TB, src string, fold bool) *Pattern {
	t.Helper()
	p, err := Compile(src, fold)
	if err != nil {
		t.Fatalf("Compile(%q): %v", src, err)
	}
	return p
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		fold    bool
		subject string
		want    bool
	}{
		{"empty matches empty", "", false, "", true},
		{"empty does not match text", "", false, "a", false},
		{"star matches empty", "*", false, "", true},
		{"star matches anything", "*", false, "arn:aws:s3:::b/k", true},
		{"literal", "s3:GetObject", false, "s3:GetObject", true},
		{"literal mismatch", "s3:GetObject", false, "s3:GetObjectAcl", false},
		{"suffix star", "s3:Get*", false, "s3:GetObject", true},
		{"suffix star matches none", "s3:Get*", false, "s3:Get", true},
		{"infix star", "s3:Get*Object", false, "s3:GetBucketObject", true},
		{"infix star needs tail", "s3:Get*Object", false, "s3:GetObjectAcl", false},
		{"service wildcard", "*:Describe*", false, "ec2:DescribeInstances", true},
		{"question one char", "q?", false, "q1", true},
		{"question not zero", "q?", false, "q", false},
		{"question not two", "q?", false, "q10", false},
		{"question is one rune", "q?", false, "qé", true},
		{"question is one rune (4 byte)", "?x", false, "\U0001F600x", true},
		{"question then star", "?*", false, "", false},
		{"multiple stars", "*a*a*a*a*a*b", false, "aaaaaaaaaaaab", true},
		{"multiple stars miss", "*a*a*a*a*a*b", false, "aaaaaaaaaaaa", false},
		{"star backtrack", "*ab*c", false, "aabxabc", true},
		{"log glob crosses slash", "arn:aws:s3:::*log*", false, "arn:aws:s3:::tsr-applog/x", true},
		{"regexp metacharacters are literal", "a.b+c(d)[e]{f}^$|\\", false, "a.b+c(d)[e]{f}^$|\\", true},
		{"dot is not any char", "a.c", false, "abc", false},
		{"plus is literal", "a+", false, "aa", false},
		{"case sensitive by default", "S3:GetObject", false, "s3:getobject", false},
		{"fold matches action case", "S3:getobject", true, "s3:GetObject", true},
		{"fold applies to wildcard patterns", "S3:Get*", true, "s3:GETOBJECT", true},
		{"fold is ASCII only", "é", true, "É", false},
		{"fold does not fold Kelvin sign", "k", true, "K", false},
		{"multibyte literal", "café*", false, "cafés", true},
		{"star does not split a rune", "?", false, "é", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustCompile(t, tc.pattern, tc.fold).Match(tc.subject); got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.subject, got, tc.want)
			}
		})
	}
}

func TestCompileEscaped(t *testing.T) {
	tests := []struct {
		pattern string
		subject string
		want    bool
	}{
		{"${*}", "*", true},
		{"${*}", "abc", false},
		{"${?}", "?", true},
		{"${?}", "a", false},
		{"${$}", "$", true},
		{"a${*}b*", "a*bxyz", true},
		{"a${*}b*", "aXbxyz", false},
		{"${aws:username}", "${aws:username}", true}, // other variables are literal here (PR-4 substitutes them)
		{"${*", "${*", true},
		{"$", "$", true},
	}
	for _, tc := range tests {
		p, err := CompileEscaped(tc.pattern, false)
		if err != nil {
			t.Fatalf("CompileEscaped(%q): %v", tc.pattern, err)
		}
		if got := p.Match(tc.subject); got != tc.want {
			t.Errorf("CompileEscaped(%q).Match(%q) = %v, want %v", tc.pattern, tc.subject, got, tc.want)
		}
	}
	// The plain compiler never interprets escapes.
	if !mustCompile(t, "${*}", false).Match("${anything}") {
		t.Error("Compile must treat ${*} as '$', '{', wildcard, '}'")
	}
}

func TestCompileRejects(t *testing.T) {
	if _, err := Compile("a\xffb", false); err != ErrInvalidUTF8 {
		t.Errorf("invalid UTF-8: err = %v", err)
	}
	if _, err := Compile(strings.Repeat("a", MaxPatternBytes+1), false); err != ErrTooLong {
		t.Errorf("oversized: err = %v", err)
	}
	if _, err := Compile(strings.Repeat("a", MaxPatternBytes), false); err != nil {
		t.Errorf("at the cap: err = %v", err)
	}
}

func TestPatternShape(t *testing.T) {
	if !mustCompile(t, "ab*", false).EndsInStar() || mustCompile(t, "ab", false).EndsInStar() || mustCompile(t, "", false).EndsInStar() {
		t.Error("EndsInStar")
	}
	p, _ := CompileEscaped("ab${*}", false)
	if p.EndsInStar() {
		t.Error("an escaped star is a literal")
	}
	if !mustCompile(t, "**", false).IsAll() || mustCompile(t, "*a", false).IsAll() || mustCompile(t, "", false).IsAll() {
		t.Error("IsAll")
	}
	if mustCompile(t, "a*b", false).String() != "a*b" {
		t.Error("String")
	}
}

// TestMatchWorstCase is the §8.5 ReDoS check: a pattern with 1000 stars and a
// subject that nearly matches returns false quickly.
func TestMatchWorstCase(t *testing.T) {
	s := strings.Repeat("a", 10_000)
	// The second pattern is the real quadratic shape: every restart rescans 1000 bytes.
	// It is ~10 ms normally and ~10x that under -race, so its bound is loose: it proves
	// "polynomial", while the design's pattern keeps the 50 ms bound of §8.5.
	for _, c := range []struct {
		src   string
		limit time.Duration
	}{
		{strings.Repeat("*a", 1000) + "b", 50 * time.Millisecond},
		{"*" + strings.Repeat("a", 1000) + "b", 2 * time.Second},
	} {
		p := mustCompile(t, c.src, false)
		start := time.Now()
		if p.Match(s) {
			t.Fatal("must not match")
		}
		if d := time.Since(start); d > c.limit {
			t.Fatalf("worst case took %v (limit %v)", d, c.limit)
		}
	}
}

// refRegexp is the reference oracle. It lives in test code only.
func refRegexp(pattern string, fold bool) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString("^(?s)")
	if fold {
		sb.WriteString("(?i)")
	}
	var lit strings.Builder
	flush := func() {
		sb.WriteString(regexp.QuoteMeta(lit.String()))
		lit.Reset()
	}
	for _, r := range pattern {
		switch r {
		case '*':
			flush()
			sb.WriteString(".*")
		case '?':
			flush()
			sb.WriteString(".")
		default:
			lit.WriteRune(r)
		}
	}
	flush()
	sb.WriteString("$")
	return regexp.MustCompile(sb.String())
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func FuzzMatchAgreesWithRegexp(f *testing.F) {
	seeds := [][2]string{
		{"*a*a*a*a*a*b", "aaaaaaaaaab"},
		{"q?", "q1"},
		{"q?", "q10"},
		{"arn:aws:s3:::*log*", "arn:aws:s3:::tsr-applog/x"},
		{"${*}", "*"},
		{"${*}", "${x}"},
		{"?", "é"},
		{"é?", "é\U0001F600"},
		{"a?b", "aéb"},
		{"a.b+c", "a.b+c"},
		{"S3:Get*", "s3:getobject"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], false)
		f.Add(s[0], s[1], true)
	}
	f.Fuzz(func(t *testing.T, pattern, subject string, fold bool) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(subject) {
			t.Skip()
		}
		if fold && (!isASCII(pattern) || !isASCII(subject)) {
			t.Skip() // (?i) in RE2 folds Unicode; the matcher folds ASCII only
		}
		p, err := Compile(pattern, fold)
		if err != nil {
			t.Skip()
		}
		if got, want := p.Match(subject), refRegexp(pattern, fold).MatchString(subject); got != want {
			t.Fatalf("Match(%q, %q, fold=%v) = %v, regexp says %v", pattern, subject, fold, got, want)
		}
	})
}

func FuzzCompile(f *testing.F) {
	for _, s := range []string{"", "*", "?", "s3:*", "${*}", "a\xffb", "é*", strings.Repeat("*a", 100)} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Add(strings.Repeat("a", MaxPatternBytes+1), false)
	f.Fuzz(func(t *testing.T, src string, fold bool) {
		for _, compile := range []func(string, bool) (*Pattern, error){Compile, CompileEscaped} {
			p, err := compile(src, fold)
			wantErr := len(src) > MaxPatternBytes || !utf8.ValidString(src)
			if (err != nil) != wantErr {
				t.Fatalf("compile(%q): err = %v, want error %v", src, err, wantErr)
			}
			if err != nil {
				continue
			}
			if len(p.b) != len(p.k) {
				t.Fatalf("parallel slices differ for %q", src)
			}
			p.Match("")
			p.Match(src)
			p.Match("arn:aws:s3:::bucket/key")
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	cases := []struct {
		name, pattern, subject string
		fold                   bool
	}{
		{"action_prefix", "s3:Get*", "s3:GetObject", true},
		{"action_literal", "s3:GetObject", "s3:GetObject", true},
		{"arn_bucket_star", "arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/some/deep/key.txt", false},
		{"arn_infix", "arn:aws:s3:::*log*", "arn:aws:s3:::tsr-applog/x", false},
		{"worst_case", strings.Repeat("*a", 1000) + "b", strings.Repeat("a", 10_000), false},
	}
	for _, c := range cases {
		p, err := Compile(c.pattern, c.fold)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p.Match(c.subject)
			}
		})
	}
}
