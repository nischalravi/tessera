package eval

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

func TestGlobCapMatchesPolicyLimit(t *testing.T) {
	if glob.MaxPatternBytes != policy.DefaultLimits.MaxStringBytes {
		t.Errorf("glob.MaxPatternBytes = %d, policy.DefaultLimits.MaxStringBytes = %d", glob.MaxPatternBytes, policy.DefaultLimits.MaxStringBytes)
	}
}

func TestARNGlob(t *testing.T) {
	const bkt = "arn:aws:s3:::tsr-bkt/"
	tests := []struct {
		name    string
		pattern string
		arn     string
		want    bool
	}{
		{"star matches all", "*", "arn:aws:s3:::b/k", true},
		{"star matches non-arn", "*", "anything", true},
		{"exact", "arn:aws:s3:::b", "arn:aws:s3:::b", true},
		{"exact mismatch", "arn:aws:s3:::b", "arn:aws:s3:::c", false},
		{"case sensitive (GC-05)", "arn:aws:s3:::TSR-BKT/*", bkt + "a", false},
		{"case sensitive in every segment", "ARN:aws:s3:::b", "arn:aws:s3:::b", false},
		{"IAM names are case sensitive", "arn:aws:iam::111111111111:user/Alice", "arn:aws:iam::111111111111:user/alice", false},
		{"star crosses slash in resource part (GC-06)", bkt + "*/test/*", bkt + "1/2/test/object.jpg", true},
		{"literal /test/ required (GC-07)", bkt + "*/test/*", bkt + "test/object.jpg", false},
		{"star crosses slash and colon in resource part", "arn:aws:logs:*:*:log-group:a*", "arn:aws:logs:us-east-1:111111111111:log-group:a/b:c:d", true},
		{"log glob (GC-03)", "arn:aws:s3:::*log*", "arn:aws:s3:::tsr-applog/x", true},
		{"question matches one char (GC-08)", "arn:aws:sqs:us-east-1:111111111111:q?", "arn:aws:sqs:us-east-1:111111111111:q1", true},
		{"question rejects two (GC-08)", "arn:aws:sqs:us-east-1:111111111111:q?", "arn:aws:sqs:us-east-1:111111111111:q10", false},
		{"colon in resource part is plain", "arn:aws:sqs:us-east-1:111111111111:a:b", "arn:aws:sqs:us-east-1:111111111111:a:b", true},
		{"question does not match colon-less gap", "arn:aws:s3:::b?c", "arn:aws:s3:::bc", false},
		// Segment-wise matching: wildcards in segments 1-5 stay inside the segment.
		{"region wildcard", "arn:aws:sqs:*:111111111111:q", "arn:aws:sqs:us-east-1:111111111111:q", true},
		{"mid star does not cross colon", "arn:aws:sqs:*:queue", "arn:aws:sqs:us-east-1:111111111111:queue", false},
		{"non-trailing star in service does not cross", "arn:aws:s*3:::b", "arn:aws:s:x3:::b", false},
		{"embedded star in region", "arn:aws:sqs:us-*-1:111111111111:q", "arn:aws:sqs:us-east-1:111111111111:q", true},
		{"embedded star does not cross colon", "arn:aws:sqs:us-*:111111111111:q", "arn:aws:sqs:us-east:1:111111111111:q", false},
		// A1: a '*' ending segments 3-5 matches the rest of the ARN.
		{"A1 service star", "arn:aws:s3:*", "arn:aws:s3:::tsr-bkt/a", true},
		{"A1 service star other service", "arn:aws:s3:*", "arn:aws:sqs:us-east-1:111111111111:q", false},
		{"A1 region star and colons", "arn:aws:sqs:us-east-1:*", "arn:aws:sqs:us-east-1:111111111111:q:x", true},
		{"A1 region star wrong region", "arn:aws:sqs:us-east-1:*", "arn:aws:sqs:eu-west-1:111111111111:q", false},
		{"A1 prefix then star in service", "arn:aws:s*", "arn:aws:s3:::b/k", true},
		{"A1 prefix then star wrong prefix", "arn:aws:e*", "arn:aws:s3:::b/k", false},
		{"A1 trailing star with later stars", "arn:aws:s3:*:*:*", "arn:aws:s3:::b", true},
		{"A1 trailing star blocked by later literal", "arn:aws:sqs:*:*:queue", "arn:aws:sqs:us-east-1:111111111111:other", false},
		{"A1 account star", "arn:aws:iam::*", "arn:aws:iam::111111111111:user/a", true},
		{"A1 account star, 5 segments only", "arn:aws:iam::1111*", "arn:aws:iam::111122223333:role/r", true},
		{"A1 needs the segment to exist", "arn:aws:s3:::*", "arn:aws:s3", false},
		{"short pattern without trailing star", "arn:aws:sqs", "arn:aws:sqs:us-east-1:111111111111:q", false},
		{"short pattern, 5 segments, no star", "arn:aws:sqs:us-east-1:111111111111", "arn:aws:sqs:us-east-1:111111111111:q", false},
		{"arn shorter than pattern", "arn:aws:sqs:us-east-1:111111111111:q", "arn:aws:sqs:us-east-1", false},
		{"empty arn", "arn:aws:s3:::b", "", false},
		{"metacharacters are literal", "arn:aws:s3:::b/a+(b)[c]{d}.txt", "arn:aws:s3:::b/a+(b)[c]{d}.txt", true},
		{"dot is not a wildcard", "arn:aws:s3:::b/a.txt", "arn:aws:s3:::b/aXtxt", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CompileARN(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Match(tc.arn); got != tc.want {
				t.Errorf("arn_glob(%q, %q) = %v, want %v", tc.pattern, tc.arn, got, tc.want)
			}
		})
	}
}

func TestCompileARNRejects(t *testing.T) {
	if _, err := CompileARN("arn:aws:s3:::\xff"); err == nil {
		t.Error("invalid UTF-8 must be rejected")
	}
	if _, err := CompileARN("arn:aws:s3:::" + strings.Repeat("a", glob.MaxPatternBytes+1)); err == nil {
		t.Error("oversized pattern must be rejected")
	}
}

func TestARNPatternAccessors(t *testing.T) {
	p, _ := CompileARN("*")
	if !p.IsStar() || p.String() != "*" {
		t.Error("star accessors")
	}
	q, _ := CompileARN("arn:aws:s3:*")
	if q.IsStar() || q.String() != "arn:aws:s3:*" {
		t.Error("non-star accessors")
	}
}

func TestARNMatchDoesNotAllocate(t *testing.T) {
	p, _ := CompileARN("arn:aws:s3:::bucket/*")
	if n := testing.AllocsPerRun(100, func() { p.Match("arn:aws:s3:::bucket/some/key") }); n != 0 {
		t.Errorf("Match allocates %v times", n)
	}
}

func FuzzARNGlobNeverPanics(f *testing.F) {
	f.Add("arn:aws:s3:*", "arn:aws:s3:::b")
	f.Add("arn:aws:sqs:*:queue", "arn:aws:sqs:us-east-1:1:queue")
	f.Add("*", "")
	f.Add(":::::*", ":::::")
	f.Fuzz(func(t *testing.T, pattern, arn string) {
		p, err := CompileARN(pattern)
		if err != nil {
			return
		}
		if got := p.Match(arn); pattern == "*" && !got {
			t.Fatal(`"*" must match everything`)
		}
		// A pattern that is also a valid ARN always matches itself when it has no wildcard.
		if !strings.ContainsAny(pattern, "*?") && strings.Count(pattern, ":") >= 5 && !p.Match(pattern) {
			t.Fatalf("%q does not match itself", pattern)
		}
	})
}
