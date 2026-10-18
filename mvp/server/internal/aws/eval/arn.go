// Package eval holds the evaluator's matching rules (design §8). PR-3 covers
// action, resource and principal matching; the engine and conditions follow in
// later PRs. The package does no I/O and reads no clock.
package eval

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/glob"
)

// ARNPattern is a compiled resource pattern for arn_glob (§8.3, default for
// ambiguity A1). Patterns are compiled once, when the snapshot is built.
//
// The pattern and the ARN are split on their first five ':' into up to six
// segments (the sixth keeps any further ':'):
//   - segments 1-5 (arn, partition, service, region, account) match one by one,
//     and '*' and '?' stay inside the segment;
//   - a '*' that ends segment 3, 4 or 5 (service, region, account), when every
//     later pattern segment is empty or '*', matches the rest of the ARN, colons
//     included (arn:aws:s3:* matches every S3 ARN);
//   - the sixth segment is the rest of the string and matches as one glob, so
//     '*' there crosses '/' and ':'.
//
// A non-trailing '*' never crosses a colon. A pattern with fewer than six
// segments that is not closed by the trailing-star rule matches nothing: the
// parser completes incomplete ARNs where AWS does (PatternSet.Completed).
type ARNPattern struct {
	src      string
	all      bool // the pattern is exactly "*"
	parts    []*glob.Pattern
	trailing [5]bool // trailing[i]: a trailing '*' in segment i absorbs the rest of the ARN
}

// CompileARN compiles one resource pattern. It fails on invalid UTF-8 and on
// oversized patterns. Variables must already be substituted (§9.3).
func CompileARN(pattern string) (*ARNPattern, error) {
	a := &ARNPattern{src: pattern, all: pattern == "*"}
	if a.all {
		return a, nil
	}
	segs := strings.SplitN(pattern, ":", 6)
	a.parts = make([]*glob.Pattern, len(segs))
	for i, s := range segs {
		p, err := glob.Compile(s, false)
		if err != nil {
			return nil, err
		}
		a.parts[i] = p
	}
	for i := 2; i <= 4 && i < len(a.parts); i++ {
		if !a.parts[i].EndsInStar() {
			continue
		}
		a.trailing[i] = true
		for _, later := range a.parts[i+1:] {
			if !later.IsAll() && later.String() != "" {
				a.trailing[i] = false
				break
			}
		}
	}
	return a, nil
}

// String returns the pattern text.
func (a *ARNPattern) String() string { return a.src }

// IsStar reports whether the pattern is exactly "*".
func (a *ARNPattern) IsStar() bool { return a.all }

// Match reports whether the ARN matches the pattern. It does not allocate.
func (a *ARNPattern) Match(arn string) bool {
	if a.all {
		return true
	}
	rest, have := arn, true // have: the segment starting at rest exists
	for i := 0; i < 5; i++ {
		if i >= len(a.parts) || !have {
			return false
		}
		seg, next, found := strings.Cut(rest, ":")
		if !a.parts[i].Match(seg) {
			return false
		}
		if a.trailing[i] {
			return true // the trailing '*' absorbs the rest of the segment and of the ARN
		}
		rest, have = next, found
	}
	if len(a.parts) < 6 || !have {
		return false
	}
	return a.parts[5].Match(rest)
}
