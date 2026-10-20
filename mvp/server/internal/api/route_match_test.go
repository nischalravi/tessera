package api

import (
	"strings"
	"testing"
)

// {arn} is the one path variable that spans segments (an ARN holds slashes);
// every other variable is a single segment, as before.
func TestRouteMatch(t *testing.T) {
	route := func(pattern string) *route {
		return &route{pattern: pattern, segs: strings.Split(strings.TrimPrefix(pattern, "/"), "/")}
	}
	for _, tc := range []struct {
		pattern, path string
		vars          map[string]string
	}{
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/arn:aws:iam::1:user/alice/effective",
			map[string]string{"arn": "arn:aws:iam::1:user/alice"}},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/arn:aws:iam::1:role/a/b/c/effective",
			map[string]string{"arn": "arn:aws:iam::1:role/a/b/c"}},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/plain/effective", map[string]string{"arn": "plain"}},
		{"/api/aws/resources/{arn}/who-can", "/api/aws/resources/arn:aws:s3:::b/k/e/y/who-can", map[string]string{"arn": "arn:aws:s3:::b/k/e/y"}},
		{"/api/aws/snapshots/{id}", "/api/aws/snapshots/abc", map[string]string{"id": "abc"}},
		{"/api/aws/can", "/api/aws/can", nil},
		{"/api/aws/snapshots/{id}", "/api/aws/snapshots/a/b", nil},
		{"/api/aws/snapshots/{id}", "/api/aws/snapshots", nil},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/effective", nil},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals//effective", nil},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/a//b/effective", nil},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/a/effective/extra", nil},
		{"/api/aws/principals/{arn}/effective", "/api/aws/principals/a/other", nil},
		{"/api/aws/can", "/api/aws/can/x", nil},
	} {
		vars, ok := route(tc.pattern).match(tc.path)
		if ok != (tc.vars != nil || tc.pattern == tc.path) {
			t.Errorf("%s ~ %s: matched=%v", tc.pattern, tc.path, ok)
			continue
		}
		for k, want := range tc.vars {
			if vars[k] != want {
				t.Errorf("%s ~ %s: %s = %q, want %q", tc.pattern, tc.path, k, vars[k], want)
			}
		}
	}
}
